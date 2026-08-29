#!/usr/bin/env python3
"""lanmoon - compact legal LAN monitor (TUI, zero deps).

Scans the local subnet every N seconds via ICMP (using the OS `ping`
binary, so no raw-socket privileges are needed) and reads the OS ARP table,
then shows how many devices are online, how long the network has been
reachable, gateway latency and per-device identification - all in a small
colored terminal view.

Identification shown per device: IP, MAC, hostname (reverse-DNS),
vendor (MAC OUI lookup), OS hint (TTL), state, uptime, RTT, lost probes,
and your own machine is flagged.

Only legal, passive discovery is performed: ICMP echo + reading the OS
ARP table. Nothing is sent to remote hosts except standard pings to
addresses inside your own subnet.

Usage:
    lanmoon                  # defaults: 15s interval, auto subnet
    lanmoon -i 10            # scan every 10 seconds
    lanmoon -n 24            # force /24 sweep (overrides detected mask)
    lanmoon --no-host        # skip reverse-DNS host lookups
    lanmoon --no-vendor      # skip MAC vendor (OUI) lookup
"""

import argparse
import os
import platform
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# ANSI palette
# ---------------------------------------------------------------------------
R = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
GREY = "\033[90m"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(n):
    return socket.inet_ntoa(struct.pack("!I", n & 0xFFFFFFFF))


def cidr_to_ip(cidr):
    return int_to_ip((0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF)


def run(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout).stdout
    except Exception:
        return ""


def human(sec):
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m}m {s:02d}s"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h {m:02d}m"
    d, h = divmod(h, 24)
    return f"{d}d {h:02d}h"


def pad(s, w, right=False):
    s = str(s)
    if len(s) > w:
        s = s[: w - 1] + "…"
    return s.rjust(w) if right else s.ljust(w)


# ---------------------------------------------------------------------------
# Network detection
# ---------------------------------------------------------------------------
def get_net_info(force_cidr=None):
    info = {"iface": None, "ip": None, "cidr": None,
            "mask": None, "gateway": None, "self_mac": None}
    sysname = platform.system()

    if sysname == "Darwin":
        out = run(["route", "-n", "get", "default"])
        m = re.search(r"interface:\s+(\S+)", out)
        if m:
            info["iface"] = m.group(1)
        m = re.search(r"gateway:\s+(\S+)", out)
        if m:
            info["gateway"] = m.group(1)
        if info["iface"]:
            ifc = run(["ifconfig", info["iface"]])
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+).*?netmask (0x[0-9a-fA-F]+)",
                          ifc, re.S)
            if m:
                info["ip"] = m.group(1)
                info["cidr"] = bin(int(m.group(2), 16)).count("1")
            else:
                m = re.search(r"inet (\d+\.\d+\.\d+\.\d+).*?mask (\d+\.\d+\.\d+\.\d+)",
                              ifc, re.S)
                if m:
                    info["ip"] = m.group(1)
                    info["cidr"] = bin(ip_to_int(m.group(2))).count("1")
            me = re.search(r"ether ([0-9a-fA-F:]{17})", ifc)
            if me:
                info["self_mac"] = me.group(1).lower()
    else:  # Linux / *BSD-ish
        out = run(["ip", "route", "show", "default"])
        m = re.search(r"default via (\S+) dev (\S+)", out)
        if m:
            info["gateway"] = m.group(1)
            info["iface"] = m.group(2)
        if info["iface"]:
            out = run(["ip", "-o", "-f", "inet", "addr", "show", info["iface"]])
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
            if m:
                info["ip"] = m.group(1)
                info["cidr"] = int(m.group(2))
            me = re.search(r"link/ether ([0-9a-fA-F:]{17})", out)
            if me:
                info["self_mac"] = me.group(1).lower()

    if force_cidr is not None:
        info["cidr"] = force_cidr
    if info["ip"] and info["cidr"] is not None:
        info["mask"] = cidr_to_ip(info["cidr"])
    return info


def host_list(info):
    if not info["ip"] or info["cidr"] is None:
        return []
    base = ip_to_int(info["ip"]) & ip_to_int(info["mask"])
    size = 1 << (32 - info["cidr"])
    out = []
    for i in range(1, size - 1):
        ip = int_to_ip(base + i)
        if ip == info["ip"]:
            continue
        out.append(ip)
    return out


def arp_table():
    table = {}
    out = run(["arp", "-a"], timeout=8)
    for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", out):
        table[m.group(1)] = m.group(2).lower()
    return table


def ping(ip):
    if platform.system() == "Darwin":
        cmd = ["ping", "-c", "1", "-t", "2", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        m = re.search(r"time[=<]?\s*([\d.]+)\s*ms", r.stdout)
        rtt = float(m.group(1)) if m else None
        t = re.search(r"ttl[=<]?\s*(\d+)", r.stdout, re.I)
        ttl = int(t.group(1)) if t else None
        return r.returncode == 0, rtt, ttl
    except Exception:
        return False, None, None


def resolve_host(ip):
    try:
        socket.setdefaulttimeout(0.4)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Vendor (OUI) + OS identification
# ---------------------------------------------------------------------------
# Small, curated best-effort OUI -> vendor map. Accuracy is improved when the
# system ships an OUI database (see load_vendors). This is a hint, not gospel.
EMBEDDED_OUI = {
    "3C22FB": "Apple", "542696": "Apple", "606DC7": "Apple", "7073CB": "Apple",
    "7C6D62": "Apple", "8C8590": "Apple", "9801A7": "Apple", "A483E7": "Apple",
    "ACBC32": "Apple", "B80997": "Apple", "C04A00": "Apple", "D0034B": "Apple",
    "E498D6": "Apple", "F01898": "Apple", "FCFC48": "Apple",
    "9463D1": "Samsung", "9CAED8": "Samsung", "A02195": "Samsung", "B07828": "Samsung",
    "CC08FB": "Samsung", "D442A0": "Samsung", "D8FB5E": "Samsung", "E8ABFA": "Samsung",
    "F49F0B": "Samsung",
    "34CE00": "Xiaomi", "50EC50": "Xiaomi", "640980": "Xiaomi", "7811DC": "Xiaomi",
    "88CD34": "Xiaomi", "A47733": "Xiaomi", "B025AA": "Xiaomi", "C443BD": "Xiaomi",
    "D05349": "Xiaomi", "E4902E": "Xiaomi", "F4DBE0": "Xiaomi",
    "001E10": "Huawei", "04CF8B": "Huawei", "082A5B": "Huawei", "0C1DAF": "Huawei",
    "1015C5": "Huawei", "1430C6": "Huawei", "181F6B": "Huawei", "28DFEB": "Huawei",
    "34BAFF": "Huawei", "3C8C40": "Huawei", "4455CC": "Huawei", "54FAFF": "Huawei",
    "5855CA": "Huawei", "7C3425": "Huawei", "8405FA": "Huawei", "8C141C": "Huawei",
    "901CDE": "Huawei", "9C9E6A": "Huawei", "A03A56": "Huawei", "AC142D": "Huawei",
    "C02CA0": "Huawei", "C4E90C": "Huawei", "CCA797": "Huawei", "DC7196": "Huawei",
    "E022CC": "Huawei", "F07960": "Huawei", "F4295E": "Huawei", "F88C21": "Huawei",
    "001478": "TP-Link", "001D0F": "TP-Link", "0023CD": "TP-Link", "002586": "TP-Link",
    "002682": "TP-Link", "002719": "TP-Link", "004E01": "TP-Link", "005018": "TP-Link",
    "005F67": "TP-Link", "0060E9": "TP-Link", "00696C": "TP-Link", "00904C": "TP-Link",
    "00A0C5": "TP-Link", "00B00C": "TP-Link", "00C2C6": "TP-Link", "00CC8C": "TP-Link",
    "00D005": "TP-Link", "00DA21": "TP-Link", "00E04C": "TP-Link", "00F41B": "TP-Link",
    "00000C": "Cisco", "000142": "Cisco", "000163": "Cisco", "0005DC": "Cisco",
    "0009E8": "Cisco", "000F23": "Cisco", "001418": "Cisco", "001794": "Cisco",
    "001C57": "Cisco", "005056": "VMware", "000C29": "VMware", "001517": "VMware",
    "00F651": "Netgear", "00146C": "Netgear", "001803": "Netgear", "001C7F": "Netgear",
    "001E2A": "Netgear", "002395": "Netgear", "00146C": "Netgear",
    "001D0F": "Asus", "002038": "Asus", "0024D7": "Asus", "001BFB": "D-Link",
    "0014D1": "D-Link", "001A2B": "D-Link", "001E58": "D-Link",
    "B827EB": "RaspberryPi", "DCA632": "RaspberryPi", "E4E534": "RaspberryPi",
    "F0C08C": "RaspberryPi",
    "001A79": "Sony", "001C4D": "Sony", "001D0A": "Sony", "001E3D": "Sony",
    "001109": "LG", "0011F6": "LG", "001403": "LG", "001676": "LG",
    "00155D": "Microsoft", "001DD8": "Microsoft", "001A11": "Google", "001B63": "Google",
    "001D7E": "Google", "001B38": "Amazon", "001C97": "Amazon", "001F6D": "Amazon",
    "002561": "Amazon", "DC9FDB": "Ubiquiti", "FCECDA": "Ubiquiti",
    "00156B": "MikroTik", "001959": "MikroTik", "00203F": "MikroTik", "004F22": "MikroTik",
    "00E04C": "Realtek", "0100EC": "Realtek", "0010EC": "Realtek", "001BFC": "Broadcom",
    "00145A": "Broadcom", "0018DE": "Broadcom", "001F3B": "Qualcomm",
    "0021E9": "Dell", "00190B": "Dell", "001C23": "Dell", "001560": "HP",
    "0017A0": "HP", "0019BB": "Brother", "080001": "Brother",
    "001AA3": "Canon", "001B53": "Canon", "001C7D": "Canon", "001E8F": "Epson",
    "001B3C": "Epson", "001C25": "Tenda", "001D73": "Tenda", "001E65": "Tenda",
    "00145B": "Mercusys", "0017FA": "Mercusys", "001A20": "Arris", "001B59": "Arris",
    "0017C9": "ZTE", "001D74": "ZTE",
}
# strip accidental None values and normalize keys (uppercase, no separators)
_VENDOR_DB = {}
for _k, _v in EMBEDDED_OUI.items():
    if not _v:
        continue
    _K = _k.replace(":", "").replace("-", "").upper()
    if len(_K) == 6:
        _VENDOR_DB[_K] = _v
EMBEDDED_OUI = _VENDOR_DB


def load_vendors():
    """Build an OUI->vendor map, preferring a system database if present."""
    db = {}
    candidates = [
        "/usr/share/nmap/nmap-mac-prefixes",     # "3C22FB Apple, Inc"
        "/usr/share/ieee-data/oui.txt",
        "/var/lib/ieee-data/oui.txt",
        "/etc/aircrack-ng/airodump-ng-oui.txt",
    ]
    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # nmap / airodump format: "XXXXXX vendor"
                    m = re.match(r"^([0-9A-Fa-f]{6})\s+(.*)$", line)
                    if m:
                        db[m.group(1).upper()] = m.group(2).strip()
                        continue
                    # IEEE oui.txt: "3C-22-FB   (hex)  Apple, Inc."
                    m = re.match(r"^([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})",
                                 line)
                    if m:
                        db[(m.group(1) + m.group(2) + m.group(3)).upper()] = \
                            line.split("(hex)", 1)[-1].split("(base 16)", 1)[-1].strip()
            if db:
                break
        except Exception:
            continue
    if not db:
        db.update(EMBEDDED_OUI)
    return db


VENDOR_DB = load_vendors()


def vendor_of(mac):
    if not mac or len(mac) != 17:
        return "-"
    oui = mac[:8].replace(":", "").upper()
    return VENDOR_DB.get(oui, "-")


def os_of(ttl):
    if ttl is None:
        return "-"
    if ttl >= 128:
        return "Win"
    if ttl >= 64:
        return "Lin/BSD"
    if ttl >= 32:
        return "Win?"
    if ttl >= 1:
        return "Net?"
    return "-"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
class Monitor:
    def __init__(self, info, resolve_hosts=True, resolve_vendors=True):
        self.info = info
        self.resolve_hosts = resolve_hosts
        self.resolve_vendors = resolve_vendors
        self.devices = OrderedDict()      # ip -> record
        self.session_start = time.time()
        self.net_birth = None             # when gateway first came up
        self.gw_rtt = None
        self.gw_ttl = None
        self.last_scan = 0
        self.last_duration = 0
        self.self_ip = info["ip"]
        self.lock = threading.Lock()
        self._scanning = False
        self._done = 0
        self._total = 0

    def scan(self):
        info = self.info
        targets = host_list(info)
        if info["gateway"]:
            targets = [info["gateway"]] + targets
        if info["ip"] and info["ip"] not in targets:
            targets.append(info["ip"])  # include this machine itself

        arp = arp_table()
        now = time.time()
        t0 = time.time()
        self._total = len(targets)
        self._done = 0

        def probe(ip):
            return ip, ping(ip)

        results = {}
        with ThreadPoolExecutor(max_workers=80) as ex:
            for ip, res in ex.map(probe, targets):
                results[ip] = res
                self._done += 1

        with self.lock:
            alive_now = set()
            for ip, (up, rtt, ttl) in results.items():
                rec = self.devices.get(ip)
                if rec is None:
                    rec = {
                        "mac": None, "hostname": "", "first_seen": now,
                        "last_seen": now, "alive": False, "rtt": None,
                        "ttl": None, "up": 0, "down": 0, "ever_up": False,
                        "is_gw": ip == info["gateway"],
                    }
                    self.devices[ip] = rec
                rec["mac"] = (arp.get(ip)
                              or (info.get("self_mac") if ip == info["ip"] else None)
                              or rec["mac"])
                rec["alive"] = up
                rec["rtt"] = rtt
                rec["ttl"] = ttl
                if up:
                    alive_now.add(ip)
                    rec["last_seen"] = now
                    if not rec["ever_up"]:
                        rec["first_seen"] = now
                    rec["ever_up"] = True
                    rec["up"] += 1
                else:
                    rec["down"] += 1

            # best-effort reverse DNS only for live devices missing a name
            if self.resolve_hosts:
                def lookup(ip):
                    return ip, resolve_host(ip)
                with ThreadPoolExecutor(max_workers=40) as ex:
                    for ip, name in ex.map(lookup, list(alive_now)):
                        if name:
                            self.devices[ip]["hostname"] = name

            gw = self.devices.get(info["gateway"])
            if gw and gw["alive"]:
                self.gw_rtt = gw["rtt"]
                self.gw_ttl = gw["ttl"]
                if self.net_birth is None:
                    self.net_birth = now

            self.last_scan = time.time()
            self.last_duration = self.last_scan - t0

            # keep the view compact: drop hosts that were never seen alive,
            # and drop once-alive hosts that have been gone for >10 minutes.
            recent = 10 * 60
            for ip in [ip for ip, d in self.devices.items()
                       if not d["is_gw"] and not d["ever_up"]]:
                del self.devices[ip]
            for ip in [ip for ip, d in self.devices.items()
                       if not d["is_gw"] and d["ever_up"] and not d["alive"]
                       and (now - d["last_seen"]) > recent]:
                del self.devices[ip]

    # --- view -------------------------------------------------------------
    def stats(self):
        now = time.time()
        with self.lock:
            alive = sum(1 for d in self.devices.values() if d["alive"])
            down = sum(1 for d in self.devices.values()
                       if d["ever_up"] and not d["alive"]
                       and (now - d["last_seen"]) < 600)
            total = len(self.devices)
        return alive, down, total

    def _mode(self):
        cols = shutil.get_terminal_size((80, 24)).columns
        if cols >= 100:
            return "full"
        if cols >= 86:
            return "mid"
        return "mini"

    def _rows(self, items, now, mode):
        # returns list of formatted row strings (without leading indent)
        rows = []
        order = sorted(items,
                       key=lambda kv: (not kv[1]["alive"], not kv[1]["is_gw"],
                                       ip_to_int(kv[0])))
        for ip, d in order:
            is_new = d["alive"] and (now - d["first_seen"]) < 40
            if d["is_gw"]:
                tag = f"{MAGENTA}GW{R}"
            elif is_new:
                tag = f"{YELLOW}NEW{R}"
            elif d["alive"]:
                tag = f"{GREEN}UP{R}"
            else:
                tag = f"{RED}DOWN{R}"

            hostname = d["hostname"] or ""
            vendor = vendor_of(d["mac"]) if self.resolve_vendors else "-"
            if ip == self.self_ip:
                you = f" {GREEN}*you*{R}"
            else:
                you = ""

            if mode == "full":
                name = hostname or "-"
                vals = [ip, d["mac"] or "?", name, vendor,
                        os_of(d["ttl"]), tag,
                        human(now - d["last_seen"]) if not d["alive"]
                        else human(now - d["first_seen"]),
                        "-" if d["rtt"] is None else f"{d['rtt']:.1f}",
                        d["down"]]
            elif mode == "mid":
                name = hostname or "-"
                vals = [ip, d["mac"] or "?", name, vendor, tag,
                        human(now - d["last_seen"]) if not d["alive"]
                        else human(now - d["first_seen"]),
                        "-" if d["rtt"] is None else f"{d['rtt']:.1f}"]
            else:  # mini
                name = hostname or (vendor if vendor != "-" else "-")
                vals = [ip, d["mac"] or "?", name, tag,
                        human(now - d["last_seen"]) if not d["alive"]
                        else human(now - d["first_seen"]),
                        "-" if d["rtt"] is None else f"{d['rtt']:.1f}"]

            base = f"{pad(vals[0],15)}{pad(vals[1],18)}{pad(vals[2],15)}"
            if mode == "full":
                color = RED if not d["alive"] else (MAGENTA if d["is_gw"] else R)
                row = (f"{color}{base}{pad(vals[3],12)}{pad(vals[4],7)}"
                       f"{pad(vals[5],6)}{pad(vals[6],8)}{pad(vals[7],6)}"
                       f"{pad(vals[8],5)}{R}{you}")
            elif mode == "mid":
                color = RED if not d["alive"] else (MAGENTA if d["is_gw"] else R)
                row = (f"{color}{base}{pad(vals[3],12)}{pad(vals[4],6)}"
                       f"{pad(vals[5],8)}{pad(vals[6],6)}{R}{you}")
            else:
                color = RED if not d["alive"] else (MAGENTA if d["is_gw"] else R)
                row = (f"{color}{base}{pad(vals[3],6)}{pad(vals[4],8)}"
                       f"{pad(vals[5],6)}{R}{you}")
            rows.append(row)
        return rows

    def view(self, next_in=0, scanning=False):
        now = time.time()
        alive, down, total = self.stats()
        mode = self._mode()
        if mode == "full":
            headers = ["IP", "MAC", "NAME", "VENDOR", "OS", "STATE",
                       "SEEN", "ms", "LOSS"]
            w = [15, 18, 15, 12, 7, 6, 8, 6, 5]
        elif mode == "mid":
            headers = ["IP", "MAC", "NAME", "VENDOR", "STATE", "SEEN", "ms"]
            w = [15, 18, 15, 12, 6, 8, 6]
        else:
            headers = ["IP", "MAC", "NAME", "STATE", "SEEN", "ms"]
            w = [15, 18, 15, 6, 8, 6]
        hdr = "  " + "".join(pad(h, w[i]) for i, h in enumerate(headers))
        sep = "  " + GREY + "─" * (sum(w) + len(w) - 1) + R

        lines = []
        A = BOLD + CYAN
        lines.append(f"{BOLD}● LANMOON{R} {GREY}v1.0{R}  "
                     f"{A}{self.info['iface'] or '?':<5}{R} "
                     f"{BOLD}{self.info['ip'] or '?'}{R}"
                     f"{GREY}/{self.info['cidr']}{R}  "
                     f"gw {CYAN}{self.info['gateway'] or '?'}{R}")
        net_up = human(now - self.net_birth) if self.net_birth else RED + "down" + R
        sess = human(now - self.session_start)
        lines.append(
            f"  net uptime {GREEN}{net_up}{R}   "
            f"session {YELLOW}{sess}{R}   "
            f"gw rtt {CYAN}{('-' if self.gw_rtt is None else f'{round(self.gw_rtt,1)}ms')}{R}"
            f"{('' if self.gw_ttl is None else CYAN+'  gw ttl '+str(self.gw_ttl)+R)}"
        )
        lines.append(
            f"  {GREEN}alive {alive}{R}   {RED}down {down}{R}   "
            f"{GREY}seen {total}   sweep {human(self.last_duration)}{R}"
        )
        if scanning:
            prog = f"{self._done}/{self._total}" if self._total else "?"
            lines.append(f"  {YELLOW}scanning {prog} hosts ...{R}")
        else:
            lines.append(f"  {DIM}± net info auto-detected{R}")
        lines.append("")
        lines.append(BOLD + hdr + R)
        lines.append(sep)

        with self.lock:
            items = list(self.devices.items())
        rows = self._rows(items, now, mode)
        if scanning and not rows:
            lines.append(f"  {DIM}(waiting for first replies){R}")
        else:
            lines.extend("  " + r for r in rows)
        lines.append(sep)
        if scanning:
            lines.append(f"  {GREY}scan in progress - drawing live results{R}")
        else:
            lines.append(
                f"  scan every {BOLD}{int(SCAN_INTERVAL)}s{R}   "
                f"next in {YELLOW}{int(next_in)}s{R}   "
                f"{GREY}[q] quit{R}"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
SCAN_INTERVAL = 15


def _run_scan(mon):
    try:
        mon.scan()
    finally:
        mon._scanning = False


def main():
    global SCAN_INTERVAL
    ap = argparse.ArgumentParser(description="Compact legal LAN monitor TUI")
    ap.add_argument("-i", "--interval", type=int, default=15,
                    help="scan interval in seconds (default 15)")
    ap.add_argument("-n", "--netmask", type=int, default=None,
                    help="force CIDR, e.g. 24 (overrides auto-detect)")
    ap.add_argument("--no-host", action="store_true",
                    help="disable reverse-DNS host lookups")
    ap.add_argument("--no-vendor", action="store_true",
                    help="disable MAC vendor (OUI) lookup")
    args = ap.parse_args()
    SCAN_INTERVAL = max(2, args.interval)

    info = get_net_info(args.netmask)
    if not info["ip"]:
        sys.stdout.write("\033[2J\033[H")
        print(RED + "Could not detect local network interface/IP." + R)
        print("On Linux you may need the 'ip' tool; on macOS 'route'/'ifconfig'.")
        sys.exit(1)

    mon = Monitor(info, resolve_hosts=not args.no_host,
                  resolve_vendors=not args.no_vendor)
    sys.stdout.write(
        f"{CYAN}starting lanmoon on {info['iface']} {info['ip']}/{info['cidr']} "
        f"(scan every {SCAN_INTERVAL}s) ...{R}\n"
    )
    sys.stdout.flush()

    # first scan runs in the background so the TUI paints immediately
    mon._scanning = True
    th = threading.Thread(target=_run_scan, args=(mon,), daemon=True)
    th.start()

    try:
        while True:
            if th.is_alive() or mon._scanning:
                sys.stdout.write("\033[2J\033[H" + mon.view(0, scanning=True))
                sys.stdout.flush()
                if sys.stdin in select_ready():
                    ch = sys.stdin.read(1)
                    if ch.lower() == "q":
                        raise KeyboardInterrupt
                time.sleep(0.2)
                continue
            now = time.time()
            next_scan = mon.last_scan + SCAN_INTERVAL
            while time.time() < next_scan:
                remaining = max(0, next_scan - time.time())
                sys.stdout.write("\033[2J\033[H" + mon.view(remaining))
                sys.stdout.flush()
                if sys.stdin in select_ready():
                    ch = sys.stdin.read(1)
                    if ch.lower() == "q":
                        raise KeyboardInterrupt
                time.sleep(0.25)
            mon._scanning = True
            th = threading.Thread(target=_run_scan, args=(mon,), daemon=True)
            th.start()
    except KeyboardInterrupt:
        sys.stdout.write("\033[2J\033[H\033[?25h")
        sys.stdout.flush()
        print(f"{GREY}lanmoon stopped. Bye.{R}")
        sys.exit(0)


def select_ready():
    try:
        r, _, _ = select.select([sys.stdin], [], [], 0)
        return r
    except Exception:
        return []


if __name__ == "__main__":
    main()
