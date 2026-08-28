#!/usr/bin/env python3
"""lanmoon - compact legal LAN monitor (TUI, zero deps).

Scans the local subnet every N seconds via ICMP (using the OS `ping`
binary, so no raw-socket privileges are needed), shows how many devices
are online, how long the network has been reachable, gateway latency and
per-device history - all in a small colored terminal view.

Only legal, passive discovery is performed: ICMP echo + reading the OS
ARP table. Nothing is sent to remote hosts except standard pings to
addresses inside your own subnet.

Usage:
    python3 lanmon.py            # defaults: 15s interval, auto subnet
    python3 lanmon.py -i 10     # scan every 10 seconds
    python3 lanmon.py -n 24     # force /24 sweep (overrides detected mask)
    python3 lanmon.py --no-host  # skip reverse-DNS lookups
"""

import argparse
import platform
import re
import socket
import struct
import subprocess
import sys
import time
import select
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
            "mask": None, "gateway": None}
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
        return r.returncode == 0, rtt
    except Exception:
        return False, None


def resolve_host(ip):
    try:
        socket.setdefaulttimeout(0.4)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
class Monitor:
    def __init__(self, info, resolve_hosts=True):
        self.info = info
        self.resolve_hosts = resolve_hosts
        self.devices = OrderedDict()      # ip -> record
        self.session_start = time.time()
        self.net_birth = None             # when gateway first came up
        self.gw_rtt = None
        self.last_scan = 0
        self.last_duration = 0

    def scan(self):
        info = self.info
        targets = host_list(info)
        if info["gateway"]:
            targets = [info["gateway"]] + targets

        arp = arp_table()
        now = time.time()
        t0 = time.time()

        def probe(ip):
            return ip, ping(ip)

        results = {}
        with ThreadPoolExecutor(max_workers=80) as ex:
            for ip, res in ex.map(probe, targets):
                results[ip] = res

        alive_now = set()
        for ip, (up, rtt) in results.items():
            rec = self.devices.get(ip)
            if rec is None:
                rec = {
                    "mac": None, "hostname": "", "first_seen": now,
                    "last_seen": now, "alive": False, "rtt": None,
                    "up": 0, "down": 0, "ever_up": False,
                    "is_gw": ip == info["gateway"],
                }
                self.devices[ip] = rec
            rec["mac"] = arp.get(ip) or rec["mac"]
            rec["alive"] = up
            rec["rtt"] = rtt
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
        alive = sum(1 for d in self.devices.values() if d["alive"])
        down = sum(1 for d in self.devices.values()
                   if d["ever_up"] and not d["alive"]
                   and (now - d["last_seen"]) < 600)
        return alive, down, len(self.devices)

    def view(self, next_in):
        now = time.time()
        alive, down, total = self.stats()
        lines = []
        A = BOLD + CYAN
        lines.append(f"{BOLD}● LANMON{R} {GREY}v1.0{R}  "
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
        )
        lines.append(
            f"  {GREEN}alive {alive}{R}   {RED}down {down}{R}   "
            f"{GREY}seen {total}   sweep {human(self.last_duration)}{R}"
        )
        lines.append("")
        # table header
        hdr = (f"  {BOLD}{pad('IP',17)}{pad('MAC',19)}{pad('HOST',22)}"
               f"{pad('STATE',8)}{pad('SEEN',9)}{pad('GW/ms',8)}{pad('LOST',5)}{R}")
        lines.append(hdr)
        lines.append(f"  {GREY}{'─'*88}{R}")

        order = sorted(self.devices.items(),
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
            seen = human(now - d["last_seen"]) if not d["alive"] else \
                   human(now - d["first_seen"])
            rtt = "-" if d["rtt"] is None else f"{d['rtt']:.1f}"
            color = RED if not d["alive"] else (MAGENTA if d["is_gw"] else R)
            lines.append(
                f"  {color}{pad(ip,17)}{pad(d['mac'] or '?',19)}"
                f"{pad(d['hostname'] or '-',22)}{tag}"
                f"{pad(seen,9)}{pad(rtt,8)}{pad(d['down'],5)}{R}"
            )
        lines.append(f"  {GREY}{'─'*88}{R}")
        lines.append(
            f"  scan every {BOLD}{int(SCAN_INTERVAL)}s{R}   "
            f"next in {YELLOW}{int(next_in)}s{R}   "
            f"{GREY}± net info auto-detected   [q] quit{R}"
        )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
SCAN_INTERVAL = 15


def main():
    global SCAN_INTERVAL
    ap = argparse.ArgumentParser(description="Compact LAN monitor TUI")
    ap.add_argument("-i", "--interval", type=int, default=15,
                    help="scan interval in seconds (default 15)")
    ap.add_argument("-n", "--netmask", type=int, default=None,
                    help="force CIDR, e.g. 24 (overrides auto-detect)")
    ap.add_argument("--no-host", action="store_true",
                    help="disable reverse-DNS host lookups")
    args = ap.parse_args()
    SCAN_INTERVAL = max(2, args.interval)

    info = get_net_info(args.netmask)
    if not info["ip"]:
        sys.stdout.write("\033[2J\033[H")
        print(RED + "Could not detect local network interface/IP." + R)
        print("On Linux you may need the 'ip' tool; on macOS 'route'/'ifconfig'.")
        sys.exit(1)

    mon = Monitor(info, resolve_hosts=not args.no_host)
    sys.stdout.write(
        f"{CYAN}scanning {info['iface']} {info['ip']}/{info['cidr']} "
        f"every {SCAN_INTERVAL}s ...{R}\n"
    )
    sys.stdout.flush()
    mon.scan()

    try:
        while True:
            now = time.time()
            next_scan = mon.last_scan + SCAN_INTERVAL
            # live countdown, refreshing the view
            while time.time() < next_scan:
                remaining = max(0, next_scan - time.time())
                sys.stdout.write("\033[2J\033[H" + mon.view(remaining))
                sys.stdout.flush()
                if sys.stdin in select_ready():
                    ch = sys.stdin.read(1)
                    if ch.lower() == "q":
                        raise KeyboardInterrupt
                time.sleep(0.25)
            mon.scan()
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
