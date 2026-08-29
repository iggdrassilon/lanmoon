# lanmoon

Compact, **legal** LAN monitor with a tiny colored TUI. Every few seconds it
ICMP-pings the local subnet (using the OS `ping` binary — no raw sockets, no
root required) and reads the OS ARP table, then shows:

- how many devices are currently online
- how long the network has been alive (since the gateway first answered)
- gateway latency
- a per-device table: IP · MAC · hostname · state · uptime · RTT · lost probes

It is a **passive, read-only scanner**: it only sends standard echo requests to
addresses inside your own subnet and reads already-known ARP entries. Nothing
is sent to remote hosts and no privileged sockets are opened.

Per device it shows: **IP, MAC, hostname (reverse-DNS), vendor (MAC OUI
lookup, your own machine is flagged `*you*`), OS hint (from ICMP TTL),
state, uptime, RTT and lost probes**. The first scan runs in the background, so
the TUI paints an immediate "scanning…" splash and fills in live results as
replies arrive — no blank 15-second wait.

Zero dependencies — pure Python standard library, colors via ANSI escapes.
The table adapts its columns to the terminal width (full / mid / mini).

## Screenshot

```
● LANMON v1.0  en0   192.168.0.118/24  gw 192.168.0.1
  net uptime 1h 12m   session 9m 03s   gw rtt 3.4ms
  alive 6   down 2   seen 8   sweep 8s

  IP               MAC                HOST          STATE   SEEN     GW/ms   LOST
  ────────────────────────────────────────────────────────────────────────────
  192.168.0.1      5c:a6:e6:8a:c1:72  router.lan    GW      1h 12m   3.4     0
  192.168.0.24     a4:83:e7:11:22:33  laptop.lan    UP      9m 03s   1.2     0
  192.168.0.31     –                  –             NEW     0s       –       0
  192.168.0.40     d2:11:9f:44:55:66  –             DOWN    12m 04s  –       3
  ────────────────────────────────────────────────────────────────────────────
  scan every 15s   next in 12s   ± net info auto-detected   [q] quit
```

Colors: `GW` magenta · `UP` green · `NEW` yellow (appeared <40s ago) ·
`DOWN` red.

## Install

### One-liner (downloads + installs into `/usr/local/bin`)

```bash
curl -fsSL https://raw.githubusercontent.com/iggdrassilon/lanmoon/main/install.sh | sudo bash
```

### From a clone

```bash
git clone https://github.com/iggdrassilon/lanmoon.git
cd lanmoon
sudo make install      # or: sudo ./install.sh
```

After install, from anywhere:

```bash
sudo lanmoon          # or simply: lanmoon
```

## Usage

```bash
lanmoon               # auto-detect interface/subnet, scan every 15s
lanmoon -i 10         # scan every 10 seconds
lanmoon -n 24         # force a /24 sweep (overrides auto-detected mask)
lanmoon --no-host     # skip reverse-DNS hostname lookups
lanmoon --no-vendor   # skip MAC vendor (OUI) lookup
```

| flag           | meaning                                         |
|----------------|-------------------------------------------------|
| `-i, --interval N` | scan interval in seconds (default 15)       |
| `-n, --netmask N`  | force CIDR, e.g. `24` (overrides detection) |
| `--no-host`        | disable reverse-DNS host lookups            |
| `--no-vendor`      | disable MAC vendor (OUI) lookup             |

Controls: press `q` (or `Ctrl-C`) to quit.

## Notes

- Tested on macOS (Ventura/Sonoma) and Linux. On Linux the `ip` tool is used
  for interface detection; on macOS `route`/`ifconfig`/`arp`.
- `ping` is used via the setuid system binary, so the tool does **not** need
  root — `sudo` is only used so the installed binary lands in `/usr/local/bin`.
- Devices that were never seen alive are not shown; devices that go offline are
  kept in the view for 10 minutes, then dropped to stay compact.

## License

MIT — see [LICENSE](LICENSE).
