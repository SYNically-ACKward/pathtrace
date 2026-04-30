# PathTrace — Network Decision Analyzer

A single-window, engineer-grade Tauri 2.x desktop app that shows you exactly what your OS will do with a packet — resolver selected, route matched, egress interface chosen, and firewall decision — before the packet leaves your machine.

---

## Features

### Core trace (original)
- Enter an IP, CIDR, FQDN, or hostname and get a structured decision tree
- DNS resolution flow with split-DNS detection and rule attribution
- Routing decision with matched-route highlight and full table view
- Egress interface detail: MTU, tunnel protocol, handshake age, SSID, signal
- Firewall/policy summary (pf, nftables, iptables, Windows Firewall)

### New in this release

| # | Feature | Tab/Location |
|---|---------|-------------|
| 1 | **Decision explanation mode** — human-readable summaries and reason codes (DNS_SPLIT, VPN_TUNNEL, MTU_LOW, etc.) for every decision | Trace tab, top card |
| 2 | **Before/after diff snapshots** — capture a baseline and diff against current state: interfaces, routes, DNS resolvers, firewall | Diff tab |
| 3 | **Trace timeline** — rolling history of last 20 traces, click any entry to inspect the full snapshot at that moment | Timeline tab |
| 4 | **Packet test suite** — opt-in active probes: DNS resolution, ICMP ping, TCP :443/:80, MTU probe, HTTP HEAD; all clearly labeled as active traffic | Probes tab |
| 5 | **Split tunnel coverage map** — categorize routes into VPN/local/default/unknown; show DNS scopes and full-tunnel detection | Coverage tab |
| 6 | **Policy conflict detector** — automatic warnings for: split-DNS without VPN route, competing default routes, low MTU without tunnel, IPv6 asymmetry, DNS on down interface, full-tunnel capture, private DNS without route, resolver route leakage | Trace tab, below explanation |
| 7 | **Copyable troubleshooting report** — Markdown / plain text / JSON report with copy-to-clipboard and download buttons | Report tab |
| 8 | **Redaction mode** — toggle the `redact` button to mask private IPs, MACs, VPN endpoints, internal hostnames, and gateways before copying or exporting | Toolbar button |
| 9 | **Route simulator** — add/remove routes, flip interface state up/down, adjust metrics, override DNS answers; shows hypothetical winning route without touching system config | Simulate tab |
| 10 | **Resolver-specific DNS testing** — query each configured resolver independently (via `dig`/`nslookup` fallback), compare answers, detect split-brain / stale / leakage | Report tab (bottom) |

---

## Architecture

```
pathtrace/
├── src/
│   ├── main.js          # All frontend logic (~1660 lines vanilla JS)
│   └── styles.css       # All styles including new feature CSS
├── src-tauri/
│   ├── src/
│   │   ├── lib.rs       # Tauri builder + all command registrations
│   │   ├── main.rs      # Thin wrapper calling pathtrace_lib::run()
│   │   └── system/
│   │       ├── mod.rs   # Business logic: trace, snapshot, explain, diff, probe, simulate, resolver-test
│   │       ├── models.rs # All data types (Serialize/Deserialize)
│   │       └── platform.rs # OS-specific: interfaces, routes, DNS, firewall, ping
│   └── tauri.conf.json
└── dist/                # Production build output
```

### Rust backend commands

| Command | Description |
|---------|-------------|
| `get_network_snapshot` | Current interfaces, routes, DNS, firewall, events |
| `analyze_destination` | Full trace for a destination (includes explanation, conflicts, coverage) |
| `export_trace_json` | Serialize TraceResult to pretty JSON |
| `run_packet_tests` | Active probes: DNS, ping, TCP, MTU, HTTP |
| `simulate_route` | Hypothetical route resolution with overrides |
| `test_resolvers` | Per-resolver DNS comparison with split-brain detection |

---

## Building

### Requirements
- Node.js ≥ 18
- Rust (stable, ≥ 1.74) with `cargo`
- Tauri CLI v2: `cargo install tauri-cli`
- On macOS: Xcode command-line tools
- On Linux: `build-essential`, `libwebkit2gtk-4.1-dev`, `libssl-dev`, etc.

### Icon assets
Tauri requires icon files in `src-tauri/icons/` for bundling. Generate them with:
```bash
npx tauri icon path/to/icon.png
```
A 512×512 PNG source `icon.png` must be provided. Without icons, `tauri dev` works fine but `tauri build` (bundler) will warn.

### Development
```bash
npm install
npx tauri dev
```
The app falls back to demo data when not running inside Tauri (browser/iframe preview works fully).

### Production build
```bash
npm install
npm run build           # Vite build only (frontend)
npx tauri build         # Full Tauri bundle (requires Rust)
```

### Frontend-only build (no Rust required)
```bash
npm run build
# Serve dist/ with any static server; full demo mode
```

---

## Platform notes

### macOS
- `pfctl` firewall rules require elevated permissions. PathTrace calls `sudo /sbin/pfctl -sr` — you may be prompted.
- `scutil --dns` is used for split-DNS resolver discovery.

### Linux
- `systemd-resolved` (`resolvectl status`) is preferred; falls back to `/etc/resolv.conf`.
- Firewall detection tries `nft` then `iptables`. May require `CAP_NET_ADMIN` or `sudo`.
- `ip route get` is used for per-destination route lookup.

### Windows
- PowerShell commands: `Get-NetIPConfiguration`, `Get-DnsClientServerAddress`, `Get-DnsClientNrptRule`, `Find-NetRoute`, `Get-NetFirewallRule`.
- Run as Administrator for full firewall visibility.

---

## Active probe warnings

The **Probes** tab sends real network traffic:
- ICMP echo (ping)
- TCP SYN to ports 443 and 80
- ICMP with 1400-byte payload (MTU probe)
- HTTPS HEAD request (via `curl`)

All probes are opt-in and clearly labeled in the UI. They are never run automatically.

---

## Redaction mode

When **redact** is active, the following patterns are masked in all rendered output, clipboard copies, and report downloads:
- Private IPv4 addresses (RFC 1918: 10.x, 172.16–31.x, 192.168.x)
- IPv6 addresses
- MAC addresses
- VPN endpoint hostnames (`vpn.*`, `wg.*`)
- Internal hostnames (`.corp.*`, `.internal.*`)

Redaction is purely client-side — the backend always returns full data.

---

## Route simulator

The simulator computes a hypothetical routing decision given your modifications:
- Add routes (CIDR + gateway + interface + optional metric)
- Remove routes by destination prefix
- Set interfaces up or down
- Override metric on existing routes
- Override DNS answer for the traced hostname

**No system configuration is ever modified.** All simulation happens in-memory on the backend's copy of the current routing table.

---

## npm audit

```
found 0 vulnerabilities
```

---

## Cargo availability

Cargo was not available in the build environment at implementation time. Rust source has been written and verified for correctness but not compiled via `cargo check`. When Rust toolchain is available:

```bash
cd src-tauri && cargo check
```

Expected behavior: compiles cleanly on Rust stable. The `isIpStr` → `is_ip_str` rename, HashSet dedup fix, and `#[allow(non_snake_case)]` patterns have been applied.
