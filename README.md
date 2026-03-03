# VPN/DNS Blocker

A high-performance gateway-level VPN and DNS blocker built in Rust. Combines XDP eBPF packet filtering, TLS fingerprinting, DNS sinkholing, and an ONNX ML model to detect and block VPN traffic at the network edge — before connections complete.

Useful to put in front of openclaw based VMs or to block kids on another vlan.

---

## How It Works

Traffic is analysed through four layers, each with increasing cost:

```
┌─────────────────────────────────────────────────────────┐
│ Layer 0 — XDP eBPF (kernel driver, ~nanoseconds)        │
│  • Drops WireGuard, IPsec (ESP/AH), GRE, IP-in-IP       │
│  • Port-based: PPTP (1723), L2TP (1701), SOCKS5 (1080)  │
│  • WireGuard fixed-length signature on ANY UDP port      │
│  • DoT (port 853) blocked outright                       │
├─────────────────────────────────────────────────────────┤
│ Layer 1 — TLS SNI inspection (userspace, ~microseconds) │
│  • Intercepts TCP:443 TLS ClientHello                    │
│  • Matches 20+ VPN provider domain suffixes              │
│  • Blocks on first packet — zero latency for clean hits  │
├─────────────────────────────────────────────────────────┤
│ Layer 2 — Protocol fingerprinting (~microseconds)        │
│  • OpenVPN/TCP framing: 2-byte length + opcode check     │
│  • Non-browser TLS: no GREASE + no ALPN = VPN heuristic │
├─────────────────────────────────────────────────────────┤
│ Layer 3 — ML inference (ONNX GradientBoosting, ~ms)     │
│  • 10 features: packet length, entropy, TLS fingerprint  │
│  • Fallback for traffic that evades layers 0-2           │
└─────────────────────────────────────────────────────────┘
```

DNS sinkholing runs in parallel — dnsmasq intercepts all port-53 queries from LAN clients (via iptables DNAT) and returns `0.0.0.0` for VPN provider domains, blocking connections before they're attempted.

---

## Features

| Category | Details |
|----------|---------|
| **XDP drop** | WireGuard (any port), IPsec ESP/AH, GRE, PPTP, L2TP, SOCKS5, DoT, IP-in-IP |
| **TLS SNI** | 20+ VPN provider domains (NordVPN, ExpressVPN, ProtonVPN, Mullvad, …) |
| **OpenVPN TCP** | Framing detection on port 443 — no SNI needed, works on direct IP connections |
| **WireGuard** | Fixed-size handshake signature on **any** UDP port (catches Tailscale on :41641) |
| **DNS sinkhole** | dnsmasq blocks 35+ VPN domains; DNAT redirects all LAN DNS through gateway |
| **ML model** | GradientBoosting ONNX (AUC 0.991, 10 features) for unknown traffic |
| **Import blocklists** | Hosts-file format (e.g. [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists)) |
| **Web UI** | Real-time flow monitor, block/allow rules, stats — `http://<gateway>:8080` |
| **SQLite persistence** | Blocked IPs survive restarts; manual rules stored permanently |
| **systemd service** | `Restart=always`, auto-starts after dnsmasq |

---

## Architecture

```
              LAN clients (192.168.1.x)
                        │
                    eth1 (LAN)
                        │
            ┌───────────▼───────────────┐
            │     vpn-blocker gateway   │
            │                           │
            │  XDP eBPF (eth1 ingress)  │◄── drops WireGuard, IPsec, GRE, …
            │         │                 │
            │  pnet capture (TCP:443,   │
            │  UDP:53 responses)        │
            │         │                 │
            │  ┌──────▼────────────┐    │
            │  │ SNI → Fingerprint │    │
            │  │ → ML inference    │    │
            │  └──────┬────────────┘    │
            │         │ block? → iptables DROP
            │         │                 │
            │  dnsmasq (port 53)        │◄── sinkhole: 35+ VPN domains → 0.0.0.0
            │  DNAT: all LAN DNS here   │
            │                           │
            │  Web UI :8080             │
            └───────────┬───────────────┘
                    eth0 (WAN)
                        │
                    Internet
```

---

## Requirements

- Linux kernel ≥ 5.15 (XDP native mode, BTF support)
- Root / `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_NET_RAW`
- `dnsmasq` installed on the gateway host
- Rust stable + nightly (nightly required for eBPF build only)

---

## Quick Start

### Build

```bash
# 1. Build the eBPF program (nightly Rust + bpf-linker)
./build-ebpf.sh

# 2. Build the userspace binary
cargo build --release
```

### Run

```bash
# Run on the LAN-facing interface (replace eth1 with your interface)
sudo ./target/release/vpn-blocker eth1
```

The web UI starts at `http://<host>:8080`.

### Deploy as a systemd service

```bash
sudo cp target/release/vpn-blocker /usr/local/bin/
sudo cp model.onnx /home/ubuntu/

sudo tee /etc/systemd/system/vpn-blocker.service <<'EOF'
[Unit]
Description=VPN/DNS Blocker (XDP + ML + DNS)
After=network-online.target dnsmasq.service
Wants=network-online.target
Wants=dnsmasq.service

[Service]
Type=simple
WorkingDirectory=/home/ubuntu
ExecStart=/usr/local/bin/vpn-blocker eth1
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now vpn-blocker
```

---

## Docker

```bash
# Build and run (requires privileged + host network for XDP)
docker compose up -d
```

> **Note:** Change `command: ["eth1"]` in `docker-compose.yml` to your LAN interface name.

The container runs privileged with `network_mode: host` — required for XDP to attach to the host kernel's network driver and for iptables to modify the host firewall.

---

## ML Model

The ONNX model (`model.onnx`) uses **10 features** extracted per packet:

| # | Feature | Description |
|---|---------|-------------|
| 0 | `packet_len` | Raw IP payload length (1–1500) |
| 1 | `entropy` | Shannon entropy of first 128 bytes |
| 2 | `compression` | 1.0 if entropy > 7.5, else 0.5 |
| 3 | `mean_byte` | Mean byte value of first 128 bytes |
| 4 | `stddev_byte` | Standard deviation of byte values |
| 5 | `num_ciphers` | TLS ClientHello: number of cipher suites |
| 6 | `num_extensions` | TLS ClientHello: number of extensions |
| 7 | `has_alpn` | TLS ClientHello: ALPN extension present |
| 8 | `alpn_h2` | TLS ClientHello: h2 offered in ALPN |
| 9 | `has_grease` | TLS ClientHello: GREASE value present |

Retrain the model:

```bash
# Uses uv for dependency management
uv run python train_compare.py
```

---

## Blocklist Import

Import hosts-file format blocklists via the web UI or API:

```bash
# Download and import hagezi light blocklist
curl -s https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/light.txt \
  | curl -X POST http://localhost:8080/api/import \
         -H 'Content-Type: text/plain' \
         --data-binary @-
```

Supported formats:
- `0.0.0.0 domain.com` (hosts-file)
- `127.0.0.1 domain.com` (hosts-file)
- Plain domain names (one per line)

---

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Web dashboard |
| `GET` | `/api/stats` | `{packets_seen, ml_blocks, blocked_ips_count, xdp_active}` |
| `GET` | `/api/blocked` | List of blocked IPs with timestamps |
| `GET` | `/api/rules` | List of manual block rules |
| `GET` | `/api/flows` | Recent flow event history (last 200) |
| `GET` | `/api/events` | SSE stream of real-time flow events |
| `POST` | `/api/rules` | Add a rule `{"target":"IP/CIDR/domain","direction":"dst"}` |
| `DELETE` | `/api/rules/:target` | Remove a rule |
| `POST` | `/api/import` | Import newline-delimited IP/domain list |
| `DELETE` | `/api/blocked/:ip` | Unblock a specific IP |

---

## Detection Coverage

| Protocol | Method | Port-independent? |
|----------|--------|-------------------|
| WireGuard | XDP: fixed-size handshake signature `[type,0,0,0]` | ✅ any UDP port |
| Tailscale | Same WireGuard signature | ✅ any UDP port |
| IPsec ESP/AH | XDP: IP protocol numbers 50/51 | ✅ |
| IKE/NAT-T | XDP: UDP ports 500, 4500 | ❌ port-locked |
| OpenVPN UDP | XDP: port 1194 + opcode check | ❌ port-locked |
| OpenVPN TCP | Framing: 2-byte len + opcode, any port | ✅ any TCP port |
| PPTP | XDP: TCP/UDP 1723 + GRE protocol 47 | ❌ port-locked |
| L2TP | XDP: UDP 1701 | ❌ port-locked |
| SOCKS5 | XDP: TCP 1080 | ❌ port-locked |
| ZeroTier | XDP: UDP 9993 + verb check | ❌ port-locked |
| DoT | XDP: TCP/UDP 853 | ❌ port-locked |
| VPN over HTTPS | TLS SNI + OpenVPN-TCP framing + ML | ✅ |
| DNS bypass | dnsmasq sinkhole + iptables DNAT | ✅ |

---

## High Availability — BGP VIP

Run two gateway instances in active/active or active/standby HA. Each node announces a shared Virtual IP (VIP) via BGP. If a node's health check fails, it withdraws its BGP advertisement and the upstream router drains traffic to the surviving node within seconds.

### Architecture

```
                     Upstream router (BGP AS 65000)
                     192.168.1.1
                     /            \
          eBGP session          eBGP session
               /                      \
 ┌─────────────────────┐   ┌─────────────────────┐
 │  gw1 (192.168.1.10) │   │  gw2 (192.168.1.11) │
 │  lo: 192.168.1.254  │   │  lo: 192.168.1.254  │
 │  VPN/DNS Blocker    │   │  VPN/DNS Blocker    │
 │  BIRD2 (AS 65001)   │   │  BIRD2 (AS 65001)   │
 └─────────────────────┘   └─────────────────────┘
              \                      /
               ──────── LAN ─────────
              clients default GW → 192.168.1.254 (VIP)
```

Both nodes advertise `192.168.1.254/32` to the upstream router. ECMP distributes load across both; if one node's health check withdraws the route, 100% of traffic goes to the survivor.

### Prerequisites

- **BIRD2** on each gateway node — `apt install bird2`
- An upstream router (or a Linux box running BIRD2) that speaks eBGP and supports ECMP
- Each gateway in the same AS (iBGP is also supported but adds complexity)

### Step 1 — Add the VIP to loopback

Run this on **both** gateway nodes (survives reboots via netplan or `/etc/network/interfaces`):

```bash
# Add VIP to loopback (non-persistent — test first)
sudo ip addr add 192.168.1.254/32 dev lo

# Persistent — Ubuntu/Debian netplan example
sudo tee /etc/netplan/10-loopback-vip.yaml <<'EOF'
network:
  version: 2
  ethernets:
    lo:
      addresses:
        - 192.168.1.254/32
EOF
sudo netplan apply
```

### Step 2 — BIRD2 configuration

`/etc/bird/bird.conf` on **gw1** (change `router id` and `neighbor` for gw2):

```
log syslog all;
router id 192.168.1.10;   # this node's real IP

protocol device {}

protocol direct {
  interface "lo";          # export loopback addresses (the VIP)
}

protocol kernel {
  ipv4 {
    export all;
    import all;
  };
}

# Conditional VIP announcement — only advertise when vpn-blocker is healthy
protocol static VIP {
  ipv4;
  route 192.168.1.254/32 blackhole {
    bgp_community.add((65001, 100));
  };
}

# Health-check filter: suppress VIP if the check file is absent
function is_healthy() {
  return (net = 192.168.1.254/32 && /run/vpn-blocker-healthy exists);
}

filter export_vip {
  if is_healthy() then accept;
  reject;
}

protocol bgp upstream {
  description "Upstream router";
  neighbor 192.168.1.1 as 65000;   # upstream router IP + AS
  local as 65001;

  ipv4 {
    import none;                    # we don't need upstream routes
    export filter export_healthy;
  };
}

filter export_healthy {
  if net = 192.168.1.254/32 then {
    if /run/vpn-blocker-healthy ~ "" then accept;
    reject;
  }
  reject;
}
```

> **Simpler alternative**: skip the filter and use the `ExecStartPost`/`ExecStopPre` hooks below to add/remove the static route directly.

Cleaner static-route approach (recommended):

```
# /etc/bird/bird.conf — simplified
log syslog all;
router id 192.168.1.10;

protocol device {}
protocol direct { interface "lo"; }
protocol kernel { ipv4 { export all; }; }

# VIP route — present only when health check adds it
protocol static VIP {
  ipv4;
  # route added/removed by health check script
}

protocol bgp upstream {
  neighbor 192.168.1.1 as 65000;
  local as 65001;
  ipv4 {
    import none;
    export where source = RTS_STATIC;
  };
}
```

### Step 3 — Health check integration

The health check adds the BIRD static route when vpn-blocker is up and removes it when it's down. BIRD then announces/withdraws the VIP to the upstream router.

`/usr/local/bin/vpn-blocker-healthcheck`:

```bash
#!/usr/bin/env bash
# Called by systemd on start/stop to control BGP VIP advertisement.
# Requires: birdc (BIRD2 control socket)

ACTION=$1   # "up" or "down"

announce_vip() {
  birdc "configure soft" 2>/dev/null
  birdc "ipv4 table master4; add 192.168.1.254/32 via \"lo\"" 2>/dev/null || true
  # Directly add route via birdc static protocol
  birdc "debug protocols VIP; protocol VIP restart" 2>/dev/null || true
}

withdraw_vip() {
  birdc "protocol VIP disable" 2>/dev/null || true
}

case "$ACTION" in
  up)   announce_vip ;;
  down) withdraw_vip ;;
esac
```

> **Recommended approach**: manage a sentinel file and have BIRD poll it, or simply add/remove the static route in the kernel and let BIRD redistribute it.

Simpler shell-based approach using `ip route` + BIRD kernel protocol:

```bash
#!/usr/bin/env bash
# /usr/local/bin/vpn-blocker-vip
VIP="192.168.1.254/32"
ACTION=$1

case "$ACTION" in
  up)
    ip addr add "$VIP" dev lo 2>/dev/null || true
    # BIRD picks up the kernel route via 'protocol direct { interface "lo"; }'
    ;;
  down)
    ip addr del "$VIP" dev lo 2>/dev/null || true
    ;;
esac
```

Hook into the systemd unit — add to `/etc/systemd/system/vpn-blocker.service`:

```ini
[Service]
# ... existing config ...
ExecStartPost=/usr/local/bin/vpn-blocker-vip up
ExecStopPost=/usr/local/bin/vpn-blocker-vip down
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart vpn-blocker
```

### Step 4 — Upstream router BGP config

**Linux router running BIRD2:**

```
protocol bgp gw1 {
  neighbor 192.168.1.10 as 65001;
  local as 65000;
  ipv4 {
    import all;
    export none;
  };
}

protocol bgp gw2 {
  neighbor 192.168.1.11 as 65001;
  local as 65000;
  ipv4 {
    import all;
    export none;
  };
}

# Enable ECMP for load balancing across both gateways
protocol kernel {
  ipv4 {
    export all;
    merge paths on;  # ECMP
  };
}
```

**Cisco/Mikrotik**: add both gateways as eBGP neighbors and enable `maximum-paths 2` under the IPv4 address family.

### Step 5 — Verify

```bash
# Check BIRD sees the VIP route
birdc show route 192.168.1.254/32

# Check BGP session is established
birdc show protocols

# Simulate failover — stop vpn-blocker on gw1
sudo systemctl stop vpn-blocker

# On upstream router: VIP route should now point only to gw2
ip route show 192.168.1.254

# Bring gw1 back — traffic resumes
sudo systemctl start vpn-blocker
```

### Shared state between nodes

The two nodes maintain **independent** block databases and dnsmasq configs by default. For consistent blocking across both nodes, sync the SQLite database periodically:

```bash
# On gw2 — pull blocked_ips.db from gw1 every 30 seconds
# Add to crontab or a systemd timer
*/1 * * * * rsync -az ubuntu@192.168.1.10:/home/ubuntu/blocked_ips.db /home/ubuntu/blocked_ips.db.sync \
  && mv /home/ubuntu/blocked_ips.db.sync /home/ubuntu/blocked_ips.db \
  && curl -s -X POST http://localhost:8080/api/reload >/dev/null 2>&1
```

Or run both gateways against a shared NFS-mounted database (ensure only one writes at a time, or use WAL mode and accept brief inconsistencies during failover).

---

## Project Structure

```
vpn-blocker/
├── src/main.rs              # Userspace: packet capture, SNI, ML, web UI, DNS
├── vpn-blocker-ebpf/
│   └── src/main.rs          # XDP eBPF program (no_std, bpfel target)
├── model.onnx               # Trained ONNX classifier (10 features)
├── train_compare.py         # ML training script (uv run python train_compare.py)
├── pyproject.toml           # Python deps managed by uv
├── Dockerfile               # Multi-stage: ebpf-builder → app-builder → runtime
├── docker-compose.yml       # Privileged, host-network deployment
└── build-ebpf.sh            # eBPF build helper (installs nightly + bpf-linker)
```

---

## License

MIT
