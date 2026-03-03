use aya::{programs::{Xdp, XdpFlags}, Ebpf};
use ort::{Environment, SessionBuilder, Value};
use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::Packet;
use std::collections::{HashSet, VecDeque};
use std::convert::Infallible;
use std::net::IpAddr;
use std::process::Command;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rusqlite::{Connection, params};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt as _};
use axum::{
    Router,
    routing::{get, post, delete},
    extract::{State, Path},
    response::{Html, sse::{Sse, Event, KeepAlive}},
    Json,
    http::StatusCode,
};
use serde::{Serialize, Deserialize};
use serde_json::json;

// ─── Shared state ────────────────────────────────────────────────────────────

struct AppState {
    db:           Mutex<Connection>,
    blocked_ips:  RwLock<HashSet<IpAddr>>,
    flow_tx:      broadcast::Sender<String>,
    flow_history: Mutex<VecDeque<String>>,
    pkts_seen:    AtomicU64,
    ml_blocks:    AtomicU64,
    xdp_active:   AtomicBool,
    http:         reqwest::Client,
}

// ─── DB helpers ──────────────────────────────────────────────────────────────

fn open_db() -> anyhow::Result<Connection> {
    let conn = Connection::open("blocked_ips.db")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS blocked_ips (
            ip         TEXT PRIMARY KEY,
            blocked_at INTEGER NOT NULL,
            source     TEXT NOT NULL DEFAULT 'ml',
            score      REAL
         );
         CREATE TABLE IF NOT EXISTS block_rules (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            target     TEXT NOT NULL UNIQUE,
            direction  TEXT NOT NULL DEFAULT 'dst',
            created_at INTEGER NOT NULL,
            source     TEXT NOT NULL DEFAULT 'manual'
         );"
    )?;
    Ok(conn)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ─── TLS SNI extraction ──────────────────────────────────────────────────────

/// Parse the TLS ClientHello in an IPv4 TCP packet and return the SNI hostname.
/// Returns None if the packet is not a TLS ClientHello or has no SNI extension.
fn extract_tls_sni(ip: &[u8]) -> Option<String> {
    let ihl = (ip.first()? & 0x0f) as usize * 4;
    if ip.get(9)? != &6 { return None; }                      // TCP
    let tcp = ip.get(ihl..)?;
    let doff = (*tcp.get(12)? >> 4) as usize * 4;
    let tls = tcp.get(doff..)?;

    // TLS record header: content_type=0x16 (handshake)
    if tls.get(0)? != &0x16 { return None; }
    // Handshake type: 0x01 = ClientHello
    if tls.get(5)? != &0x01 { return None; }

    // ClientHello body starts at offset 9 (record_hdr[5] + handshake_len[3])
    let ch = tls.get(9..)?;
    if ch.len() < 35 { return None; }

    // Skip: legacy_version[2] + random[32] + session_id_len[1] + session_id[N]
    let sid_len = *ch.get(34)? as usize;
    let mut pos = 35 + sid_len;

    // Skip cipher_suites_length + cipher_suites
    let cs_len = u16::from_be_bytes([*ch.get(pos)?, *ch.get(pos+1)?]) as usize;
    pos += 2 + cs_len;

    // Skip compression_methods_length + compression_methods
    let cm_len = *ch.get(pos)? as usize;
    pos += 1 + cm_len;

    // Extensions length
    let ext_total = u16::from_be_bytes([*ch.get(pos)?, *ch.get(pos+1)?]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;

    // Walk extensions looking for SNI (type 0x0000)
    while pos + 4 <= ext_end.min(ch.len()) {
        let etype = u16::from_be_bytes([ch[pos], ch[pos+1]]);
        let elen  = u16::from_be_bytes([ch[pos+2], ch[pos+3]]) as usize;
        pos += 4;
        if etype == 0x0000 && elen >= 5 {
            // server_name_list_len[2] + name_type[1] + name_len[2] + name[N]
            let name_len = u16::from_be_bytes([ch[pos+3], ch[pos+4]]) as usize;
            if let Some(bytes) = ch.get(pos+5 .. pos+5+name_len) {
                return std::str::from_utf8(bytes).ok().map(|s| s.to_lowercase());
            }
        }
        pos += elen;
    }
    None
}

/// Returns true if the SNI hostname matches a known VPN provider domain.
fn is_vpn_sni(sni: &str) -> bool {
    const VPN_SUFFIXES: &[&str] = &[
        ".nordvpn.com", ".expressvpn.com", ".protonvpn.com",
        ".surfshark.com", ".mullvad.net", ".ipvanish.com",
        ".privateinternetaccess.com", ".vyprvpn.com", ".hidemyass.com",
        ".cyberghostvpn.com", ".torguard.net", ".purevpn.com",
        ".windscribe.com", ".ivpn.net", ".strongvpn.com",
        ".tunnelbear.com", ".hotspotshield.com", ".zenmate.com",
        ".airvpn.org", ".azvpn.com", ".perfect-privacy.com",
    ];
    const VPN_EXACT: &[&str] = &[
        "opengw.net",       // VPN Gate / SoftEther
        "vpngate.net",
        "hidemy.name",
    ];
    VPN_SUFFIXES.iter().any(|s| sni.ends_with(s) || sni == &s[1..])
        || VPN_EXACT.iter().any(|&s| sni == s)
}

// ─── DNS helpers ─────────────────────────────────────────────────────────────

/// Read a DNS label sequence starting at `start` inside `dns` (the DNS message, not the IP packet).
/// Returns (lowercase dot-joined name, position after the name in the original stream).
/// Handles RFC 1035 pointer compression.
fn dns_read_name(dns: &[u8], start: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_pos: Option<usize> = None;
    let mut depth = 0usize;
    loop {
        if depth > 32 { return None; }
        depth += 1;
        let len_byte = *dns.get(pos)?;
        if len_byte == 0 {
            if end_pos.is_none() { end_pos = Some(pos + 1); }
            break;
        } else if len_byte & 0xC0 == 0xC0 {
            if end_pos.is_none() { end_pos = Some(pos + 2); }
            let offset = (((len_byte & 0x3F) as usize) << 8) | (*dns.get(pos + 1)? as usize);
            pos = offset;
        } else {
            let len = len_byte as usize;
            pos += 1;
            let label = std::str::from_utf8(dns.get(pos..pos + len)?).ok()?;
            parts.push(label.to_lowercase());
            pos += len;
        }
    }
    Some((parts.join("."), end_pos?))
}

/// Parse a DNS response IPv4/UDP packet.
/// Returns (queried_domain, vec_of_A_record_IPs) when the response is for a known VPN domain.
fn parse_dns_vpn_ips(ip: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    if ip.get(9)? != &17 { return None; }                     // UDP only
    let ihl = (ip.first()? & 0x0f) as usize * 4;
    let dns  = ip.get(ihl + 8..)?;                            // skip IP + UDP headers
    if dns.len() < 12 { return None; }

    let flags  = u16::from_be_bytes([dns[2], dns[3]]);
    if flags & 0x8000 == 0 { return None; }                   // QR must be 1 (response)
    if flags & 0x7800 != 0 { return None; }                   // opcode must be 0

    let qdcount = u16::from_be_bytes([dns[4], dns[5]]) as usize;
    let ancount = u16::from_be_bytes([dns[6], dns[7]]) as usize;
    if qdcount == 0 || ancount == 0 { return None; }

    // Extract the queried domain from the question section
    let (domain, mut pos) = dns_read_name(dns, 12)?;
    pos += 4; // skip QTYPE + QCLASS
    if !is_vpn_sni(&domain) { return None; }

    // Walk answer RRs collecting A records
    let mut ips: Vec<IpAddr> = Vec::new();
    for _ in 0..ancount {
        let (_, next) = dns_read_name(dns, pos)?;
        pos = next;
        if pos + 10 > dns.len() { break; }
        let rtype = u16::from_be_bytes([dns[pos],   dns[pos+1]]);
        let rdlen = u16::from_be_bytes([dns[pos+8], dns[pos+9]]) as usize;
        pos += 10;
        if rtype == 1 && rdlen == 4 {
            if let Some(r) = dns.get(pos..pos + 4) {
                ips.push(IpAddr::from([r[0], r[1], r[2], r[3]]));
            }
        }
        pos = pos.saturating_add(rdlen);
        if pos > dns.len() { break; }
    }

    if ips.is_empty() { return None; }
    Some((domain, ips))
}

// ─── Packet helpers ──────────────────────────────────────────────────────────

fn extract_ip(packet: &[u8], offset: usize) -> Option<IpAddr> {
    if packet.len() >= offset + 4 && (packet[0] >> 4) == 4 {
        Some(IpAddr::from([packet[offset], packet[offset+1], packet[offset+2], packet[offset+3]]))
    } else {
        None
    }
}

fn is_tcp_port(packet: &[u8], port: u16) -> bool {
    packet.len() >= 24
        && packet[9] == 6
        && u16::from_be_bytes([packet[22], packet[23]]) == port
}

fn fast_entropy(packet: &[u8]) -> f32 {
    let slice = &packet[..packet.len().min(128)];
    let mut counts = [0u16; 256];
    for &b in slice { counts[b as usize] += 1; }
    let total = slice.len() as f32;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f32 / total;
        -p * p.log2()
    }).sum()
}

fn mean_stddev(packet: &[u8]) -> (f32, f32) {
    let slice = &packet[..packet.len().min(128)];
    let len = slice.len() as f32;
    let mean = slice.iter().map(|&b| b as f32).sum::<f32>() / len;
    let var  = slice.iter().map(|&b| { let d = b as f32 - mean; d*d }).sum::<f32>() / len;
    (mean, var.sqrt())
}

/// Extract the TCP payload from an IPv4 packet.  Returns None for non-TCP or malformed.
fn tcp_payload(ip: &[u8]) -> Option<&[u8]> {
    let ihl  = (ip.first()? & 0x0f) as usize * 4;
    if ip.get(9)? != &6 { return None; }
    let tcp  = ip.get(ihl..)?;
    let doff = (*tcp.get(12)? >> 4) as usize * 4;
    ip.get(ihl + doff..)
}

/// Detect OpenVPN over TCP framing.
///
/// OpenVPN-TCP wraps every packet with a 2-byte big-endian length prefix, followed by a
/// 1-byte (opcode<<3 | key_id) field.  Valid opcodes are 1-9 (OpenVPN control/data packets).
/// The P_CONTROL_HARD_RESET_CLIENT_V2 packet (opcode=7, key_id=0) is always the very first
/// data segment and is exactly 16 bytes on the wire.
fn is_openvpn_tcp(payload: &[u8]) -> bool {
    if payload.len() < 3 { return false; }
    // 2-byte length must match remaining payload (payload[0..2] = length of rest)
    let declared = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if declared + 2 != payload.len() && declared > payload.len().saturating_sub(2) { return false; }
    let opcode = payload[2] >> 3;
    // OpenVPN uses opcodes 1-9; opcode 7 is P_CONTROL_HARD_RESET_CLIENT_V2 (most common first packet)
    opcode >= 1 && opcode <= 9
}

/// Extract TLS ClientHello fingerprint features from an IPv4/TCP packet.
/// Returns (num_ciphers, num_extensions, has_alpn, alpn_h2, has_grease) or None.
fn tls_fingerprint(ip: &[u8]) -> Option<(f32, f32, f32, f32, f32)> {
    let ihl  = (ip.first()? & 0x0f) as usize * 4;
    if ip.get(9)? != &6 { return None; }
    let tcp  = ip.get(ihl..)?;
    let doff = (*tcp.get(12)? >> 4) as usize * 4;
    let tls  = tcp.get(doff..)?;

    if tls.get(0)? != &0x16 || tls.get(5)? != &0x01 { return None; }
    let ch = tls.get(9..)?;
    if ch.len() < 35 { return None; }

    let sid_len = *ch.get(34)? as usize;
    let mut pos = 35 + sid_len;

    let cs_len = u16::from_be_bytes([*ch.get(pos)?, *ch.get(pos+1)?]) as usize;
    let num_ciphers = (cs_len / 2) as f32;
    pos += 2 + cs_len;

    let cm_len = *ch.get(pos)? as usize;
    pos += 1 + cm_len;

    let ext_total = u16::from_be_bytes([*ch.get(pos)?, *ch.get(pos+1)?]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;

    let mut num_ext = 0f32;
    let mut has_alpn = 0f32;
    let mut alpn_h2  = 0f32;
    let mut has_grease = 0f32;

    while pos + 4 <= ext_end.min(ch.len()) {
        let etype = u16::from_be_bytes([ch[pos], ch[pos+1]]);
        let elen  = u16::from_be_bytes([ch[pos+2], ch[pos+3]]) as usize;
        pos += 4;
        num_ext += 1.0;
        // GREASE values (0xXAXA pattern)
        if etype & 0x0f0f == 0x0a0a { has_grease = 1.0; }
        // ALPN extension (type 0x0010)
        if etype == 0x0010 && elen >= 4 {
            has_alpn = 1.0;
            // Check if h2 is offered: "h2" = [0x00, 0x02, 0x68, 0x32]
            if ch.get(pos..pos+elen)
                .map(|b| b.windows(2).any(|w| w == b"h2"))
                .unwrap_or(false)
            {
                alpn_h2 = 1.0;
            }
        }
        pos = pos.saturating_add(elen);
    }

    Some((num_ciphers, num_ext, has_alpn, alpn_h2, has_grease))
}

fn extract_features(packet: &[u8]) -> [f32; 10] {
    let entropy     = fast_entropy(packet);
    let compression = if entropy > 7.5 { 1.0 } else { 0.5 };
    let (mean, std) = mean_stddev(packet);
    // TLS fingerprint features (0 if not a TLS ClientHello)
    let (nc, ne, alpn, h2, grease) = tls_fingerprint(packet).unwrap_or((0.0, 0.0, 0.0, 0.0, 0.0));
    [
        packet.len().min(1500) as f32,
        entropy, compression, mean, std,
        nc, ne, alpn, h2, grease,
    ]
}

fn run_inference(session: &ort::Session, features: &[f32; 10]) -> f32 {
    let arr  = ndarray::Array2::from_shape_vec((1,10), features.to_vec()).unwrap();
    let dyn_ = arr.into_dyn();
    let cow  = ndarray::CowArray::from(dyn_.view());
    let inp = Value::from_array(session.allocator(), &cow).unwrap();
    let out = session.run(vec![inp]).unwrap();
    out[1].try_extract::<f32>().unwrap().view()[[0,1]]
}

// ─── dnsmasq domain blocking ─────────────────────────────────────────────────

const DNSMASQ_BLOCK_CONF: &str = "/etc/dnsmasq.d/vpn-blocker-domains.conf";

/// Known VPN provider domains — pre-seeded into dnsmasq on startup.
/// These match the is_vpn_sni() list so DNS-level blocking fires before any connection.
const VPN_PROVIDER_DOMAINS: &[&str] = &[
    "nordvpn.com", "expressvpn.com", "protonvpn.com", "surfshark.com",
    "mullvad.net", "ipvanish.com", "privateinternetaccess.com", "vyprvpn.com",
    "hidemyass.com", "cyberghostvpn.com", "torguard.net", "purevpn.com",
    "windscribe.com", "ivpn.net", "strongvpn.com", "tunnelbear.com",
    "hotspotshield.com", "zenmate.com", "airvpn.org", "azvpn.com",
    "perfect-privacy.com", "opengw.net", "vpngate.net", "hidemy.name",
    // Common VPN server hostnames
    "vpn.ac", "anonine.com", "bolehvpn.net", "cactusvpn.com",
    "fastestvpn.com", "hidelocation.net", "hide.me", "ovpn.com",
    "trust.zone", "vpm.ht", "vpn.ht",
];

/// Rewrite the dnsmasq blocklist file from built-in VPN domains + block_rules table.
fn sync_dnsmasq(db: &Connection) {
    let mut stmt = match db.prepare("SELECT target FROM block_rules WHERE direction='dst'") {
        Ok(s) => s,
        Err(_) => return,
    };
    let user_domains: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map(|rows| rows.filter_map(|r| r.ok()).collect())
        .unwrap_or_default();
    let user_domains: Vec<String> = user_domains.into_iter()
        .filter(|s| s.parse::<IpAddr>().is_err() && !s.contains('/'))
        .collect();

    // Built-in VPN domains + user rules, deduplicated
    let mut all_domains: Vec<&str> = VPN_PROVIDER_DOMAINS.to_vec();
    for d in &user_domains { all_domains.push(d.as_str()); }
    all_domains.sort_unstable();
    all_domains.dedup();

    let conf: String = std::iter::once("# managed by vpn-blocker\n".to_string())
        .chain(all_domains.iter().map(|d| format!("address=/{d}/0.0.0.0\n")))
        .collect();

    if std::fs::write(DNSMASQ_BLOCK_CONF, conf).is_ok() {
        Command::new("systemctl").args(["restart", "dnsmasq"]).status().ok();
        eprintln!("dnsmasq: {} domains blocked ({} built-in + {} user rules)",
            all_domains.len(), VPN_PROVIDER_DOMAINS.len(), user_domains.len());
    }
}

/// Add a single domain to the dnsmasq blocklist immediately (appends and reloads).
fn dnsmasq_block_domain(domain: &str) {
    if domain.parse::<IpAddr>().is_ok() || domain.contains('/') { return; }
    let entry = format!("address=/{domain}/0.0.0.0\n");
    // Append to the conf file (create if not present)
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true).append(true).open(DNSMASQ_BLOCK_CONF)
    {
        let _ = f.write_all(entry.as_bytes());
        Command::new("systemctl").args(["restart", "dnsmasq"]).status().ok();
    }
}

// ─── Blocking helpers ────────────────────────────────────────────────────────

fn iptables_rule(action: &str, direction: &str, target: &str, extra: &[&str]) {
    let flag = if direction == "src" { "-s" } else { "-d" };
    let mut args = vec![action, "FORWARD", flag, target];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["-j", "DROP"]);
    Command::new("iptables").args(&args).status().ok();
}

fn apply_block(target: &str, direction: &str) {
    iptables_rule("-I", direction, target, &[]);
}

fn remove_block(target: &str) {
    iptables_rule("-D", "dst", target, &[]);
    iptables_rule("-D", "src", target, &[]);
}

/// Block DNS-bypass protocols and redirect plain DNS through the gateway resolver.
/// DoT (port 853): blocked outright — XDP drops it, iptables is belt-and-suspenders.
/// Plain DNS (port 53): DNAT to local resolver so dnsmasq can sinkhole VPN domains.
/// DoH (port 443): cannot be intercepted at this layer; SNI detection catches the
///   actual VPN connection on first attempt regardless.
fn setup_dns_intercept(lan_iface: &str, gw_lan_ip: &str) {
    // Helper: add an iptables rule only if it doesn't already exist.
    // Suppresses the stderr noise from iptables -C on a missing rule.
    let ipt_idempotent = |args_check: &[&str], args_add: &[&str]| {
        let exists = Command::new("iptables")
            .args(args_check)
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !exists {
            Command::new("iptables").args(args_add).status().ok();
        }
    };

    // Block DoT (port 853) in the FORWARD chain — belt-and-suspenders alongside XDP
    for proto in &["tcp", "udp"] {
        ipt_idempotent(
            &["-C", "FORWARD", "-p", proto, "--dport", "853", "-j", "DROP"],
            &["-I", "FORWARD", "-p", proto, "--dport", "853", "-j", "DROP"],
        );
    }

    // DNAT: redirect all port-53 queries from LAN → gateway IP, but only if dnsmasq is active.
    // If dnsmasq is not running, skip DNAT (DNS would be black-holed otherwise).
    let dnsmasq_running = Command::new("pgrep").arg("dnsmasq")
        .stdout(std::process::Stdio::null()).status()
        .map(|s| s.success()).unwrap_or(false);
    if dnsmasq_running {
        for proto in &["udp", "tcp"] {
            let target = format!("{gw_lan_ip}:53");
            ipt_idempotent(
                &["-t", "nat", "-C", "PREROUTING",
                  "-i", lan_iface, "-p", proto, "--dport", "53",
                  "-j", "DNAT", "--to-destination", &target],
                &["-t", "nat", "-I", "PREROUTING",
                  "-i", lan_iface, "-p", proto, "--dport", "53",
                  "-j", "DNAT", "--to-destination", &target],
            );
        }
    } else {
        eprintln!("DNS intercept: dnsmasq not running, skipping port-53 DNAT (run: apt install dnsmasq)");
    }
    eprintln!("DNS intercept: DoT blocked, port-53 DNAT → {gw_lan_ip}:53");
}

fn load_xdp(iface: &str) -> Option<Ebpf> {
    let path = std::path::Path::new("vpn-blocker-ebpf");
    if !path.exists() {
        eprintln!("XDP: no eBPF object, running without fast-path");
        return None;
    }
    let mut bpf = Ebpf::load_file(path).ok()?;
    let prog: &mut Xdp = bpf.program_mut("vpn_filter")?.try_into().ok()?;
    prog.load().ok()?;
    prog.attach(iface, XdpFlags::default()).ok()?;
    eprintln!("XDP attached to {iface}");
    Some(bpf)
}

// ─── Web handlers ────────────────────────────────────────────────────────────

type AS = Arc<AppState>;

async fn index() -> Html<&'static str> { Html(DASHBOARD_HTML) }

#[derive(Serialize)]
struct BlockedEntry { ip: String, blocked_at: i64, source: String, score: Option<f32> }

async fn list_blocked(State(s): State<AS>) -> Json<Vec<BlockedEntry>> {
    let db = s.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT ip, blocked_at, source, score FROM blocked_ips ORDER BY blocked_at DESC"
    ).unwrap();
    let rows = stmt.query_map([], |r| Ok(BlockedEntry {
        ip:         r.get(0)?,
        blocked_at: r.get(1)?,
        source:     r.get(2)?,
        score:      r.get(3)?,
    })).unwrap().filter_map(|r| r.ok()).collect();
    Json(rows)
}

#[derive(Deserialize)]
struct BlockReq { target: String }

async fn add_block(State(s): State<AS>, Json(req): Json<BlockReq>) -> StatusCode {
    let target = req.target.trim().to_string();
    if target.is_empty() { return StatusCode::BAD_REQUEST; }

    // Resolve hostname → IPs if not already an IP/CIDR
    let ips: Vec<String> = if target.parse::<IpAddr>().is_ok() || target.contains('/') {
        vec![target.clone()]
    } else {
        match tokio::net::lookup_host(format!("{target}:80")).await {
            Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
            Err(_)    => vec![target.clone()],
        }
    };

    let ts = now_secs();
    for ip in &ips {
        apply_block(ip, "dst");
        {
            let db = s.db.lock().unwrap();
            db.execute(
                "INSERT OR IGNORE INTO blocked_ips (ip, blocked_at, source) VALUES (?1,?2,'manual')",
                params![ip, ts],
            ).ok();
        }
        if let Ok(addr) = ip.parse::<IpAddr>() {
            s.blocked_ips.write().unwrap().insert(addr);
        }
    }
    StatusCode::CREATED
}

async fn del_block(State(s): State<AS>, Path(ip): Path<String>) -> StatusCode {
    remove_block(&ip);
    s.db.lock().unwrap().execute("DELETE FROM blocked_ips WHERE ip=?1", params![ip]).ok();
    if let Ok(addr) = ip.parse::<IpAddr>() {
        s.blocked_ips.write().unwrap().remove(&addr);
    }
    StatusCode::OK
}

#[derive(Serialize)]
struct RuleEntry { id: i64, target: String, direction: String, created_at: i64, source: String }

async fn list_rules(State(s): State<AS>) -> Json<Vec<RuleEntry>> {
    let db = s.db.lock().unwrap();
    let mut stmt = db.prepare(
        "SELECT id, target, direction, created_at, source FROM block_rules ORDER BY created_at DESC"
    ).unwrap();
    let rows = stmt.query_map([], |r| Ok(RuleEntry {
        id:         r.get(0)?,
        target:     r.get(1)?,
        direction:  r.get(2)?,
        created_at: r.get(3)?,
        source:     r.get(4)?,
    })).unwrap().filter_map(|r| r.ok()).collect();
    Json(rows)
}

async fn add_rule(State(s): State<AS>, Json(req): Json<BlockReq>) -> StatusCode {
    let target = req.target.trim().to_string();
    if target.is_empty() { return StatusCode::BAD_REQUEST; }

    // Resolve hostname → IPs and block each one in iptables
    let is_ip   = target.parse::<IpAddr>().is_ok();
    let is_cidr = target.contains('/');
    if is_ip || is_cidr {
        apply_block(&target, "dst");
    } else {
        // Hostname: resolve all current IPs and block them, plus add DNS sinkhole
        let ips: Vec<String> = match tokio::net::lookup_host(format!("{target}:80")).await {
            Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
            Err(_)    => vec![],
        };
        for ip in &ips { apply_block(ip, "dst"); }
        dnsmasq_block_domain(&target);
    }

    let ts = now_secs();
    let db = s.db.lock().unwrap();
    db.execute(
        "INSERT OR IGNORE INTO block_rules (target, direction, created_at, source) VALUES (?1,'dst',?2,'manual')",
        params![target, ts],
    ).ok();
    StatusCode::CREATED
}

async fn del_rule(State(s): State<AS>, Path(id): Path<i64>) -> StatusCode {
    let target: Option<String> = {
        let db = s.db.lock().unwrap();
        let t = db.query_row("SELECT target FROM block_rules WHERE id=?1", params![id], |r| r.get(0)).ok();
        db.execute("DELETE FROM block_rules WHERE id=?1", params![id]).ok();
        t
    };
    if let Some(ref t) = target {
        remove_block(t);
        // Rebuild dnsmasq config without this entry
        let db = s.db.lock().unwrap();
        sync_dnsmasq(&db);
    }
    StatusCode::OK
}

async fn whois(State(s): State<AS>, Path(ip): Path<String>) -> Json<serde_json::Value> {
    let url = format!("https://ipinfo.io/{ip}/json");
    match s.http.get(&url).send().await.and_then(|r| r.error_for_status()) {
        Ok(r) => Json(r.json::<serde_json::Value>().await.unwrap_or(json!({}))),
        Err(_) => Json(json!({"error": "lookup failed"})),
    }
}

#[derive(Deserialize)]
struct ImportReq { url: Option<String>, csv: Option<String> }

async fn import_list(State(s): State<AS>, Json(req): Json<ImportReq>) -> Json<serde_json::Value> {
    let text = if let Some(url) = req.url {
        match s.http.get(&url).send().await.and_then(|r| r.error_for_status()) {
            Ok(r) => r.text().await.unwrap_or_default(),
            Err(e) => return Json(json!({"error": e.to_string()})),
        }
    } else {
        req.csv.unwrap_or_default()
    };

    let ts = now_secs();
    let mut ip_count = 0u32;
    let mut domain_count = 0u32;
    let mut new_domains: Vec<String> = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }

        // Hosts-file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
        let (sink, hostname) = if let Some(rest) = line
            .strip_prefix("0.0.0.0 ").or_else(|| line.strip_prefix("127.0.0.1 "))
        {
            let h = rest.split_whitespace().next().unwrap_or("").trim();
            (true, h)
        } else {
            (false, line.split(',').next().unwrap_or("").trim())
        };

        if hostname.is_empty() { continue; }

        // Pure IP or CIDR → iptables block
        let is_ip   = hostname.parse::<IpAddr>().is_ok();
        let is_cidr = hostname.contains('/') && hostname.split('/').next()
            .map(|p| p.parse::<IpAddr>().is_ok()).unwrap_or(false);

        if is_ip || is_cidr {
            apply_block(hostname, "dst");
            {
                let db = s.db.lock().unwrap();
                db.execute(
                    "INSERT OR IGNORE INTO blocked_ips (ip, blocked_at, source) VALUES (?1,?2,'import')",
                    params![hostname, ts],
                ).ok();
            }
            if is_ip {
                if let Ok(addr) = hostname.parse::<IpAddr>() {
                    s.blocked_ips.write().unwrap().insert(addr);
                }
            }
            ip_count += 1;
        } else if sink || (!hostname.contains(' ') && hostname.contains('.')) {
            // Hostname: add to dnsmasq sinkhole and store as a block rule
            new_domains.push(hostname.to_string());
            {
                let db = s.db.lock().unwrap();
                db.execute(
                    "INSERT OR IGNORE INTO block_rules (target, direction, created_at, source) VALUES (?1,'dst',?2,'import')",
                    params![hostname, ts],
                ).ok();
            }
            domain_count += 1;
        }
    }

    // Batch-append new domains to dnsmasq config and reload once
    if !new_domains.is_empty() {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true).append(true).open(DNSMASQ_BLOCK_CONF)
        {
            for d in &new_domains {
                let _ = writeln!(f, "address=/{d}/0.0.0.0");
            }
        }
        Command::new("systemctl").args(["restart", "dnsmasq"]).status().ok();
    }

    Json(json!({
        "message": format!("Imported {ip_count} IP/CIDR rules and {domain_count} domain blocks")
    }))
}

async fn stats(State(s): State<AS>) -> Json<serde_json::Value> {
    let blocked_count = s.blocked_ips.read().unwrap().len();
    Json(json!({
        "packets_seen":     s.pkts_seen.load(Ordering::Relaxed),
        "ml_blocks":        s.ml_blocks.load(Ordering::Relaxed),
        "blocked_ips_count": blocked_count,
        "xdp_active":       s.xdp_active.load(Ordering::Relaxed),
    }))
}

async fn sse_handler(State(s): State<AS>) -> Sse<impl futures::Stream<Item = Result<Event, Infallible>>> {
    let history: Vec<String> = s.flow_history.lock().unwrap().iter().cloned().collect();
    let rx = s.flow_tx.subscribe();

    let history_stream = futures::stream::iter(
        history.into_iter().map(|d| Ok(Event::default().data(d)))
    );
    let live_stream = BroadcastStream::new(rx)
        .filter_map(|r| r.ok())
        .map(|d| Ok(Event::default().data(d)));

    Sse::new(history_stream.chain(live_stream)).keep_alive(KeepAlive::default())
}

// ─── Packet capture loop (runs blocking inside tokio) ────────────────────────

fn capture_loop(state: Arc<AppState>, iface_name: Option<String>, session: ort::Session) {
    let interface = datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .filter(|i| iface_name.as_deref().map_or(true, |n| i.name == n))
        .last()
        .expect("No suitable interface");

    eprintln!("Capturing on: {}", interface.name);

    let xdp = load_xdp(&interface.name);
    state.xdp_active.store(xdp.is_some(), Ordering::Relaxed);
    let _xdp_guard = xdp;

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()).unwrap() {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => panic!("Unsupported channel"),
    };

    loop {
        let frame = match rx.next() {
            Ok(f) => f,
            Err(e) => { eprintln!("Recv: {e}"); continue; }
        };
        let eth = match EthernetPacket::new(frame) {
            Some(e) => e,
            None => continue,
        };
        if eth.get_ethertype() != EtherTypes::Ipv4 { continue; }
        let packet = eth.payload().to_vec();

        // Accept: TCP:443 (VPN-over-TLS) and UDP src:53 (DNS responses)
        let is_443     = is_tcp_port(&packet, 443);
        let is_dns_rsp = packet.len() >= 22
            && packet[9] == 17
            && u16::from_be_bytes([packet[20], packet[21]]) == 53;
        if !is_443 && !is_dns_rsp { continue; }

        state.pkts_seen.fetch_add(1, Ordering::Relaxed);

        // ── DNS response path: intercept A records for VPN domains ───────
        if is_dns_rsp {
            if let Some((domain, ips)) = parse_dns_vpn_ips(&packet) {
                // client IP is the DNS packet destination
                let client_ip = extract_ip(&packet, 16)
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
                for ip in ips {
                    // Skip unroutable/sinkhole addresses (e.g. 0.0.0.0 returned by our own dnsmasq)
                    if let IpAddr::V4(v4) = ip {
                        if v4.is_unspecified() || v4.is_loopback() { continue; }
                    }
                    if state.blocked_ips.read().unwrap().contains(&ip) { continue; }
                    let ip_str = ip.to_string();
                    apply_block(&ip_str, "dst");
                    {
                        let db = state.db.lock().unwrap();
                        db.execute(
                            "INSERT OR IGNORE INTO blocked_ips (ip, blocked_at, source, score) VALUES (?1,?2,'dns',1.0)",
                            params![ip_str, now_secs()],
                        ).ok();
                    }
                    state.blocked_ips.write().unwrap().insert(ip);
                    state.ml_blocks.fetch_add(1, Ordering::Relaxed);
                    eprintln!("BLOCK [dns] {ip_str} domain={domain} client={client_ip}");

                    let event = serde_json::to_string(&json!({
                        "ts":     now_secs(),
                        "src":    client_ip,
                        "dst":    ip_str,
                        "proto":  "DNS",
                        "port":   53u16,
                        "action": "block",
                        "score":  1.0f32,
                        "sni":    domain,
                        "reason": "dns",
                    })).unwrap();
                    let mut history = state.flow_history.lock().unwrap();
                    history.push_back(event.clone());
                    if history.len() > 200 { history.pop_front(); }
                    drop(history);
                    let _ = state.flow_tx.send(event);
                }
            }
            continue;
        }

        // ── TCP:443 path ─────────────────────────────────────────────────
        let src_ip = match extract_ip(&packet, 12) { Some(ip) => ip, None => continue };
        let dst_ip = match extract_ip(&packet, 16) { Some(ip) => ip, None => continue };

        // Skip if destination VPN server already blocked
        if state.blocked_ips.read().unwrap().contains(&dst_ip) { continue; }

        // ── Layer 1: TLS SNI check (fast, zero ML cost) ──────────────────
        let sni   = extract_tls_sni(&packet);
        let score: f32;
        let action: &str;
        let reason: &str;

        if let Some(ref s) = sni {
            if is_vpn_sni(s) {
                score  = 1.0;
                action = "block";
                reason = "sni";
            } else {
                score  = 0.0;
                action = "pass";
                reason = "sni";
            }
        } else {
            // ── Layer 2a: OpenVPN-over-TCP framing detection ──────────────
            // OpenVPN/TCP wraps TLS in its own 2-byte length + opcode framing,
            // so the TCP payload does NOT start with the TLS 0x16 record type.
            // Detect by checking the OpenVPN control packet structure directly.
            let payload = tcp_payload(&packet);
            if payload.map(|p| is_openvpn_tcp(p)).unwrap_or(false) {
                score  = 0.95;
                action = "block";
                reason = "fingerprint";
            } else {
                // ── Layer 2b: TLS ClientHello fingerprint ─────────────────
                // Non-browser TLS (no GREASE, no ALPN) over port 443 without SNI
                // is a strong signal for VPN/tunneling tools.
                let features = extract_features(&packet);
                let (nc, ne, alpn, _h2, grease) = (features[5], features[6], features[7], features[8], features[9]);
                let is_tls_ch = nc > 0.0 || ne > 0.0;
                if is_tls_ch && alpn == 0.0 && grease == 0.0 {
                    score  = 0.9;
                    action = "block";
                    reason = "fingerprint";
                } else {
                    // ── Layer 3: ML fallback ──────────────────────────────
                    score  = run_inference(&session, &features);
                    action = if score > 0.5 { "block" } else { "pass" };
                    reason = "ml";
                }
            }
        }

        if action == "block" {
            apply_block(&dst_ip.to_string(), "dst");
            {
                let db = state.db.lock().unwrap();
                db.execute(
                    "INSERT OR IGNORE INTO blocked_ips (ip, blocked_at, source, score) VALUES (?1,?2,?3,?4)",
                    params![dst_ip.to_string(), now_secs(), reason, score as f64],
                ).ok();
            }
            state.blocked_ips.write().unwrap().insert(dst_ip);
            state.ml_blocks.fetch_add(1, Ordering::Relaxed);
            eprintln!("BLOCK [{reason}] {dst_ip} sni={} score={score:.3} client={src_ip}",
                sni.as_deref().unwrap_or("—"));
        }

        // Emit flow event
        let event = serde_json::to_string(&json!({
            "ts":     now_secs(),
            "src":    src_ip.to_string(),
            "dst":    dst_ip.to_string(),
            "proto":  "TCP",
            "port":   443u16,
            "action": action,
            "score":  score,
            "sni":    sni.as_deref().unwrap_or(""),
            "reason": reason,
        })).unwrap();

        let mut history = state.flow_history.lock().unwrap();
        history.push_back(event.clone());
        if history.len() > 200 { history.pop_front(); }
        drop(history);

        let _ = state.flow_tx.send(event);
    }
}

// ─── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let env     = Arc::new(Environment::builder().build()?);
    let session = SessionBuilder::new(&env)?.with_model_from_file("model.onnx")?;

    let db = open_db()?;

    // Load previously blocked IPs into in-memory set and re-apply iptables
    let blocked_ips: HashSet<IpAddr> = {
        let mut stmt = db.prepare("SELECT ip FROM blocked_ips")?;
        stmt.query_map([], |r| r.get::<_,String>(0))?
            .filter_map(|r| r.ok())
            .filter_map(|s| s.parse().ok())
            .collect()
    };
    eprintln!("Restoring {} blocked IPs from DB", blocked_ips.len());
    for ip in &blocked_ips { apply_block(&ip.to_string(), "dst"); }

    // Load manual rules: IPs/CIDRs → iptables, hostnames → dnsmasq only
    {
        let mut stmt = db.prepare("SELECT target, direction FROM block_rules")?;
        let rules: Vec<(String,String)> = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .filter_map(|r| r.ok()).collect();
        for (target, dir) in &rules {
            // Only call iptables for numeric IPs and CIDRs; hostnames go through dnsmasq
            let is_ip_or_cidr = target.parse::<IpAddr>().is_ok()
                || (target.contains('/') && target.split('/').next()
                    .map(|p| p.parse::<IpAddr>().is_ok()).unwrap_or(false));
            if is_ip_or_cidr { apply_block(target, dir); }
        }
    }
    // Restore dnsmasq domain blocklist from DB
    sync_dnsmasq(&db);

    let (flow_tx, _) = broadcast::channel(512);

    let state = Arc::new(AppState {
        db:           Mutex::new(db),
        blocked_ips:  RwLock::new(blocked_ips),
        flow_tx:      flow_tx.clone(),
        flow_history: Mutex::new(VecDeque::new()),
        pkts_seen:    AtomicU64::new(0),
        ml_blocks:    AtomicU64::new(0),
        xdp_active:   AtomicBool::new(false),
        http:         reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .user_agent("vpn-blocker/0.1")
            .build()?,
    });

    // Start web server
    let app = Router::new()
        .route("/",              get(index))
        .route("/api/events",    get(sse_handler))
        .route("/api/stats",     get(stats))
        .route("/api/blocked",   get(list_blocked))
        .route("/api/block",     post(add_block))
        .route("/api/block/:ip", delete(del_block))
        .route("/api/rules",     get(list_rules).post(add_rule))
        .route("/api/rules/:id", delete(del_rule))
        .route("/api/whois/:ip", get(whois))
        .route("/api/import",    post(import_list))
        .with_state(state.clone());

    let iface = std::env::args().nth(1);

    // Set up DNS interception on the LAN interface
    if let Some(ref iface_name) = iface {
        if let Some(gw_lan_ip) = datalink::interfaces()
            .into_iter()
            .find(|i| i.name == *iface_name)
            .and_then(|i| i.ips.iter()
                .find(|ip| matches!(ip.ip(), IpAddr::V4(_)))
                .map(|ip| ip.ip().to_string()))
        {
            setup_dns_intercept(iface_name, &gw_lan_ip);
        } else {
            eprintln!("DNS intercept: could not find IPv4 address on {iface_name}, skipping DNAT");
        }
    }

    let state_cap = state.clone();

    tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([0,0,0,0], 8080));
        eprintln!("Web UI: http://{}:8080", {
            datalink::interfaces().into_iter()
                .find(|i| i.ips.iter().any(|ip| ip.ip().to_string().starts_with("192.168.")))
                .and_then(|i| i.ips.first().map(|ip| ip.ip().to_string()))
                .unwrap_or_else(|| "0.0.0.0".to_string())
        });
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    });

    // Run capture loop on a dedicated blocking thread
    tokio::task::spawn_blocking(move || capture_loop(state_cap, iface, session)).await?;
    Ok(())
}

// ─── Embedded dashboard ──────────────────────────────────────────────────────

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN/DNS Blocker</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#090d14;color:#b8c6d6;font:13px/1.5 'Courier New',monospace;min-height:100vh}
#hdr{background:#0c1220;border-bottom:2px solid #0d3d28;padding:10px 24px;display:flex;align-items:center;gap:16px}
.logo{color:#00e676;font-size:17px;font-weight:bold;letter-spacing:4px;text-shadow:0 0 12px #00e67640}
.dot{width:9px;height:9px;border-radius:50%;background:#00e676;box-shadow:0 0 10px #00e676;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.hstats{display:flex;gap:28px;margin-left:auto}
.hs{text-align:center}.hs .v{color:#00e676;font-size:20px;font-weight:bold}
.hs .l{color:#3a5060;font-size:10px;letter-spacing:1px;margin-top:2px}
nav{background:#0c1220;display:flex;border-bottom:1px solid #1a2840}
nav button{background:none;border:none;border-bottom:3px solid transparent;color:#3a6070;padding:10px 22px;cursor:pointer;font:12px 'Courier New',monospace;letter-spacing:1px;transition:color .15s}
nav button.on{color:#00e676;border-bottom-color:#00e676}
nav button:hover{color:#80c8a8}
.pan{display:none;padding:18px}.pan.on{display:block}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#0c1220;color:#3a6070;text-align:left;padding:8px 14px;border-bottom:1px solid #1a2840;letter-spacing:1px;font-weight:normal;text-transform:uppercase}
td{padding:7px 14px;border-bottom:1px solid #101825;vertical-align:middle}
tr:hover>td{background:#0e1928}
.bl{color:#ff4757;font-weight:bold}.ok{color:#00e676}.ml{color:#ffa502}
.imp{color:#7fa8d0}.mn{color:#9090a0}
.btn{background:#0d1928;border:1px solid #1a3040;color:#9ab0c0;padding:4px 11px;cursor:pointer;border-radius:3px;font:11px 'Courier New',monospace;transition:all .15s}
.btn:hover{border-color:#00e676;color:#00e676;background:#041810}
.bdg{border-color:#ff475740;color:#ff6070}
.bdg:hover{background:#1a050a;border-color:#ff4757;color:#ff4757}
input,textarea{background:#060c15;border:1px solid #1a2840;color:#b8c6d6;padding:7px 11px;border-radius:3px;font:12px 'Courier New',monospace;width:100%}
input:focus,textarea:focus{border-color:#00e676;outline:none}
.row{display:flex;gap:10px;margin-bottom:14px;align-items:flex-start}
.row input{flex:1}
.ilog{background:#060c15;border:1px solid #1a2840;padding:10px;margin-top:12px;border-radius:3px;height:130px;overflow-y:auto;font-size:11px;color:#3a6070;line-height:1.6}
.ilog .line{border-bottom:1px solid #0e1625;padding:2px 0}
.wrow{background:#060c15}
.wrow td{color:#3a7060;font-size:11px;padding:8px 14px}
.wrow .k{color:#3a8060;margin-right:8px}
@keyframes flash{from{background:#001f10}to{background:transparent}}
.flash{animation:flash .6s ease-out}
.tag{display:inline-block;padding:1px 7px;border-radius:2px;font-size:10px;letter-spacing:.5px}
.tag-ml{background:#1a0a00;color:#ffa502;border:1px solid #3a2000}
.tag-imp{background:#001228;color:#7fa8d0;border:1px solid #1a3060}
.tag-man{background:#0d1220;color:#8090a0;border:1px solid #2a3040}
.score-bar{display:inline-block;height:4px;border-radius:2px;vertical-align:middle;margin-left:6px}
</style></head>
<body>
<div id="hdr">
  <div class="dot"></div>
  <span class="logo">VPN/DNS BLOCKER</span>
  <div class="hstats">
    <div class="hs"><div class="v" id="st-p">0</div><div class="l">INSPECTED</div></div>
    <div class="hs"><div class="v" id="st-m">0</div><div class="l">ML BLOCKS</div></div>
    <div class="hs"><div class="v" id="st-b">0</div><div class="l">BLOCKED IPs</div></div>
    <div class="hs"><div class="v" id="st-x" style="color:#ffa502">—</div><div class="l">XDP</div></div>
  </div>
</div>
<nav>
  <button class="on" onclick="tab('flow',this)">&#9654; LIVE FLOW</button>
  <button onclick="tab('blocked',this)">&#128683; BLOCKED IPs</button>
  <button onclick="tab('rules',this)">&#9881; RULES</button>
  <button onclick="tab('import',this)">&#8659; IMPORT LISTS</button>
</nav>

<div id="pan-flow" class="pan on">
  <table><thead><tr>
    <th>TIME</th><th>SRC</th><th>DST (VPN SERVER)</th><th>SNI</th><th>ACTION</th><th>SCORE</th><th>BY</th>
  </tr></thead><tbody id="tb-flow"></tbody></table>
</div>

<div id="pan-blocked" class="pan">
  <table><thead><tr>
    <th>IP ADDRESS</th><th>BLOCKED AT</th><th>SOURCE</th><th>SCORE</th><th>ACTIONS</th>
  </tr></thead><tbody id="tb-blocked"></tbody></table>
</div>

<div id="pan-rules" class="pan">
  <div class="row">
    <input id="r-t" placeholder="IP, CIDR, or hostname — e.g. 185.206.225.0/24  or  nordvpn.com">
    <button class="btn" style="white-space:nowrap" onclick="addRule()">ADD BLOCK</button>
  </div>
  <table><thead><tr>
    <th>TARGET</th><th>DIRECTION</th><th>ADDED</th><th>SOURCE</th><th></th>
  </tr></thead><tbody id="tb-rules"></tbody></table>
</div>

<div id="pan-import" class="pan">
  <div class="row">
    <input id="i-url" placeholder="Raw URL — GitHub / CSV  e.g. https://raw.githubusercontent.com/...">
    <button class="btn" style="white-space:nowrap" onclick="importURL()">IMPORT URL</button>
  </div>
  <div class="row" style="margin-top:4px">
    <textarea id="i-csv" rows="5" placeholder="Or paste IPs / CIDRs here (one per line)"></textarea>
    <button class="btn" style="white-space:nowrap;margin-top:0" onclick="importCSV()">IMPORT CSV</button>
  </div>
  <div class="ilog" id="ilog"></div>
</div>

<script>
// ── Tab switching ─────────────────────────────────────────────────────────────
function tab(id,btn){
  document.querySelectorAll('.pan').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('on'));
  document.getElementById('pan-'+id).classList.add('on');
  btn.classList.add('on');
  if(id==='blocked')loadBlocked();
  if(id==='rules')loadRules();
}

// ── Live flow via SSE ─────────────────────────────────────────────────────────
const MAX_ROWS=150;
const es=new EventSource('/api/events');
es.onmessage=e=>addFlow(JSON.parse(e.data));

function addFlow(f){
  const tb=document.getElementById('tb-flow');
  const tr=document.createElement('tr');
  const isBlock=f.action==='block';
  tr.className='flash';
  const act=isBlock
    ?'<span class="bl">&#9632; BLOCKED</span>'
    :'<span class="ok">&#9654; PASS</span>';
  const sc=f.score>0.01?scoreBar(f.score):'<span style="color:#2a4050">—</span>';
  const sni=f.sni?`<span style="color:${isBlock?'#ff9060':'#6090a0'}">${f.sni}</span>`:'<span style="color:#2a4050">—</span>';
  const by=f.reason==='sni'?'<span style="color:#7fa8d0">SNI</span>':f.reason==='dns'?'<span style="color:#a0c8ff">DNS</span>':f.reason==='fingerprint'?'<span style="color:#c080ff">FP</span>':'<span style="color:#ffa502">ML</span>';
  tr.innerHTML=`<td>${fmtT(f.ts)}</td><td>${f.src}</td><td style="color:${isBlock?'#ff8070':'#b8c6d6'}">${f.dst}</td><td>${sni}</td><td>${act}</td><td>${sc}</td><td>${by}</td>`;
  tb.insertBefore(tr,tb.firstChild);
  while(tb.rows.length>MAX_ROWS)tb.deleteRow(-1);
}

function scoreBar(s){
  const pct=Math.round(s*100);
  const col=s>0.8?'#ff4757':s>0.5?'#ffa502':'#00e676';
  return `<span style="color:${col}">${pct}%</span><span class="score-bar" style="width:${pct/2}px;background:${col}"></span>`;
}

// ── Blocked IPs ───────────────────────────────────────────────────────────────
async function loadBlocked(){
  const data=await fetch('/api/blocked').then(r=>r.json());
  const tb=document.getElementById('tb-blocked');
  tb.innerHTML='';
  for(const r of data){
    const tagClass=r.source==='ml'?'tag-ml':r.source==='import'?'tag-imp':'tag-man';
    const tagText=r.source.toUpperCase();
    const sc=r.score!=null?scoreBar(r.score):'<span style="color:#2a4050">—</span>';
    const tr=document.createElement('tr');
    tr.id='br-'+eid(r.ip);
    tr.innerHTML=`<td style="font-family:monospace">${r.ip}</td><td>${fmtD(r.blocked_at)}</td><td><span class="tag ${tagClass}">${tagText}</span></td><td>${sc}</td><td style="white-space:nowrap"><button class="btn" onclick="toggleW('${r.ip}',this)">WHOIS</button> <button class="btn bdg" onclick="unblock('${r.ip}')">UNBLOCK</button></td>`;
    tb.appendChild(tr);
    const wr=document.createElement('tr');
    wr.className='wrow';wr.id='w-'+eid(r.ip);wr.style.display='none';
    wr.innerHTML='<td colspan="5"><em style="color:#2a4050">Loading...</em></td>';
    tb.appendChild(wr);
  }
}

async function toggleW(ip,btn){
  const wr=document.getElementById('w-'+eid(ip));
  if(wr.style.display==='table-row'){wr.style.display='none';return;}
  wr.style.display='table-row';
  if(wr._done)return;
  const d=await fetch('/api/whois/'+encodeURIComponent(ip)).then(r=>r.json());
  const fields=[
    d.org&&`<span class="k">ORG</span>${d.org}`,
    d.country&&`<span class="k">CC</span>${d.country}`,
    (d.city||d.region)&&`<span class="k">LOC</span>${[d.city,d.region].filter(Boolean).join(', ')}`,
    d.hostname&&`<span class="k">HOST</span>${d.hostname}`,
    d.timezone&&`<span class="k">TZ</span>${d.timezone}`,
  ].filter(Boolean);
  wr.querySelector('td').innerHTML=fields.join(' &nbsp;|&nbsp; ');
  wr._done=true;
}

async function unblock(ip){
  if(!confirm('Remove block for '+ip+'?'))return;
  await fetch('/api/block/'+encodeURIComponent(ip),{method:'DELETE'});
  loadBlocked();
}

// ── Rules ─────────────────────────────────────────────────────────────────────
async function loadRules(){
  const data=await fetch('/api/rules').then(r=>r.json());
  const tb=document.getElementById('tb-rules');
  tb.innerHTML='';
  for(const r of data){
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${r.target}</td><td>${r.direction.toUpperCase()}</td><td>${fmtD(r.created_at)}</td><td>${r.source}</td><td><button class="btn bdg" onclick="delRule(${r.id})">REMOVE</button></td>`;
    tb.appendChild(tr);
  }
}

async function addRule(){
  const t=document.getElementById('r-t').value.trim();
  if(!t)return;
  await fetch('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:t})});
  document.getElementById('r-t').value='';
  loadRules();
}

async function delRule(id){
  await fetch('/api/rules/'+id,{method:'DELETE'});
  loadRules();
}

// ── Import ────────────────────────────────────────────────────────────────────
function ilog(msg){
  const el=document.getElementById('ilog');
  const d=document.createElement('div');d.className='line';d.textContent=new Date().toTimeString().slice(0,8)+' '+msg;
  el.insertBefore(d,el.firstChild);
}

async function importURL(){
  const url=document.getElementById('i-url').value.trim();
  if(!url)return;ilog('Fetching '+url+'...');
  const r=await fetch('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})}).then(r=>r.json());
  ilog(r.message||r.error);
}

async function importCSV(){
  const csv=document.getElementById('i-csv').value.trim();
  if(!csv)return;ilog('Importing pasted data...');
  const r=await fetch('/api/import',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({csv})}).then(r=>r.json());
  ilog(r.message||r.error);
}

// ── Stats polling ─────────────────────────────────────────────────────────────
async function pollStats(){
  const s=await fetch('/api/stats').then(r=>r.json()).catch(()=>null);
  if(!s)return;
  document.getElementById('st-p').textContent=fmt(s.packets_seen);
  document.getElementById('st-m').textContent=fmt(s.ml_blocks);
  document.getElementById('st-b').textContent=fmt(s.blocked_ips_count);
  const x=document.getElementById('st-x');
  x.textContent=s.xdp_active?'ON':'OFF';
  x.style.color=s.xdp_active?'#00e676':'#ffa502';
}
setInterval(pollStats,2000);pollStats();

// ── Helpers ───────────────────────────────────────────────────────────────────
const fmt=n=>n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'K':String(n);
const fmtT=ts=>new Date(ts*1000).toTimeString().slice(0,8);
const fmtD=ts=>{const d=new Date(ts*1000);return d.toLocaleDateString()+' '+d.toTimeString().slice(0,8)};
const eid=ip=>ip.replace(/[.:\/]/g,'_');
</script></body></html>"#;
