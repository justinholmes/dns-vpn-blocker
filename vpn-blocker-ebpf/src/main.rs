#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[xdp]
pub fn vpn_filter(ctx: XdpContext) -> u32 {
    match try_filter(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + core::mem::size_of::<T>() > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

fn try_filter(ctx: &XdpContext) -> Result<u32, ()> {
    // ── Ethernet ────────────────────────────────────────────────────────────
    let ethhdr: *const EthHdr = ptr_at(ctx, 0)?;
    if unsafe { (*ethhdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── IPv4 ────────────────────────────────────────────────────────────────
    let iphdr: *const Ipv4Hdr = ptr_at(ctx, EthHdr::LEN)?;
    // Only handle standard 20-byte IP headers (IHL=5, no options).
    // The verifier needs constant packet offsets for safe access; dynamic IHL makes
    // range-proofs unsound.  Packets with IP options (IHL != 5) are rare and fall
    // through to XDP_PASS where the ML path handles them.
    let ihl_byte: *const u8 = ptr_at(ctx, EthHdr::LEN)?;
    if unsafe { *ihl_byte } & 0x0F != 5 {
        return Ok(xdp_action::XDP_PASS);
    }
    let proto = unsafe { (*iphdr).proto };
    const TRANSPORT_OFF: usize = EthHdr::LEN + Ipv4Hdr::LEN;
    let transport_off = TRANSPORT_OFF;

    // ── Protocol-level tunnels (no port needed) ──────────────────────────────
    // IPsec ESP (50) and AH (51) — only IPsec uses these protocol numbers.
    if proto == IpProto::Esp || proto == IpProto::Ah {
        return Ok(xdp_action::XDP_DROP);
    }
    // GRE (47) — PPTP data tunnel; also used by some proprietary VPNs.
    if proto == IpProto::Gre {
        return Ok(xdp_action::XDP_DROP);
    }
    // IP-in-IP (4) and IPv6-in-IPv4 (41 / SIT) — used by tunnel VPNs.
    if proto == IpProto::Ipv4 || proto == IpProto::Ipv6 {
        return Ok(xdp_action::XDP_DROP);
    }

    // ── TCP VPNs ─────────────────────────────────────────────────────────────
    // For TCP we check ports only — signature bytes live in the payload and
    // require TCP connection state that XDP doesn't have.
    // OpenVPN over TCP:443 is NOT caught here; that's the ML path's job.
    if proto == IpProto::Tcp {
        let tcphdr: *const TcpHdr = ptr_at(ctx, transport_off)?;
        let dst = u16::from_be(unsafe { (*tcphdr).dest });
        let src = u16::from_be(unsafe { (*tcphdr).source });

        // PPTP control channel
        if dst == 1723 || src == 1723 {
            return Ok(xdp_action::XDP_DROP);
        }
        // OpenVPN TCP (standard port — non-standard/443 handled by ML)
        if dst == 1194 || src == 1194 {
            return Ok(xdp_action::XDP_DROP);
        }
        // SOCKS5 proxy (standard port 1080)
        if dst == 1080 || src == 1080 {
            return Ok(xdp_action::XDP_DROP);
        }
        // DNS over TLS (DoT) — port 853; blocks encrypted DNS bypass
        if dst == 853 || src == 853 {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    // ── UDP VPNs — port + payload signature ──────────────────────────────────
    if proto == IpProto::Udp {
        let udphdr: *const UdpHdr = ptr_at(ctx, transport_off)?;
        let dst = u16::from_be(unsafe { (*udphdr).dest });
        let src = u16::from_be(unsafe { (*udphdr).source });
        let payload_off = transport_off + UdpHdr::LEN;

        // IKE / IPsec key exchange — ports 500 and 4500 (NAT-T).
        // Everything on these ports is IPsec-related.
        if dst == 500 || src == 500 || dst == 4500 || src == 4500 {
            return Ok(xdp_action::XDP_DROP);
        }

        // L2TP (classic Windows VPN, usually layered over IPsec)
        if dst == 1701 || src == 1701 {
            return Ok(xdp_action::XDP_DROP);
        }

        // OpenVPN UDP — port + opcode signature.
        // First byte: opcode = high 3 bits (>> 3), valid range 1-9.
        if dst == 1194 || src == 1194 {
            if let Ok(b0) = ptr_at::<u8>(ctx, payload_off) {
                let opcode = unsafe { *b0 >> 3 };
                if opcode >= 1 && opcode <= 9 {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }

        // WireGuard / Tailscale — detected on ANY UDP port by fixed message size + header.
        // WG handshake messages have fixed lengths and the same 4-byte header format:
        //   [type: 1|2|3, reserved: 0,0,0, ...]
        //   Type 1 (Initiation):   exactly 148 bytes of UDP payload
        //   Type 2 (Response):     exactly  92 bytes of UDP payload
        //   Type 3 (Cookie Reply): exactly  64 bytes of UDP payload
        // The combination of fixed size + reserved zeros is essentially collision-free.
        // This catches WireGuard on default port 51820, Tailscale on 41641,
        // and any custom-port WireGuard deployments.
        {
            let udp_len = u16::from_be(unsafe { (*udphdr).len }) as usize;
            let udp_data_len = udp_len.saturating_sub(8); // subtract 8-byte UDP header
            if let Ok(b0) = ptr_at::<u8>(ctx, payload_off) {
                let wg_type = unsafe { *b0 };
                let wg_expected_len: usize = match wg_type {
                    1 => 148,
                    2 => 92,
                    3 => 64,
                    _ => 0,
                };
                if wg_expected_len > 0 && udp_data_len == wg_expected_len {
                    let r = (
                        ptr_at::<u8>(ctx, payload_off + 1),
                        ptr_at::<u8>(ctx, payload_off + 2),
                        ptr_at::<u8>(ctx, payload_off + 3),
                    );
                    if let (Ok(b1), Ok(b2), Ok(b3)) = r {
                        if unsafe { *b1 == 0 && *b2 == 0 && *b3 == 0 } {
                            return Ok(xdp_action::XDP_DROP);
                        }
                    }
                }
            }
        }

        // ZeroTier — UDP:9993 (standard) + any port with ZT framing.
        // ZeroTier v1 packets: bytes 0-4 = dest addr, 5-9 = src addr, 10 = flags|hop.
        // The verb byte at position 11 identifies the packet type (0x01-0x14 for known verbs).
        // On port 9993 we also check the lower-confidence verb-in-low-5-bits heuristic.
        if dst == 9993 || src == 9993 {
            if let Ok(b0) = ptr_at::<u8>(ctx, payload_off) {
                let verb = unsafe { *b0 & 0x1F };
                if verb >= 1 && verb <= 16 {
                    return Ok(xdp_action::XDP_DROP);
                }
            }
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
