//! Shared IPv4 redirect mechanics. Admission and statistics belong to callers.

use aya_ebpf::{bindings::TC_ACT_REDIRECT, helpers::bpf_redirect, programs::TcContext};

pub fn read(ctx: &TcContext) -> Result<[u8; 20], ()> {
    let ip = ctx.load::<[u8; 20]>(14).map_err(|_| ())?;
    let skb = ctx.skb.skb;
    if ip[0] != 0x45
        || u16::from_be_bytes([ip[6], ip[7]]) & 0xbfff != 0
        || unsafe {
            (*skb).mark != 0
                || (*skb).pkt_type != 0
                || (*skb).vlan_present != 0
                || (*skb).gso_segs > 1
                || (*skb).gso_size != 0
        }
    {
        return Err(());
    }
    let len = u16::from_be_bytes([ip[2], ip[3]]) as u32;
    let min = match ip[9] {
        6 => 40,
        17 => 28,
        _ => return Err(()),
    };
    // Helpers handle non-linear payloads; do not pull/copy the entire skb.
    if len < min || len + 14 != ctx.len() {
        return Err(());
    }
    let mut sum = 0u32;
    let mut offset = 0;
    while offset < 20 {
        sum += u16::from_be_bytes([ip[offset], ip[offset + 1]]) as u32;
        offset += 2;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    if sum != 0xffff {
        return Err(());
    }
    Ok(ip)
}

pub fn unicast_address(ip: u32) -> bool {
    let bytes = ip.to_be_bytes();
    bytes[0] != 0 && bytes[0] != 127 && bytes[0] < 224 && !(bytes[0] == 169 && bytes[1] == 254)
}

pub fn unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

/// Any error after this boundary requires SHOT, never kernel fallthrough.
pub fn transmit(
    ctx: &mut TcContext,
    mut ip: [u8; 20],
    ifindex: u32,
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
) -> Result<i32, ()> {
    let old_word = u16::from_be_bytes([ip[8], ip[9]]);
    ip[8] -= 1;
    let new_word = u16::from_be_bytes([ip[8], ip[9]]);
    let check = super::incremental_csum(u16::from_be_bytes([ip[10], ip[11]]), old_word, new_word);
    ip[10..12].copy_from_slice(&check.to_be_bytes());
    let mut macs = [0u8; 12];
    macs[..6].copy_from_slice(&destination_mac);
    macs[6..].copy_from_slice(&source_mac);
    ctx.store(14, &ip, 0).map_err(|_| ())?;
    ctx.store(0, &macs, 0).map_err(|_| ())?;
    let action = unsafe { bpf_redirect(ifindex, 0) } as i32;
    if action == TC_ACT_REDIRECT {
        Ok(action)
    } else {
        Err(())
    }
}
