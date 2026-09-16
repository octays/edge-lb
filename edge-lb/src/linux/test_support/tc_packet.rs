//! Packet construction and TC test-run helpers shared by both directions.

use aya::{
    Ebpf,
    programs::{SchedClassifier, TestRun, TestRunOptions},
};

pub(in crate::linux) use crate::linux::test_support::packet::checksum;

pub(in crate::linux) const VIP: u32 = 0xc000020a;
pub(in crate::linux) const TARGET: u32 = 0xc0000214;

// Prefix of Linux __sk_buff accepted by PROG_TEST_RUN. The kernel zero-fills
// omitted trailing fields; no raw magic offsets are needed.
#[repr(C)]
#[derive(Default)]
struct SkbContext {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
}

pub(in crate::linux) fn packet(proto: u8, ttl: u8, sport: u16, udp_zero: bool) -> Vec<u8> {
    let l4_len = if proto == 6 { 20 } else { 8 };
    let mut data = vec![0u8; 14 + 20 + l4_len];
    // PROG_TEST_RUN uses lo: its zero MAC makes this a PACKET_HOST skb.
    data[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 12]);
    data[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    data[14] = 0x45;
    data[15] = (46 << 2) | 3;
    data[16..18].copy_from_slice(&((20 + l4_len) as u16).to_be_bytes());
    data[22] = ttl;
    data[23] = proto;
    data[26..30].copy_from_slice(&[198, 51, 100, 1]);
    data[30..34].copy_from_slice(&VIP.to_be_bytes());
    data[34..36].copy_from_slice(&sport.to_be_bytes());
    data[36..38].copy_from_slice(&5060u16.to_be_bytes());
    if proto == 6 {
        data[46] = 0x50;
        data[47] = 0x10;
    } else {
        data[38..40].copy_from_slice(&(l4_len as u16).to_be_bytes());
    }
    repair_checksums(&mut data, udp_zero);
    data
}

pub(in crate::linux) fn l4_checksum(data: &[u8]) -> u16 {
    let offset = 14 + usize::from(data[14] & 0x0f) * 4;
    let mut pseudo = data[26..34].to_vec();
    pseudo.extend_from_slice(&[0, data[23]]);
    pseudo.extend_from_slice(&((data.len() - offset) as u16).to_be_bytes());
    pseudo.extend_from_slice(&data[offset..]);
    checksum(&pseudo)
}

pub(in crate::linux) fn repair_checksums(data: &mut [u8], udp_zero: bool) {
    let offset = 14 + usize::from(data[14] & 0x0f) * 4;
    data[24..26].fill(0);
    let sum = checksum(&data[14..offset]);
    data[24..26].copy_from_slice(&sum.to_be_bytes());
    let csum_offset = offset + if data[23] == 6 { 16 } else { 6 };
    data[csum_offset..csum_offset + 2].fill(0);
    if data[23] == 6 || !udp_zero {
        let sum = l4_checksum(data);
        let sum = if sum == 0 { 0xffff } else { sum };
        data[csum_offset..csum_offset + 2].copy_from_slice(&sum.to_be_bytes());
    }
}

pub(in crate::linux) fn load_program(bpf: &mut Ebpf, name: &str) {
    let program: &mut SchedClassifier = bpf.program_mut(name).unwrap().try_into().unwrap();
    program.load().expect("TC verifier acceptance");
}

pub(in crate::linux) fn run(bpf: &Ebpf, name: &str, data: &[u8]) -> (u32, Vec<u8>) {
    run_on(bpf, name, data, 1)
}

pub(in crate::linux) fn run_on(
    bpf: &Ebpf,
    name: &str,
    data: &[u8],
    ifindex: u32,
) -> (u32, Vec<u8>) {
    let context = SkbContext {
        ingress_ifindex: ifindex,
        ifindex,
        ..Default::default()
    };
    assert_eq!(std::mem::size_of::<SkbContext>(), 44);
    // SAFETY: repr(C) has only initialized u32 fields and no padding.
    let context_bytes = unsafe {
        std::slice::from_raw_parts(
            (&context as *const SkbContext).cast(),
            std::mem::size_of_val(&context),
        )
    };
    let mut output = vec![0u8; data.len().max(2048)];
    let program: &SchedClassifier = bpf.program(name).unwrap().try_into().unwrap();
    let result = program
        .test_run(TestRunOptions {
            data_in: Some(data),
            data_out: Some(&mut output),
            ctx_in: Some(context_bytes),
            ..Default::default()
        })
        .unwrap_or_else(|error| panic!("TC test run {name}, input={data:02x?}: {error}"));
    output.truncate(result.data_size_out as usize);
    (result.return_value, output)
}
