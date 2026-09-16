//! Internet checksum oracle for kernel packet tests.

pub(in crate::linux) fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in bytes.chunks(2) {
        sum += u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
