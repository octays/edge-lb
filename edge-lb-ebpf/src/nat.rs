//! NAT header mutation shared by forward and return paths. Never PIPE on error.

use aya_ebpf::{bindings::TC_ACT_SHOT, programs::TcContext};
use aya_ebpf_cty::c_long;

const BPF_F_PSEUDO_HDR: u64 = 1 << 4;

// Deliberately not convertible to c_long: `?` must not reach an entry point's
// parse-error PIPE handler after a partial mutation.
pub struct MutationFailed;

impl MutationFailed {
    #[inline(always)]
    pub fn action(self) -> i32 {
        TC_ACT_SHOT
    }
}

pub struct Rewrite {
    pub old_address: u32,
    pub new_address: u32,
    pub old_port: u16,
    pub new_port: u16,
    pub preserve_zero_udp_checksum: bool,
}

impl Rewrite {
    #[inline(always)]
    pub fn destination(
        self,
        ctx: &mut TcContext,
        ip_off: usize,
        l4_off: usize,
        l4_csum_off: usize,
    ) -> Result<(), MutationFailed> {
        self.apply(ctx, ip_off + 16, ip_off + 10, l4_off + 2, l4_csum_off)
    }

    #[inline(always)]
    pub fn source(
        self,
        ctx: &mut TcContext,
        ip_off: usize,
        l4_off: usize,
        l4_csum_off: usize,
    ) -> Result<(), MutationFailed> {
        self.apply(ctx, ip_off + 12, ip_off + 10, l4_off, l4_csum_off)
    }

    #[inline(always)]
    fn apply(
        self,
        ctx: &mut TcContext,
        address_off: usize,
        ip_csum_off: usize,
        port_off: usize,
        l4_csum_off: usize,
    ) -> Result<(), MutationFailed> {
        self.write(ctx, address_off, ip_csum_off, port_off, l4_csum_off)
            .map_err(|_| {
                // An earlier store/helper may already have changed this skb.
                super::native_bump(|stats| stats.checksum_error += 1);
                MutationFailed
            })
    }

    #[inline(always)]
    fn write(
        self,
        ctx: &mut TcContext,
        address_off: usize,
        ip_csum_off: usize,
        port_off: usize,
        l4_csum_off: usize,
    ) -> Result<(), c_long> {
        let old_address = self.old_address.to_be();
        let new_address = self.new_address.to_be();
        ctx.store(address_off, &new_address, 0)?;
        ctx.l3_csum_replace(ip_csum_off, old_address as u64, new_address as u64, 4)?;
        ctx.l4_csum_replace(
            l4_csum_off,
            old_address as u64,
            new_address as u64,
            4 | BPF_F_PSEUDO_HDR,
        )?;
        ctx.store(port_off, &self.new_port.to_be(), 0)?;
        ctx.l4_csum_replace(
            l4_csum_off,
            self.old_port.to_be() as u64,
            self.new_port.to_be() as u64,
            2,
        )?;
        if self.preserve_zero_udp_checksum {
            ctx.store(l4_csum_off, &0u16, 0)?;
        }
        Ok(())
    }
}
