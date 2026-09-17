//! Read-only multicast notifications. Every kernel datagram invalidates the
//! snapshot, including unknown messages; no fragile event payload parsing.

use std::{io, os::fd::AsRawFd};

use anyhow::{Context, Result, bail};
use rtnetlink::{
    constants::{
        RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV4_RULE, RTMGRP_IPV6_IFADDR,
        RTMGRP_IPV6_ROUTE, RTMGRP_LINK, RTMGRP_NEIGH, RTMGRP_TC,
    },
    sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE},
};

pub(super) struct RouteEvents(Vec<Socket>);

impl RouteEvents {
    pub(super) fn open() -> Result<Self> {
        let mut socket = Socket::new(NETLINK_ROUTE).context("opening redirect route monitor")?;
        let groups = RTMGRP_LINK
            | RTMGRP_NEIGH
            | RTMGRP_TC
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV4_RULE
            | RTMGRP_IPV6_IFADDR
            | RTMGRP_IPV6_ROUTE;
        socket
            .bind(&SocketAddr::new(0, groups))
            .context("subscribing redirect route monitor")?;
        // RTNLGRP_IPV4_NETCONF (linux/rtnetlink.h): forwarding/rp_filter changes.
        socket
            .add_membership(24)
            .context("subscribing IPv4 netconf changes")?;
        socket.set_non_blocking(true)?;
        let mut nft = Socket::new(libc::NETLINK_NETFILTER as isize)?;
        nft.bind(&SocketAddr::new(0, 1 << (libc::NFNLGRP_NFTABLES - 1)))?;
        nft.set_non_blocking(true)?;
        let mut xfrm = Socket::new(libc::NETLINK_XFRM as isize)?;
        // XFRMGRP_POLICY, from linux/xfrm.h (includes default-policy updates).
        xfrm.bind(&SocketAddr::new(0, 8))?;
        xfrm.set_non_blocking(true)?;
        Ok(Self(vec![socket, nft, xfrm]))
    }

    /// Bounded wait so shutdown does not depend on another network event.
    pub(super) fn changed(&self) -> Result<bool> {
        self.poll(200)
    }

    pub(super) fn pending(&self) -> Result<bool> {
        self.poll(0)
    }

    fn poll(&self, timeout_ms: i32) -> Result<bool> {
        let mut polls: Vec<_> = self
            .0
            .iter()
            .map(|socket| libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: polls holds initialized descriptors for live sockets.
        let ready =
            unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, timeout_ms) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error).context("polling redirect route monitor");
        }
        if ready == 0 {
            return Ok(false);
        }
        if polls
            .iter()
            .any(|poll| poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0)
        {
            bail!("redirect policy monitor lost notifications");
        }
        let Some((socket, _)) = self
            .0
            .iter()
            .zip(&polls)
            .find(|(_, poll)| poll.revents & libc::POLLIN != 0)
        else {
            return Ok(false);
        };
        let mut buffer = [0u8; 8192];
        // Truncation is harmless: any datagram invalidates the whole cache.
        // Do not enable NETLINK_NO_ENOBUFS; lost notifications are errors.
        match socket.recv_from(&mut &mut buffer[..], 0) {
            Ok((_, address)) => Ok(address.port_number() == 0),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error).context("receiving redirect route notifications"),
        }
    }
}
