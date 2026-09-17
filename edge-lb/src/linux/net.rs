//! Link/VXLAN helpers shared by the backend and gateway roles.

use std::{fs, future::Future, net::IpAddr};

use anyhow::{Context, Result};
use futures_util::{StreamExt, TryStreamExt};
use rtnetlink::{
    LinkUnspec, LinkVxlan, new_connection,
    packet_core::{
        NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
    },
    packet_route::{
        AddressFamily, RouteNetlinkMessage,
        neighbour::{
            NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
        },
        route::RouteType,
    },
};

/// Ifindex of a device, read at runtime (never hardcoded: VXLAN ifindex
/// changes whenever the link is recreated).
pub fn ifindex(dev: &str) -> Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let name = std::ffi::CString::new(dev).context("interface name contains NUL")?;
        let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if idx == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("looking up interface {dev}"));
        }
        Ok(idx)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dev;
        anyhow::bail!("interface operations require Linux")
    }
}

pub fn link_exists(dev: &str) -> bool {
    if dev.is_empty() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(name) = std::ffi::CString::new(dev) else {
            return false;
        };
        (unsafe { libc::if_nametoindex(name.as_ptr()) } != 0)
    }
    #[cfg(not(target_os = "linux"))]
    false
}

/// Allow packets arriving from a VXLAN device to use a local VIP as their
/// source after native reverse DNAT. Linux otherwise rejects them as local-
/// source martians before the normal route lookup.
pub fn set_accept_local(dev: &str, enabled: bool) -> Result<()> {
    let path = format!("/proc/sys/net/ipv4/conf/{dev}/accept_local");
    fs::write(&path, if enabled { "1\n" } else { "0\n" })
        .with_context(|| format!("failed to set accept_local on {dev}"))
}

pub fn link_mtu(dev: &str) -> Result<u32> {
    let path = format!("/sys/class/net/{dev}/mtu");
    std::fs::read_to_string(&path)
        .with_context(|| format!("reading MTU for {dev}"))?
        .trim()
        .parse()
        .with_context(|| format!("invalid MTU in {path}"))
}

pub fn is_up(dev: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{dev}/operstate"))
        .is_ok_and(|state| matches!(state.trim(), "up" | "unknown"))
}

/// Return the configured IPv4 prefix on `dev` that contains `wanted`.
/// This is used for automatic control-plane trust ranges and deliberately
/// reads rtnetlink instead of parsing `ip addr` output.
pub fn interface_ipv4_cidr(dev: &str, wanted: IpAddr) -> Option<String> {
    let wanted = match wanted {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return None,
    };
    let index = ifindex(dev).ok()?;
    run_netlink(async move {
        let (connection, handle, _) = new_connection().context("opening rtnetlink connection")?;
        tokio::spawn(connection);
        let mut addresses = handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        while let Some(address) = addresses.try_next().await.context("dumping addresses")? {
            let ip =
                address
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        rtnetlink::packet_route::address::AddressAttribute::Local(IpAddr::V4(
                            ip,
                        ))
                        | rtnetlink::packet_route::address::AddressAttribute::Address(
                            IpAddr::V4(ip),
                        ) => Some(*ip),
                        _ => None,
                    });
            let Some(ip) = ip else { continue };
            let prefix = address.header.prefix_len;
            if prefix <= 32
                && (u32::from(ip) & ipv4_mask(prefix)) == (u32::from(wanted) & ipv4_mask(prefix))
            {
                return Ok(Some(format!("{ip}/{prefix}")));
            }
        }
        Ok(None)
    })
    .ok()
    .flatten()
}

/// Find the interface that owns an IPv4 address using the kernel interface
/// address list. This is used to resolve the source device for UDP discovery.
pub fn interface_for_ipv4(wanted: IpAddr) -> Option<String> {
    let wanted = match wanted {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return None,
    };
    #[cfg(target_os = "linux")]
    unsafe {
        let mut list = std::ptr::null_mut();
        if libc::getifaddrs(&mut list) != 0 {
            return None;
        }
        let mut current = list;
        let mut result = None;
        while !current.is_null() {
            let item = &*current;
            if !item.ifa_addr.is_null() && (*item.ifa_addr).sa_family as i32 == libc::AF_INET {
                let addr = &*(item.ifa_addr.cast::<libc::sockaddr_in>());
                let value =
                    IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)));
                if value == IpAddr::V4(wanted) && !item.ifa_name.is_null() {
                    result = std::ffi::CStr::from_ptr(item.ifa_name)
                        .to_str()
                        .ok()
                        .map(str::to_string);
                    break;
                }
            }
            current = (*current).ifa_next;
        }
        libc::freeifaddrs(list);
        result
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = wanted;
        None
    }
}

/// Dump all IPv4 interface addresses as `(device, address/prefix)` pairs.
pub fn ipv4_addresses() -> Vec<(String, String)> {
    run_netlink(async {
        let (connection, handle, _) = new_connection().context("opening rtnetlink connection")?;
        tokio::spawn(connection);
        let mut addresses = handle.address().get().execute();
        let mut result = Vec::new();
        while let Some(address) = addresses.try_next().await.context("dumping addresses")? {
            let Some(IpAddr::V4(ip)) =
                address
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        rtnetlink::packet_route::address::AddressAttribute::Local(ip)
                        | rtnetlink::packet_route::address::AddressAttribute::Address(ip) => {
                            Some(*ip)
                        }
                        _ => None,
                    })
            else {
                continue;
            };
            let mut name = [0_u8; libc::IFNAMSIZ];
            let index = address.header.index;
            if unsafe { libc::if_indextoname(index, name.as_mut_ptr().cast()) }.is_null() {
                continue;
            }
            let Ok(dev) = unsafe { std::ffi::CStr::from_ptr(name.as_ptr().cast()) }.to_str() else {
                continue;
            };
            result.push((
                dev.to_string(),
                format!("{ip}/{}", address.header.prefix_len),
            ));
        }
        Ok(result)
    })
    .unwrap_or_default()
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

/// Current point-to-point remote of a vxlan device, if any.
pub fn vxlan_remote(dev: &str) -> Option<IpAddr> {
    link_state(dev).and_then(|state| state.remote)
}

#[derive(Debug, Default)]
struct LinkState {
    mtu: Option<u32>,
    vxlan_id: Option<u32>,
    vxlan_port: Option<u16>,
    remote: Option<IpAddr>,
}

fn link_state(dev: &str) -> Option<LinkState> {
    run_netlink(async move {
        let (connection, handle, _) = new_connection().context("opening rtnetlink connection")?;
        tokio::spawn(connection);
        let mut links = handle.link().get().match_name(dev.to_string()).execute();
        let link = links.try_next().await.context("reading link state")?;
        let Some(link) = link else {
            return Ok(None);
        };
        let mut state = LinkState {
            mtu: None,
            vxlan_id: None,
            vxlan_port: None,
            remote: None,
        };
        for attribute in link.attributes {
            match attribute {
                rtnetlink::packet_route::link::LinkAttribute::Mtu(mtu) => state.mtu = Some(mtu),
                rtnetlink::packet_route::link::LinkAttribute::LinkInfo(infos) => {
                    for info in infos {
                        if let rtnetlink::packet_route::link::LinkInfo::Data(
                            rtnetlink::packet_route::link::InfoData::Vxlan(values),
                        ) = info
                        {
                            for value in values {
                                match value {
                                    rtnetlink::packet_route::link::InfoVxlan::Id(id) => {
                                        state.vxlan_id = Some(id)
                                    }
                                    rtnetlink::packet_route::link::InfoVxlan::Port(port) => {
                                        state.vxlan_port = Some(port)
                                    }
                                    rtnetlink::packet_route::link::InfoVxlan::Group(ip) => {
                                        state.remote = Some(IpAddr::V4(ip))
                                    }
                                    rtnetlink::packet_route::link::InfoVxlan::Group6(ip) => {
                                        state.remote = Some(IpAddr::V6(ip))
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(Some(state))
    })
    .ok()
    .flatten()
}

#[derive(Clone, Copy)]
pub struct VxlanSpec<'a> {
    pub dev: &'a str,
    pub vni: u32,
    pub dstport: u16,
    pub remote: Option<IpAddr>,
    pub underlay_dev: &'a str,
    /// Address with prefix, e.g. 10.255.255.2/30.
    pub local_addr: &'a str,
    pub mtu: u32,
}

fn add_vxlan(spec: &VxlanSpec<'_>) -> Result<()> {
    let underlay = ifindex(spec.underlay_dev)?;
    let remote = spec.remote;
    run_netlink(async move {
        let (connection, handle, _) = new_connection().context("opening rtnetlink connection")?;
        tokio::spawn(connection);
        let mut request = LinkVxlan::new(spec.dev, spec.vni)
            .dev(underlay)
            .port(spec.dstport);
        if let Some(remote) = remote {
            request = match remote {
                IpAddr::V4(ip) => request.remote(ip),
                IpAddr::V6(ip) => request.remote6(ip),
            };
        }
        handle
            .link()
            .add(request.build())
            .execute()
            .await
            .map_err(|error| anyhow::anyhow!(error))
            .with_context(|| format!("creating VXLAN {}", spec.dev))
    })
}

pub fn delete_link(dev: &str) -> Result<()> {
    let index = ifindex(dev)?;
    run_netlink(async move {
        let (connection, handle, _) = new_connection().context("opening rtnetlink connection")?;
        tokio::spawn(connection);
        handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(|error| anyhow::anyhow!(error))
            .with_context(|| format!("deleting link {dev}"))
    })
}

pub fn set_link(dev: &str, mtu: u32, up: bool) -> Result<()> {
    let index = ifindex(dev)?;
    run_netlink(async move {
        let (connection, handle, _) = new_connection().context("opening rtnetlink connection")?;
        tokio::spawn(connection);
        let request = LinkUnspec::new_with_index(index).mtu(mtu);
        let request = if up { request.up() } else { request.down() };
        handle
            .link()
            .set(request.build())
            .execute()
            .await
            .map_err(|error| anyhow::anyhow!(error))
            .with_context(|| format!("setting link {dev}"))
    })
}

/// Create the VXLAN device if missing, or verify/amend its parameters.
/// Returns true when the device was (re)created.
///
/// Kernel quirk: `remote`/`dstport` of an existing vxlan can only be changed
/// while recreating on older kernels, so a parameter mismatch falls back to
/// delete + recreate.
pub fn ensure_vxlan(spec: &VxlanSpec<'_>) -> Result<bool> {
    let n = &spec;
    let mut created = false;
    if !link_exists(n.dev) {
        add_vxlan(n)?;
        created = true;
    } else {
        let state = link_state(n.dev).context("reading existing VXLAN state")?;
        let drifted = state.vxlan_id != Some(n.vni)
            || state.remote != n.remote
            || state.vxlan_port != Some(n.dstport);
        if drifted {
            delete_link(n.dev)?;
            return ensure_vxlan(spec).map(|_| true);
        }
    }
    // Address and link state for both the fresh and preexisting cases.
    ensure_local_addr(n.dev, n.local_addr)?;
    set_link(n.dev, n.mtu, true)?;
    Ok(created)
}

/// Create or reuse a multipoint VXLAN device and keep all requested local
/// overlay addresses on it.
pub fn ensure_vxlan_multipoint(
    spec: &VxlanSpec<'_>,
    local_addrs: &[String],
    peers: &[IpAddr],
) -> Result<bool> {
    let multi = VxlanSpec {
        remote: None,
        ..*spec
    };
    let created = ensure_vxlan_without_addresses(&multi)?;
    ensure_local_addrs(multi.dev, local_addrs)?;
    set_link(multi.dev, multi.mtu, true)?;
    sync_vxlan_peers(multi.dev, peers)?;
    Ok(created)
}

fn ensure_vxlan_without_addresses(spec: &VxlanSpec<'_>) -> Result<bool> {
    let n = &spec;
    let mut created = false;
    if !link_exists(n.dev) {
        add_vxlan(n)?;
        created = true;
    } else {
        let state = link_state(n.dev).context("reading existing VXLAN state")?;
        let drifted = state.vxlan_id != Some(n.vni)
            || state.remote != n.remote
            || state.vxlan_port != Some(n.dstport);
        if drifted {
            delete_link(n.dev)?;
            return ensure_vxlan_without_addresses(spec).map(|_| true);
        }
    }
    Ok(created)
}

fn ensure_local_addr(dev: &str, local_addr: &str) -> Result<()> {
    ensure_local_addrs(dev, &[local_addr.to_string()])
}

pub fn ensure_local_addrs(dev: &str, local_addrs: &[String]) -> Result<()> {
    if local_addrs.is_empty() {
        return Ok(());
    }
    let mut desired = local_addrs.to_vec();
    desired.sort();
    desired.dedup();
    let index = ifindex(dev)?;
    run_netlink(async move {
        let (connection, handle, _) = new_connection().context("opening rtnetlink connection")?;
        tokio::spawn(connection);
        let mut addresses = handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute();
        let mut existing = Vec::new();
        while let Some(address) = addresses
            .try_next()
            .await
            .context("dumping interface addresses")?
        {
            let ip = address
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    rtnetlink::packet_route::address::AddressAttribute::Local(ip)
                    | rtnetlink::packet_route::address::AddressAttribute::Address(ip) => Some(*ip),
                    _ => None,
                });
            if let Some(ip) = ip {
                existing.push((ip, address));
            }
        }
        for (ip, address) in existing {
            let keep = desired.iter().any(|value| {
                value
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .is_some_and(|wanted| wanted == ip)
                    && value
                        .split_once('/')
                        .and_then(|(_, prefix)| prefix.parse::<u8>().ok())
                        == Some(address.header.prefix_len)
            });
            if !keep {
                handle
                    .address()
                    .del(address)
                    .execute()
                    .await
                    .with_context(|| format!("removing stale {ip} from {dev}"))?;
            }
        }
        for value in desired {
            let (ip, prefix) = value
                .split_once('/')
                .ok_or_else(|| anyhow::anyhow!("address must include prefix: {value}"))?;
            let ip = ip
                .parse::<std::net::IpAddr>()
                .with_context(|| format!("invalid address {value}"))?;
            let prefix = prefix
                .parse::<u8>()
                .with_context(|| format!("invalid prefix in {value}"))?;
            handle
                .address()
                .add(index, ip, prefix)
                .execute()
                .await
                .with_context(|| format!("setting {value} on {dev}"))?;
        }
        Ok(())
    })
}

pub(super) fn run_netlink<F, T>(future: F) -> Result<T>
where
    F: Future<Output = Result<T>> + Send,
    T: Send,
{
    let run = move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context("creating rtnetlink runtime")?
            .block_on(future)
    };

    // Some reconciliation paths are called by the tonic/Tokio xDS server.
    // Blocking that runtime with a nested `block_on` panics. Run the small
    // synchronous rtnetlink transaction on a scoped OS thread in that case.
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::scope(|scope| {
            scope
                .spawn(run)
                .join()
                .map_err(|_| anyhow::anyhow!("rtnetlink worker thread panicked"))?
        })
    } else {
        run()
    }
}

/// Repoint an existing vxlan at a new remote without recreating it; falls
/// back to recreation when the kernel refuses the in-place change.
pub fn set_vxlan_remote(spec: &VxlanSpec<'_>, new_remote: IpAddr) -> Result<()> {
    if !link_exists(spec.dev) {
        ensure_vxlan(spec)?;
        return Ok(());
    }
    let changed = set_vxlan_remote_netlink(spec.dev, new_remote).is_ok()
        && vxlan_remote(spec.dev) == Some(new_remote);
    if !changed {
        delete_link(spec.dev).ok();
        ensure_vxlan(spec)?;
    }
    Ok(())
}

fn set_vxlan_remote_netlink(dev: &str, remote: IpAddr) -> Result<()> {
    let index = ifindex(dev)?;
    run_netlink(async move {
        let (connection, handle, _) = new_connection().context("opening rtnetlink connection")?;
        tokio::spawn(connection);
        let request = LinkUnspec::new_with_index(index);
        let request = match remote {
            IpAddr::V4(ip) => request.append_extra_attribute(
                rtnetlink::packet_route::link::LinkAttribute::LinkInfo(vec![
                    rtnetlink::packet_route::link::LinkInfo::Data(
                        rtnetlink::packet_route::link::InfoData::Vxlan(vec![
                            rtnetlink::packet_route::link::InfoVxlan::Group(ip),
                        ]),
                    ),
                ]),
            ),
            IpAddr::V6(ip) => request.append_extra_attribute(
                rtnetlink::packet_route::link::LinkAttribute::LinkInfo(vec![
                    rtnetlink::packet_route::link::LinkInfo::Data(
                        rtnetlink::packet_route::link::InfoData::Vxlan(vec![
                            rtnetlink::packet_route::link::InfoVxlan::Group6(ip),
                        ]),
                    ),
                ]),
            ),
        };
        handle
            .link()
            .set(request.build())
            .execute()
            .await
            .map_err(|error| anyhow::anyhow!(error))
            .with_context(|| format!("setting VXLAN remote for {dev}"))
    })
}

/// Ensure a multipoint VXLAN can flood unknown traffic to every backend
/// underlay. Existing learned MAC entries are left intact.
pub fn sync_vxlan_peers(dev: &str, peers: &[IpAddr]) -> Result<()> {
    let index = ifindex(dev)?;
    let peers = peers.to_vec();
    run_netlink(async move {
        let (connection, mut handle, _) =
            new_connection().context("opening rtnetlink connection")?;
        tokio::spawn(connection);
        for peer in peers {
            let result = append_vxlan_fdb(&mut handle, index, peer).await;
            if let Err(error) = result
                && !error.to_string().contains("File exists")
            {
                return Err(anyhow::anyhow!(error))
                    .with_context(|| format!("adding VXLAN peer {peer} on {dev}"));
            }
        }
        Ok(())
    })
}

async fn append_vxlan_fdb(
    handle: &mut rtnetlink::Handle,
    index: u32,
    peer: IpAddr,
) -> Result<(), rtnetlink::Error> {
    let mut message = NeighbourMessage::default();
    message.header.family = AddressFamily::Bridge;
    message.header.ifindex = index;
    // `bridge fdb append` emits NUD_NOARP|NUD_PERMANENT for VXLAN flood
    // entries. Some kernels reject a permanent-only bridge neighbour with
    // EOPNOTSUPP even though the CLI form succeeds.
    message.header.state = NeighbourState::Other(0xc0);
    message.header.kind = RouteType::Unspec;
    message.header.flags = NeighbourFlags::Own;
    message
        .attributes
        .push(NeighbourAttribute::LinkLocalAddress(vec![0, 0, 0, 0, 0, 0]));
    message
        .attributes
        .push(NeighbourAttribute::Destination(match peer {
            IpAddr::V4(ip) => NeighbourAddress::Inet(ip),
            IpAddr::V6(ip) => NeighbourAddress::Inet6(ip),
        }));
    let mut request = NetlinkMessage::from(RouteNetlinkMessage::NewNeighbour(message));
    request.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND;
    let mut responses = handle.request(request)?;
    while let Some(response) = responses.next().await {
        if let NetlinkPayload::Error(error) = response.payload {
            return Err(rtnetlink::Error::NetlinkError(error));
        }
    }
    Ok(())
}
