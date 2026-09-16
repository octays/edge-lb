//! Two gateway peers and one host-network backend, with real VXLAN and nft.

use crate::{
    config::{Config, FileConfig, GatewayReturnPath, NetworkConfig, return_mark, return_table_id},
    linux::test_support::{self as net, Namespace, private_namespace},
};

pub(super) struct Peer {
    pub ns: Namespace,
    pub path: GatewayReturnPath,
}

impl Peer {
    pub fn received(&self) -> u64 {
        self.ns.run(|| net::received("edge-hub"))
    }
}

pub(super) struct Topology {
    pub peers: [Peer; 2],
    pub cfg: Config,
}

fn address(dev: &str, ip_cidr: &str, mac: &str) {
    net::set_link(net::link(dev).address(net::mac(mac)).up());
    net::address(dev, ip_cidr);
}

impl Topology {
    pub fn new() -> Self {
        private_namespace(false);
        net::bridge("underlay0");
        address("underlay0", "198.18.0.2/24", "02:00:00:00:00:02");
        net::vxlan("edge-return", "underlay0", "198.18.0.2", None);
        address("edge-return", "192.0.2.2/24", "02:00:00:00:02:02");
        net::address("edge-return", "192.0.3.2/24");
        net::set_link(net::link("edge-return").mtu(1450));
        net::add_route(net::route("0.0.0.0/0", "underlay0", Some("198.18.0.1")));
        for dev in ["all", "default", "underlay0", "edge-return"] {
            std::fs::write(format!("/proc/sys/net/ipv4/conf/{dev}/rp_filter"), "0").unwrap();
        }
        let peers = [
            (0, "198.18.0.1", "192.0.2.1", "192.0.2.2/24", 46),
            (1, "198.18.0.3", "192.0.3.1", "192.0.3.2/24", 40),
        ]
        .map(|(slot, underlay, overlay, backend, dscp)| {
            let ns = Namespace::new();
            let dev = format!("peer{slot}");
            net::veth(&dev, "uplink");
            net::move_link("uplink", ns.tid);
            net::set_link(net::link(&dev).controller(net::index("underlay0")));
            net::set_link(net::link(&dev).up());
            let mac = format!("02:00:00:00:01:{:02x}", slot + 1);
            let peer_mac = mac.clone();
            ns.run(move || {
                address(
                    "uplink",
                    &format!("{underlay}/24"),
                    &format!("02:00:00:00:00:{:02x}", slot + 10),
                );
                net::vxlan("edge-hub", "uplink", underlay, Some("198.18.0.2"));
                address("edge-hub", &format!("{overlay}/24"), &peer_mac);
                net::set_link(net::link("edge-hub").mtu(1450));
                net::address("lo", "198.51.100.2/32");
                net::neighbor(
                    "edge-hub",
                    backend.split('/').next().unwrap(),
                    "02:00:00:00:02:02",
                    rtnetlink::packet_route::neighbour::NeighbourState::Permanent,
                );
                for dev in ["all", "default", "uplink", "edge-hub"] {
                    std::fs::write(format!("/proc/sys/net/ipv4/conf/{dev}/rp_filter"), "0")
                        .unwrap();
                }
            });
            net::fdb("edge-return", &mac, underlay);
            net::neighbor(
                "edge-return",
                overlay,
                &mac,
                rtnetlink::packet_route::neighbour::NeighbourState::Permanent,
            );
            let mark = return_mark(dscp, slot);
            let table = return_table_id(dscp, slot);
            // Explicit fixture routes avoid the process-global ownership database.
            net::rule(100 + slot, mark, table, None);
            net::add_route(
                net::route("0.0.0.0/0", "edge-return", Some(overlay))
                    .table_id(table)
                    .onlink(),
            );
            for gw in ["198.18.0.1/32", "198.18.0.3/32"] {
                net::add_route(net::route(gw, "underlay0", None).table_id(table));
            }
            Peer {
                ns,
                path: GatewayReturnPath {
                    gateway: Some(format!("gateway-{slot}")),
                    gateway_underlay_ip: underlay.parse().unwrap(),
                    gateway_overlay_ip: overlay.parse().unwrap(),
                    backend_overlay_ip: Some(backend.into()),
                    dscp,
                    mark,
                    route_table_id: table,
                },
            }
        });
        let cfg = Config {
            path: "/unused/test.toml".into(),
            file: FileConfig {
                network: NetworkConfig {
                    vxlan_dev: "edge-return".into(),
                    ..Default::default()
                },
                backend_return_paths: peers.iter().map(|peer| peer.path.clone()).collect(),
                ..Default::default()
            },
        };
        let this = Self { peers, cfg };
        this.apply();
        this
    }

    pub fn apply(&self) {
        crate::linux::nftables::apply_return_path(&self.cfg).unwrap();
    }
}
