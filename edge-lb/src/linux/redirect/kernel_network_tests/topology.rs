//! Private namespace peers, connected only to the calling private gateway.

use crate::linux::test_support::{self as net, Namespace};
use rtnetlink::packet_route::neighbour::NeighbourState;

pub(super) struct Topology {
    pub client: Namespace,
    pub backend: Namespace,
}

fn address(dev: &str, address: &str, mac: &str, mtu: u32) {
    net::set_link(net::link(dev).address(net::mac(mac)).mtu(mtu).up());
    net::address(dev, address);
}

fn tunnel(dev: &str, local: &str, remote: &str, address_ip: &str, mac: &str) {
    net::vxlan(dev, "underlay0", local, Some(remote));
    address(dev, address_ip, mac, 1450);
}

pub(super) fn gateway_neighbor() {
    net::neighbor(
        "edge-hub",
        "192.0.2.2",
        "02:00:00:00:00:02",
        NeighbourState::Permanent,
    );
}

impl Topology {
    pub(super) fn diagnose(&self) {
        net::diagnose("gateway");
        self.client.run(|| net::diagnose("client"));
        self.backend.run(|| net::diagnose("backend"));
    }

    pub(super) fn new() -> Self {
        net::private_namespace(true);
        let client = Namespace::new();
        let backend = Namespace::new();
        net::veth("ingress0", "client0");
        net::move_link("client0", client.tid);
        net::veth("underlay0", "backend0");
        net::move_link("backend0", backend.tid);
        address("ingress0", "198.51.100.1/24", "02:00:00:00:00:21", 9000);
        address("underlay0", "198.18.0.1/30", "02:00:00:00:00:11", 1500);
        net::address("lo", "203.0.113.100/32");
        tunnel(
            "edge-hub",
            "198.18.0.1",
            "198.18.0.2",
            "192.0.2.1/24",
            "02:00:00:00:00:01",
        );
        gateway_neighbor();
        net::add_route(net::route("203.0.113.20/32", "edge-hub", Some("192.0.2.2")));
        crate::linux::sysctl::ensure_ipv4_forwarding().unwrap();
        // Reverse DNAT emits this gateway's own VIP.
        crate::linux::net::set_accept_local("edge-hub", true).unwrap();
        for dev in ["all", "default", "ingress0", "underlay0", "edge-hub"] {
            std::fs::write(format!("/proc/sys/net/ipv4/conf/{dev}/rp_filter"), "0").unwrap();
        }
        client.run(|| {
            address("client0", "198.51.100.2/24", "02:00:00:00:00:22", 9000);
            net::add_route(net::route(
                "203.0.113.100/32",
                "client0",
                Some("198.51.100.1"),
            ));
        });
        backend.run(|| {
            net::set_link(net::link("backend0").name("underlay0".into()));
            address("underlay0", "198.18.0.2/30", "02:00:00:00:00:12", 1500);
            tunnel(
                "edge-back",
                "198.18.0.2",
                "198.18.0.1",
                "192.0.2.2/24",
                "02:00:00:00:00:02",
            );
            net::address("lo", "203.0.113.20/32");
            net::neighbor(
                "edge-back",
                "192.0.2.1",
                "02:00:00:00:00:01",
                NeighbourState::Permanent,
            );
            net::add_route(net::route(
                "198.51.100.0/24",
                "edge-back",
                Some("192.0.2.1"),
            ));
            for dev in ["all", "default", "underlay0", "edge-back"] {
                std::fs::write(format!("/proc/sys/net/ipv4/conf/{dev}/rp_filter"), "0").unwrap();
            }
        });
        Self { client, backend }
    }
}
