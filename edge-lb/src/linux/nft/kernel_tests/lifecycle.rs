//! Reconcile and withdrawal preserve conntrack without stale tuple-learning sets.

use super::*;

pub(super) fn no_reply(client: &UdpSocket) {
    client
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let error = client
        .recv_from(&mut [0; 128])
        .expect_err("unexpected reply");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    client.set_read_timeout(Some(TIMEOUT)).unwrap();
}

fn ordinary_reply(server: &UdpSocket, client: &UdpSocket, topology: &Topology, source: SocketAddr) {
    let before = topology.peers.each_ref().map(Peer::received);
    reply(server, client, source, "198.18.0.2:8080".parse().unwrap());
    assert_eq!(
        topology.peers.each_ref().map(Peer::received),
        before,
        "unclassified reply uses the fixture's main underlay route"
    );
}

#[test]
fn unknown_dscp_is_not_steered_and_reapply_keeps_tcp_and_udp_conntrack() {
    std::thread::spawn(|| {
        let topology = Topology::new();
        let server = udp("0.0.0.0:8080");
        let peer = &topology.peers[0];
        for (port, codepoint) in [(40001, 7), (40002, 0)] {
            let unknown = client(peer, port, codepoint);
            let source = request(&unknown, &server, destination(peer, 8080), b"unclassified");
            ordinary_reply(&server, &unknown, &topology, source);
        }
        let known = client(peer, 40000, 46);
        let source = request(&known, &server, destination(peer, 8080), b"classified");
        let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
        let mut stream = tcp(peer, &listener);
        tcp_exchange(&mut stream);
        topology.apply();
        let before = peer.received();
        // No new UDP request after replacing the ruleset.
        reply(&server, &known, source, destination(peer, 8080));
        assert!(peer.received() > before);
        tcp_exchange(&mut stream);
    })
    .join()
    .unwrap();
}

#[test]
fn withdrawing_contract_stops_restoring_its_mark_without_rewriting_source() {
    std::thread::spawn(|| {
        let mut topology = Topology::new();
        let server = udp("0.0.0.0:8080");
        let a = client(&topology.peers[0], 40000, 46);
        let b = client(&topology.peers[1], 40001, 40);
        let ordinary_b = client(&topology.peers[0], 40001, 7);
        for (slot, client) in [&a, &b].iter().enumerate() {
            let to = destination(&topology.peers[slot], 8080);
            let source = request(client, &server, to, b"before withdrawal");
            reply(&server, client, source, to);
        }
        topology.cfg.file.backend_return_paths = vec![topology.peers[1].path.clone()];
        topology.apply();
        ordinary_reply(&server, &a, &topology, a.local_addr().unwrap());
        reply(
            &server,
            &b,
            b.local_addr().unwrap(),
            destination(&topology.peers[1], 8080),
        );
        topology.cfg.file.backend_return_paths.clear();
        topology.apply();
        ordinary_reply(&server, &ordinary_b, &topology, b.local_addr().unwrap());
        no_reply(&b);
    })
    .join()
    .unwrap();
}

#[test]
fn invalid_contract_reconcile_leaves_existing_kernel_rules_intact() {
    std::thread::spawn(|| {
        let mut topology = Topology::new();
        let server = udp("0.0.0.0:8080");
        let b = client(&topology.peers[1], 40000, 40);
        topology.cfg.file.backend_return_paths[1].dscp = 46;
        assert!(crate::linux::nftables::apply_return_path(&topology.cfg).is_err());
        let to = destination(&topology.peers[1], 8080);
        let source = request(&b, &server, to, b"old contract still active");
        let before = topology.peers[1].received();
        reply(&server, &b, source, to);
        assert!(topology.peers[1].received() > before);
    })
    .join()
    .unwrap();
}
