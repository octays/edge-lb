//! Shared writer/revision guards apply to both maps, including ABI failures.

use super::{
    maps,
    test_support::{PrivateBpffs, load_bpf, private_namespace},
};
use aya::maps::HashMap;
use edge_lb_common::{
    NATIVE_LISTENERS_MAP, NATIVE_TARGETS_MAP, NativeTargetKey,
    redirect::{NATIVE_LOCAL_ADDRS_MAP, NATIVE_TARGET_ROUTES_MAP, NativeTargetRoute},
    return_redirect::{NATIVE_RETURN_LEASES_MAP, ReturnLease, ReturnLeaseKey},
};

#[test]
fn return_publication_is_fenced_by_both_map_ids_and_cleared_on_errors() {
    std::thread::spawn(|| {
        private_namespace(true);
        let fs = PrivateBpffs::new();
        let bpf = load_bpf();
        for name in [
            NATIVE_LISTENERS_MAP,
            NATIVE_TARGETS_MAP,
            NATIVE_LOCAL_ADDRS_MAP,
            NATIVE_TARGET_ROUTES_MAP,
            NATIVE_RETURN_LEASES_MAP,
        ] {
            bpf.map(name).unwrap().pin(fs.0.join(name)).unwrap();
        }
        let pin = fs.0.join(NATIVE_TARGET_ROUTES_MAP);
        let returns = [(
            ReturnLeaseKey {
                ingress_ifindex: 7,
                ifindex: 2,
                source: 0xc000020a,
            },
            ReturnLease { expires_ns: 100 },
        )];
        let routes = [(
            NativeTargetKey {
                listener_id: 1,
                target_id: 0,
            },
            NativeTargetRoute {
                expires_ns: 100,
                ..Default::default()
            },
        )];
        let clear = || {
            assert_eq!(
                HashMap::<_, ReturnLeaseKey, ReturnLease>::try_from(
                    bpf.map(NATIVE_RETURN_LEASES_MAP).unwrap()
                )
                .unwrap()
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
                0
            );
            assert_eq!(
                HashMap::<_, NativeTargetKey, NativeTargetRoute>::try_from(
                    bpf.map(NATIVE_TARGET_ROUTES_MAP).unwrap()
                )
                .unwrap()
                .keys()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
                .len(),
                0
            );
        };
        let (token, _) = maps::snapshot(&pin).unwrap();
        assert!(maps::publish(&pin, token, &routes, &returns, &[], 50).unwrap());
        assert!(!maps::publish(&pin, token, &routes, &returns, &[], 50).unwrap());
        let (token, _) = maps::snapshot(&pin).unwrap();
        {
            let _guard = maps::begin_mutation(&pin).unwrap();
        }
        clear();
        assert!(!maps::publish(&pin, token, &routes, &returns, &[], 50).unwrap());
        let (token, _) = maps::snapshot(&pin).unwrap();
        assert!(!maps::publish(&pin, token, &routes, &returns, &[], 100).unwrap());
        clear();
        let (token, _) = maps::snapshot(&pin).unwrap();
        assert!(maps::publish(&pin, token, &routes, &returns, &[], 50).unwrap());
        let (token, _) = maps::snapshot(&pin).unwrap();
        std::fs::remove_file(fs.0.join(NATIVE_LOCAL_ADDRS_MAP)).unwrap();
        assert!(maps::publish(&pin, token, &routes, &returns, &[], 50).is_err());
        clear();
        bpf.map(NATIVE_LOCAL_ADDRS_MAP)
            .unwrap()
            .pin(fs.0.join(NATIVE_LOCAL_ADDRS_MAP))
            .unwrap();
        let (token, _) = maps::snapshot(&pin).unwrap();
        let replacement = load_bpf();
        std::fs::remove_file(fs.0.join(NATIVE_RETURN_LEASES_MAP)).unwrap();
        replacement
            .map(NATIVE_RETURN_LEASES_MAP)
            .unwrap()
            .pin(fs.0.join(NATIVE_RETURN_LEASES_MAP))
            .unwrap();
        assert!(!maps::publish(&pin, token, &routes, &returns, &[], 50).unwrap());
        clear();
    })
    .join()
    .unwrap();
}
