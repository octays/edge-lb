//! Default-route ("underlay device") detection.
//!
//! Linux: `/proc/net/route`, the 00000000 destination with the lowest metric.
//! Other platforms: best-effort interface scan. This helper intentionally avoids
//! shelling out to `ip`, `route`, or similar host commands.

/// Name of the device holding the default route, if it can be determined.
pub fn default_interface() -> Option<String> {
    default_interface_impl()
}

#[cfg(target_os = "linux")]
fn default_interface_impl() -> Option<String> {
    parse_linux_proc_net_route(&std::fs::read_to_string("/proc/net/route").ok()?)
}

#[cfg(target_os = "macos")]
fn default_interface_impl() -> Option<String> {
    first_non_loopback_ipv4_interface()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn default_interface_impl() -> Option<String> {
    first_non_loopback_ipv4_interface()
}

/// Parse `/proc/net/route` contents; return the default-route interface.
///
/// Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
#[cfg(any(test, target_os = "linux"))]
pub fn parse_linux_proc_net_route(data: &str) -> Option<String> {
    let mut best: Option<(u32, String)> = None;
    for line in data.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        if f[1] != "00000000" {
            continue; // not the default destination
        }
        let Ok(metric) = f[6].parse::<u32>() else {
            continue;
        };
        match &best {
            Some((m, _)) if *m <= metric => {}
            _ => best = Some((metric, f[0].to_string())),
        }
    }
    best.map(|(_, name)| name)
}

#[cfg(not(target_os = "linux"))]
fn first_non_loopback_ipv4_interface() -> Option<String> {
    crate::system::ifaddr::list()
        .into_iter()
        .find(|addr| {
            !addr.is_loopback && matches!(addr.ip, std::net::IpAddr::V4(ip) if !ip.is_unspecified())
        })
        .map(|addr| addr.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_route_prefers_lowest_metric_default() {
        let data = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
enp3s0\t00000000\t0104010A\t0003\t0\t0\t100\t00000000\t0\t0\t0
wlan0\t00000000\t0104010A\t0003\t0\t0\t600\t00000000\t0\t0\t0
docker0\t0000AC1A\t00000000\t0001\t0\t0\t0\tFFFF0000\t0\t0\t0
enp3s0\t000010AC\t00000000\t0001\t0\t0\t0\tFFFF0000\t0\t0\t0
";
        assert_eq!(parse_linux_proc_net_route(data), Some("enp3s0".to_string()));

        let data2 = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
wlan0\t00000000\t0104010A\t0003\t0\t0\t600\t00000000\t0\t0\t0
enp3s0\t00000000\t0104010A\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        assert_eq!(
            parse_linux_proc_net_route(data2),
            Some("enp3s0".to_string())
        );

        let none = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
docker0\t0000AC1A\t00000000\t0001\t0\t0\t0\tFFFF0000\t0\t0\t0
";
        assert_eq!(parse_linux_proc_net_route(none), None);
    }

    #[test]
    fn linux_route_metric_is_decimal() {
        let data = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
eth9\t00000000\t0104010A\t0003\t0\t0\t0x10\t00000000\t0\t0\t0
eth0\t00000000\t0104010A\t0003\t0\t0\t20\t00000000\t0\t0\t0
";
        assert_eq!(parse_linux_proc_net_route(data), Some("eth0".to_string()));
    }
}
