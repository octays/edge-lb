use std::{collections::HashMap, fs};

use crate::config::{Config, NodeRole};

pub fn render_gateway(cfg: &Config) -> String {
    let mut out = String::new();
    metric_line(
        &mut out,
        "edge_lb_node_info",
        &[("role", "gateway"), ("node", cfg.node_name.as_str())],
        1,
        Some("gauge"),
    );
    metric_line(
        &mut out,
        "edge_lb_build_info",
        &[("version", env!("CARGO_PKG_VERSION"))],
        1,
        Some("gauge"),
    );
    metric_line(
        &mut out,
        "edge_lb_underlay_info",
        &[
            ("dev", cfg.network().underlay_dev.as_str()),
            ("underlay", &cfg.underlay_ip.to_string()),
        ],
        1,
        Some("gauge"),
    );
    render_process_metrics(&mut out);
    render_host_metrics(&mut out);

    if !matches!(cfg.node_role, NodeRole::Gateway) {
        return out;
    }

    let n = cfg.network();
    metric_line(
        &mut out,
        "edge_lb_gateway_dscp_attached",
        &[],
        bool_value(crate::linux::dscp::attached(cfg, &n.underlay_dev)),
        Some("gauge"),
    );
    metric_line(
        &mut out,
        "edge_lb_gateway_native_datapath_attached",
        &[],
        bool_value(crate::linux::native_dnat::attached(cfg)),
        Some("gauge"),
    );
    metric_line(
        &mut out,
        "edge_lb_gateway_native_flow_map_capacity",
        &[],
        edge_lb_common::NATIVE_FLOW_MAP_CAPACITY as u64,
        Some("gauge"),
    );
    metric_line(
        &mut out,
        "edge_lb_gateway_native_flow_pair_capacity",
        &[],
        edge_lb_common::NATIVE_FLOW_PAIR_CAPACITY as u64,
        Some("gauge"),
    );

    if let Ok(stats) = crate::linux::dscp::stats(cfg) {
        metric_line(
            &mut out,
            "edge_lb_gateway_dscp_packets_matched_total",
            &[],
            stats.matched,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_dscp_packets_changed_total",
            &[],
            stats.changed,
            Some("counter"),
        );
    }

    if let Ok(stats) = crate::linux::native_dnat::stats(cfg) {
        metric_line(
            &mut out,
            "edge_lb_gateway_native_listener_hit_total",
            &[],
            stats.listener_hit,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_native_listener_miss_total",
            &[],
            stats.listener_miss,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_native_target_miss_total",
            &[],
            stats.target_miss,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_native_return_miss_total",
            &[],
            stats.return_miss,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_native_rewritten_total",
            &[],
            stats.rewritten,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_native_checksum_error_total",
            &[],
            stats.checksum_error,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_native_consistent_hash_bucket_hit_total",
            &[],
            stats.chash_bucket_hit,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_native_consistent_hash_bucket_miss_total",
            &[],
            stats.chash_bucket_miss,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_native_consistent_hash_bucket_unusable_total",
            &[],
            stats.chash_bucket_unusable,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_native_consistent_hash_fallback_total",
            &[],
            stats.chash_fallback,
            Some("counter"),
        );
        metric_line(
            &mut out,
            "edge_lb_gateway_native_flow_event_lost_total",
            &[],
            stats.flow_event_lost,
            Some("counter"),
        );
    }

    render_redirect_metrics(
        &mut out,
        crate::linux::native_dnat::redirect_stats(cfg).ok(),
    );
    render_return_redirect_metrics(
        &mut out,
        crate::linux::native_dnat::return_redirect_stats(cfg).ok(),
    );

    if let Ok(digests) = crate::linux::native_dnat::consistent_hash_bucket_digests(cfg) {
        for digest in digests {
            let listener_id = digest.listener_id.to_string();
            let port = digest.port.to_string();
            let bucket_count = digest.bucket_count.to_string();
            metric_line(
                &mut out,
                "edge_lb_gateway_native_consistent_hash_bucket_table_info",
                &[
                    ("listener", digest.listener_name.as_str()),
                    ("listener_id", listener_id.as_str()),
                    ("vip", digest.vip.as_str()),
                    ("port", port.as_str()),
                    ("protocol", digest.protocol),
                    ("bucket_count", bucket_count.as_str()),
                    ("digest", digest.digest.as_str()),
                ],
                1,
                Some("gauge"),
            );
        }
    }

    render_flow_persistence_metrics(&mut out);

    out
}

fn render_flow_persistence_metrics(out: &mut String) {
    let status = crate::provider::native::flow_persistence::status();
    metric_line(
        out,
        "edge_lb_gateway_native_flow_persistence_enabled",
        &[],
        bool_value(status.enabled),
        Some("gauge"),
    );
    metric_line(
        out,
        "edge_lb_gateway_native_flow_snapshot_records",
        &[],
        status.snapshot_records as u64,
        Some("gauge"),
    );
    metric_line(
        out,
        "edge_lb_gateway_native_flow_snapshot_bytes",
        &[],
        status.snapshot_bytes,
        Some("gauge"),
    );
    metric_float_line(
        out,
        "edge_lb_gateway_native_flow_snapshot_duration_seconds",
        &[],
        status.snapshot_duration_ms as f64 / 1000.0,
        Some("gauge"),
    );
    metric_line(
        out,
        "edge_lb_gateway_native_flow_snapshot_errors_total",
        &[],
        status.snapshot_errors_total,
        Some("counter"),
    );
    metric_line(
        out,
        "edge_lb_gateway_native_flow_restore_records_total",
        &[],
        status.restore_records_total,
        Some("counter"),
    );
    metric_line(
        out,
        "edge_lb_gateway_native_flow_restore_skipped_total",
        &[("reason", "expired")],
        status.restore_skipped_expired_total,
        Some("counter"),
    );
    metric_line(
        out,
        "edge_lb_gateway_native_flow_restore_skipped_total",
        &[("reason", "config")],
        status.restore_skipped_config_total,
        None,
    );
    metric_line(
        out,
        "edge_lb_gateway_native_flow_restore_skipped_total",
        &[("reason", "incomplete")],
        status.restore_skipped_incomplete_total,
        None,
    );
    metric_float_line(
        out,
        "edge_lb_gateway_native_flow_restore_duration_seconds",
        &[],
        status.restore_duration_ms as f64 / 1000.0,
        Some("gauge"),
    );
    metric_line(
        out,
        "edge_lb_gateway_native_flow_restore_errors_total",
        &[],
        status.restore_errors_total,
        Some("counter"),
    );
}

fn bool_value(value: bool) -> u64 {
    if value { 1 } else { 0 }
}

fn render_redirect_metrics(
    out: &mut String,
    stats: Option<edge_lb_common::redirect::NativeRedirectStats>,
) {
    metric_line(
        out,
        "edge_lb_gateway_native_redirect_stats_available",
        &[],
        u64::from(stats.is_some()),
        Some("gauge"),
    );
    let Some(stats) = stats else {
        return;
    };
    metric_line(
        out,
        "edge_lb_gateway_native_redirect_submitted_total",
        &[],
        stats.submitted,
        Some("counter"),
    );
    metric_line(
        out,
        "edge_lb_gateway_native_redirect_mutation_error_total",
        &[],
        stats.mutation_error,
        Some("counter"),
    );
    for (index, (reason, value)) in [
        ("route_miss", stats.route_miss),
        ("route_invalid", stats.route_invalid),
        ("expired", stats.expired),
        ("target_changed", stats.target_changed),
        ("ttl", stats.ttl),
        ("mtu", stats.mtu),
        ("unsupported", stats.unsupported),
    ]
    .into_iter()
    .enumerate()
    {
        metric_line(
            out,
            "edge_lb_gateway_native_redirect_fallback_total",
            &[("reason", reason)],
            value,
            (index == 0).then_some("counter"),
        );
    }
}

fn render_return_redirect_metrics(
    out: &mut String,
    stats: Option<edge_lb_common::return_redirect::ReturnRedirectStats>,
) {
    metric_line(
        out,
        "edge_lb_gateway_native_return_redirect_stats_available",
        &[],
        u64::from(stats.is_some()),
        Some("gauge"),
    );
    let Some(stats) = stats else {
        return;
    };
    metric_line(
        out,
        "edge_lb_gateway_native_return_redirect_submitted_total",
        &[],
        stats.submitted,
        Some("counter"),
    );
    metric_line(
        out,
        "edge_lb_gateway_native_return_redirect_mutation_error_total",
        &[],
        stats.mutation_error,
        Some("counter"),
    );
    for (index, (reason, value)) in [
        ("policy", stats.policy),
        ("expired", stats.expired),
        ("route", stats.route),
        ("neighbor", stats.neighbor),
        ("ttl", stats.ttl),
        ("mtu", stats.mtu),
        ("unsupported", stats.unsupported),
    ]
    .into_iter()
    .enumerate()
    {
        metric_line(
            out,
            "edge_lb_gateway_native_return_redirect_fallback_total",
            &[("reason", reason)],
            value,
            (index == 0).then_some("counter"),
        );
    }
}

fn metric_line(
    out: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    value: u64,
    metric_type: Option<&str>,
) {
    metric_value_line(out, name, labels, &value.to_string(), metric_type);
}

fn metric_float_line(
    out: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    value: f64,
    metric_type: Option<&str>,
) {
    if value.is_finite() {
        metric_value_line(out, name, labels, &format!("{value:.6}"), metric_type);
    }
}

fn metric_value_line(
    out: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    value: &str,
    metric_type: Option<&str>,
) {
    if let Some(metric_type) = metric_type {
        out.push_str("# TYPE ");
        out.push_str(name);
        out.push(' ');
        out.push_str(metric_type);
        out.push('\n');
    }
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (idx, (key, value)) in labels.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push_str(key);
            out.push_str("=\"");
            push_escaped_label(out, value);
            out.push('"');
        }
        out.push('}');
    }
    out.push(' ');
    out.push_str(value);
    out.push('\n');
}

fn push_escaped_label(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
}

fn render_process_metrics(out: &mut String) {
    if let Ok(stat) = read_process_stat() {
        metric_float_line(
            out,
            "edge_lb_process_cpu_seconds_total",
            &[],
            stat.cpu_seconds,
            Some("counter"),
        );
        metric_float_line(
            out,
            "edge_lb_process_start_time_seconds",
            &[],
            stat.start_time_seconds,
            Some("gauge"),
        );
    }
    if let Ok(status) = read_process_status() {
        metric_line(
            out,
            "edge_lb_process_memory_rss_bytes",
            &[],
            status.rss_bytes,
            Some("gauge"),
        );
        metric_line(
            out,
            "edge_lb_process_memory_virtual_bytes",
            &[],
            status.virtual_bytes,
            Some("gauge"),
        );
        metric_line(
            out,
            "edge_lb_process_threads",
            &[],
            status.threads,
            Some("gauge"),
        );
    }
}

fn render_host_metrics(out: &mut String) {
    if let Ok(cores) = read_host_cpu_cores() {
        metric_line(out, "edge_lb_host_cpu_cores", &[], cores, Some("gauge"));
    }
    if let Ok(mem) = read_meminfo() {
        metric_line(
            out,
            "edge_lb_host_memory_total_bytes",
            &[],
            mem.total_bytes,
            Some("gauge"),
        );
        metric_line(
            out,
            "edge_lb_host_memory_available_bytes",
            &[],
            mem.available_bytes,
            Some("gauge"),
        );
        metric_line(
            out,
            "edge_lb_host_memory_used_bytes",
            &[],
            mem.total_bytes.saturating_sub(mem.available_bytes),
            Some("gauge"),
        );
    }
    if let Ok(load) = read_loadavg() {
        metric_float_line(out, "edge_lb_host_load1", &[], load.0, Some("gauge"));
        metric_float_line(out, "edge_lb_host_load5", &[], load.1, Some("gauge"));
        metric_float_line(out, "edge_lb_host_load15", &[], load.2, Some("gauge"));
    }
}

struct ProcessStat {
    cpu_seconds: f64,
    start_time_seconds: f64,
}

struct ProcessStatus {
    rss_bytes: u64,
    virtual_bytes: u64,
    threads: u64,
}

struct MemInfo {
    total_bytes: u64,
    available_bytes: u64,
}

fn read_process_stat() -> std::io::Result<ProcessStat> {
    parse_process_stat(
        &fs::read_to_string("/proc/self/stat")?,
        clock_ticks(),
        boot_time_seconds(),
    )
    .ok_or_else(|| std::io::Error::other("failed to parse /proc/self/stat"))
}

fn parse_process_stat(text: &str, clock_ticks: f64, boot_time_seconds: f64) -> Option<ProcessStat> {
    let end = text.rfind(") ")?;
    let fields: Vec<&str> = text[end + 2..].split_whitespace().collect();
    let utime: f64 = fields.get(11)?.parse::<u64>().ok()? as f64;
    let stime: f64 = fields.get(12)?.parse::<u64>().ok()? as f64;
    let start_ticks: f64 = fields.get(19)?.parse::<u64>().ok()? as f64;
    Some(ProcessStat {
        cpu_seconds: (utime + stime) / clock_ticks,
        start_time_seconds: boot_time_seconds + start_ticks / clock_ticks,
    })
}

fn read_process_status() -> std::io::Result<ProcessStatus> {
    parse_process_status(&fs::read_to_string("/proc/self/status")?)
        .ok_or_else(|| std::io::Error::other("failed to parse /proc/self/status"))
}

fn parse_process_status(text: &str) -> Option<ProcessStatus> {
    let mut rss_bytes = None;
    let mut virtual_bytes = None;
    let mut threads = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            rss_bytes = parse_kib_line(value);
        } else if let Some(value) = line.strip_prefix("VmSize:") {
            virtual_bytes = parse_kib_line(value);
        } else if let Some(value) = line.strip_prefix("Threads:") {
            threads = value.trim().parse::<u64>().ok();
        }
    }
    Some(ProcessStatus {
        rss_bytes: rss_bytes?,
        virtual_bytes: virtual_bytes?,
        threads: threads?,
    })
}

fn read_host_cpu_cores() -> std::io::Result<u64> {
    let count = fs::read_to_string("/proc/stat")?
        .lines()
        .filter(|line| {
            let Some(rest) = line.strip_prefix("cpu") else {
                return false;
            };
            rest.chars().next().is_some_and(|ch| ch.is_ascii_digit())
        })
        .count() as u64;
    if count == 0 {
        Err(std::io::Error::other("no cpu cores in /proc/stat"))
    } else {
        Ok(count)
    }
}

fn read_meminfo() -> std::io::Result<MemInfo> {
    parse_meminfo(&fs::read_to_string("/proc/meminfo")?)
        .ok_or_else(|| std::io::Error::other("failed to parse /proc/meminfo"))
}

fn parse_meminfo(text: &str) -> Option<MemInfo> {
    let mut values = HashMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once(':')?;
        if let Some(bytes) = parse_kib_line(value) {
            values.insert(key, bytes);
        }
    }
    Some(MemInfo {
        total_bytes: *values.get("MemTotal")?,
        available_bytes: *values.get("MemAvailable")?,
    })
}

fn read_loadavg() -> std::io::Result<(f64, f64, f64)> {
    parse_loadavg(&fs::read_to_string("/proc/loadavg")?)
        .ok_or_else(|| std::io::Error::other("failed to parse /proc/loadavg"))
}

fn parse_loadavg(text: &str) -> Option<(f64, f64, f64)> {
    let mut fields = text.split_whitespace();
    Some((
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
        fields.next()?.parse().ok()?,
    ))
}

fn boot_time_seconds() -> f64 {
    fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("btime "))
                .and_then(|value| value.trim().parse::<u64>().ok())
        })
        .unwrap_or_default() as f64
}

fn clock_ticks() -> f64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 { ticks as f64 } else { 100.0 }
}

fn parse_kib_line(value: &str) -> Option<u64> {
    value
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()
        .map(|kib| kib.saturating_mul(1024))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_redirect_stats_do_not_fabricate_counters() {
        let mut out = String::new();
        render_redirect_metrics(&mut out, None);
        assert!(out.contains("edge_lb_gateway_native_redirect_stats_available 0\n"));
        assert!(!out.contains("_total"));
    }

    #[test]
    fn return_redirect_metrics_have_bounded_reasons_and_no_fabricated_counters() {
        let mut out = String::new();
        render_return_redirect_metrics(&mut out, None);
        assert!(out.contains("edge_lb_gateway_native_return_redirect_stats_available 0\n"));
        assert!(!out.contains("_total"));
        out.clear();
        render_return_redirect_metrics(
            &mut out,
            Some(edge_lb_common::return_redirect::ReturnRedirectStats {
                submitted: 9,
                neighbor: 3,
                mutation_error: 1,
                ..Default::default()
            }),
        );
        assert!(out.contains("edge_lb_gateway_native_return_redirect_submitted_total 9\n"));
        assert!(out.contains(
            "edge_lb_gateway_native_return_redirect_fallback_total{reason=\"neighbor\"} 3\n"
        ));
        assert!(out.contains("edge_lb_gateway_native_return_redirect_mutation_error_total 1\n"));
        assert_eq!(
            out.matches("# TYPE edge_lb_gateway_native_return_redirect_fallback_total counter\n")
                .count(),
            1
        );
        assert_eq!(
            out.lines()
                .filter(|l| l.starts_with("edge_lb_gateway_native_return_redirect_fallback_total{"))
                .count(),
            7
        );
    }

    #[test]
    fn redirect_stats_have_fixed_reasons_and_one_type_declaration() {
        let mut out = String::new();
        render_redirect_metrics(
            &mut out,
            Some(edge_lb_common::redirect::NativeRedirectStats {
                submitted: 10,
                route_miss: 11,
                mutation_error: 2,
                ..Default::default()
            }),
        );
        assert!(out.contains("edge_lb_gateway_native_redirect_stats_available 1\n"));
        assert!(out.contains("edge_lb_gateway_native_redirect_submitted_total 10\n"));
        assert!(out.contains("edge_lb_gateway_native_redirect_mutation_error_total 2\n"));
        assert!(out.contains(
            "edge_lb_gateway_native_redirect_fallback_total{reason=\"route_miss\"} 11\n"
        ));
        assert_eq!(
            out.matches("# TYPE edge_lb_gateway_native_redirect_fallback_total counter\n")
                .count(),
            1
        );
        assert_eq!(
            out.lines()
                .filter(|line| line.starts_with("edge_lb_gateway_native_redirect_fallback_total{"))
                .count(),
            7
        );
    }

    #[test]
    fn labels_are_escaped_for_prometheus_text() {
        let mut out = String::new();
        metric_line(
            &mut out,
            "edge_lb_test",
            &[("node", "gw\"a\\b\nc")],
            1,
            Some("gauge"),
        );
        assert!(out.contains("node=\"gw\\\"a\\\\b\\nc\""));
    }

    #[test]
    fn process_stat_parser_reads_cpu_and_start_time() {
        let stat = parse_process_stat(
            "123 (edge lb) S 1 2 3 4 5 6 7 8 9 10 200 300 14 15 16 17 18 19 4000 21",
            100.0,
            1_700_000_000.0,
        )
        .unwrap();
        assert_eq!(stat.cpu_seconds, 5.0);
        assert_eq!(stat.start_time_seconds, 1_700_000_040.0);
    }

    #[test]
    fn process_status_parser_reads_memory_and_threads() {
        let status = parse_process_status(
            "Name:\tedge-lb\nVmSize:\t  1234 kB\nVmRSS:\t    456 kB\nThreads:\t7\n",
        )
        .unwrap();
        assert_eq!(status.virtual_bytes, 1234 * 1024);
        assert_eq!(status.rss_bytes, 456 * 1024);
        assert_eq!(status.threads, 7);
    }

    #[test]
    fn meminfo_parser_reads_total_and_available() {
        let mem =
            parse_meminfo("MemTotal: 4096 kB\nMemFree: 1 kB\nMemAvailable: 2048 kB\n").unwrap();
        assert_eq!(mem.total_bytes, 4096 * 1024);
        assert_eq!(mem.available_bytes, 2048 * 1024);
    }

    #[test]
    fn loadavg_parser_reads_three_windows() {
        assert_eq!(
            parse_loadavg("0.10 0.20 0.30 1/2 3").unwrap(),
            (0.1, 0.2, 0.3)
        );
    }
}
