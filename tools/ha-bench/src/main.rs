use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::File,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    path::PathBuf,
    process,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod raw_output;
use raw_output::RawOutput;

#[derive(Clone, Debug)]
struct Config {
    target: String,
    port: u16,
    protocol: ProtocolArg,
    duration: Duration,
    concurrency: usize,
    payload: Vec<u8>,
    timeout: Duration,
    expect: String,
    out: Option<PathBuf>,
    udp_source_port: Option<u16>,
    interval: Option<Duration>,
    udp_socket_mode: UdpSocketMode,
    tcp_conn_mode: TcpConnMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProtocolArg {
    Tcp,
    Udp,
    Both,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpSocketMode {
    ReusePerWorker,
    NewPerRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpConnMode {
    NewPerRequest,
    ReusePerWorker,
}

#[derive(Clone, Debug)]
struct Sample {
    ts_ms: u128,
    protocol: Protocol,
    source_port: Option<u16>,
    ok: bool,
    latency_us: u128,
    backend: String,
    error: String,
}

#[derive(Default)]
struct Stats {
    total: u64,
    ok: u64,
    fail: u64,
    latencies_us: Vec<u128>,
    source_ports: BTreeSet<u16>,
    backends: BTreeMap<String, u64>,
    errors: BTreeMap<String, u64>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ha-bench failed: {error}");
        process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let cfg = match parse_args(env::args().skip(1).collect()) {
        Ok(cfg) => cfg,
        Err(error) => {
            eprintln!("{error}");
            usage();
            process::exit(2);
        }
    };

    let tcp_addr = if matches!(cfg.protocol, ProtocolArg::Tcp | ProtocolArg::Both) {
        match resolve_addr(&cfg.target, cfg.port) {
            Ok(addr) => Some(addr),
            Err(error) => {
                eprintln!("{error}");
                process::exit(1);
            }
        }
    } else {
        None
    };
    let udp_addr = if matches!(cfg.protocol, ProtocolArg::Udp | ProtocolArg::Both) {
        match resolve_addr(&cfg.target, cfg.port) {
            Ok(addr) => Some(addr),
            Err(error) => {
                eprintln!("{error}");
                process::exit(1);
            }
        }
    } else {
        None
    };

    let raw = match cfg.out.as_ref() {
        Some(path) => match File::create(path) {
            Ok(file) => Some(Arc::new(Mutex::new(RawOutput::new(file)?))),
            Err(error) => {
                eprintln!("creating {}: {error}", path.display());
                process::exit(1);
            }
        },
        None => None,
    };
    let cfg = Arc::new(cfg);
    let deadline = Instant::now() + cfg.duration;
    let mut handles = Vec::new();
    for protocol in protocols(cfg.protocol) {
        for worker_id in 0..cfg.concurrency {
            let cfg = Arc::clone(&cfg);
            let raw = raw.clone();
            let addr = match protocol {
                Protocol::Tcp => tcp_addr.expect("tcp addr resolved"),
                Protocol::Udp => udp_addr.expect("udp addr resolved"),
            };
            handles.push(thread::spawn(move || {
                run_worker(worker_id, protocol, addr, deadline, &cfg, raw)
            }));
        }
    }

    let mut stats: BTreeMap<Protocol, Stats> = BTreeMap::new();
    let mut worker_failed = false;
    for handle in handles {
        match handle.join() {
            Ok(worker_stats) => merge_stats(&mut stats, worker_stats),
            Err(_) => worker_failed = true,
        }
    }
    if let Some(raw) = &raw {
        raw.lock()
            .map_err(|_| io::Error::other("raw output mutex poisoned"))?
            .finish(stats.values().map(|stats| stats.total).sum())?;
    }
    if worker_failed {
        return Err(io::Error::other(
            "worker thread panicked; results incomplete",
        ));
    }

    print_summary(&cfg, &stats);
    Ok(())
}

fn run_worker(
    worker_id: usize,
    protocol: Protocol,
    addr: SocketAddr,
    deadline: Instant,
    cfg: &Config,
    raw: Option<Arc<Mutex<RawOutput<File>>>>,
) -> BTreeMap<Protocol, Stats> {
    let mut stats = BTreeMap::new();
    let mut tcp_stream = None;
    let udp_socket =
        if protocol == Protocol::Udp && cfg.udp_socket_mode == UdpSocketMode::ReusePerWorker {
            match bind_udp_socket(addr, cfg) {
                Ok(socket) => Some(socket),
                Err(err) => {
                    let sample = failed_sample(
                        Protocol::Udp,
                        format!(
                            "binding UDP socket for worker {worker_id}: {}",
                            describe_io_error(&err)
                        ),
                    );
                    record_sample(&mut stats, &sample);
                    if let Some(raw) = &raw {
                        write_sample(raw, &sample);
                    }
                    return stats;
                }
            }
        } else {
            None
        };
    let mut seq = 0u64;
    while Instant::now() < deadline {
        let sample = match protocol {
            Protocol::Tcp if cfg.tcp_conn_mode == TcpConnMode::ReusePerWorker => {
                run_tcp_reused(addr, cfg, &mut tcp_stream)
            }
            Protocol::Tcp => run_tcp(addr, cfg),
            Protocol::Udp => run_udp(addr, cfg, udp_socket.as_ref(), worker_id, seq),
        };
        record_sample(&mut stats, &sample);
        if let Some(raw) = &raw {
            write_sample(raw, &sample);
        }
        seq = seq.wrapping_add(1);
        if let Some(interval) = cfg.interval {
            thread::sleep(interval);
        }
    }
    stats
}

fn run_tcp(addr: SocketAddr, cfg: &Config) -> Sample {
    let started = Instant::now();
    let ts_ms = unix_ms();
    let mut response = Vec::new();
    let mut error = String::new();
    let mut source_port = None;

    let result = TcpStream::connect_timeout(&addr, cfg.timeout).and_then(|mut stream| {
        source_port = stream.local_addr().ok().map(|addr| addr.port());
        stream.set_read_timeout(Some(cfg.timeout))?;
        stream.set_write_timeout(Some(cfg.timeout))?;
        stream.write_all(&cfg.payload)?;
        stream.flush()?;
        stream.shutdown(Shutdown::Write)?;
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf)?;
        response.extend_from_slice(&buf[..n]);
        Ok(())
    });
    if let Err(err) = result {
        error = describe_io_error(&err);
    }

    finish_sample(
        ts_ms,
        Protocol::Tcp,
        started,
        source_port,
        &response,
        &error,
        &cfg.expect,
    )
}

fn run_tcp_reused(addr: SocketAddr, cfg: &Config, stream: &mut Option<TcpStream>) -> Sample {
    let started = Instant::now();
    let ts_ms = unix_ms();
    let mut response = Vec::new();
    let mut error = String::new();

    let mut result = send_tcp_reused_request(addr, cfg, stream, &mut response);
    if should_retry_reused_tcp(&result, &response) {
        *stream = None;
        response.clear();
        result = send_tcp_reused_request(addr, cfg, stream, &mut response);
    }
    let source_port = stream
        .as_ref()
        .and_then(|stream| stream.local_addr().ok().map(|addr| addr.port()));
    if let Err(err) = result {
        error = describe_io_error(&err);
        *stream = None;
    }

    finish_sample(
        ts_ms,
        Protocol::Tcp,
        started,
        source_port,
        &response,
        &error,
        &cfg.expect,
    )
}

fn send_tcp_reused_request(
    addr: SocketAddr,
    cfg: &Config,
    stream: &mut Option<TcpStream>,
    response: &mut Vec<u8>,
) -> io::Result<()> {
    if stream.is_none() {
        *stream = Some(connect_tcp(addr, cfg)?);
    }
    let stream = stream.as_mut().expect("tcp stream should be connected");
    stream.write_all(&cfg.payload)?;
    stream.flush()?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "tcp peer closed reused connection",
        ));
    }
    response.extend_from_slice(&buf[..n]);
    Ok(())
}

fn connect_tcp(addr: SocketAddr, cfg: &Config) -> io::Result<TcpStream> {
    let stream = TcpStream::connect_timeout(&addr, cfg.timeout)?;
    stream.set_read_timeout(Some(cfg.timeout))?;
    stream.set_write_timeout(Some(cfg.timeout))?;
    Ok(stream)
}

fn should_retry_reused_tcp(result: &io::Result<()>, response: &[u8]) -> bool {
    result.is_err() || response.is_empty()
}

fn run_udp(
    addr: SocketAddr,
    cfg: &Config,
    socket: Option<&UdpSocket>,
    worker_id: usize,
    seq: u64,
) -> Sample {
    let started = Instant::now();
    let ts_ms = unix_ms();
    let mut response = Vec::new();
    let mut error = String::new();
    let mut source_port = None;

    let result = with_udp_socket(addr, cfg, socket, |socket| {
        source_port = socket.local_addr().ok().map(|addr| addr.port());
        socket.send(&cfg.payload)?;
        let mut buf = [0u8; 4096];
        let n = socket.recv(&mut buf)?;
        response.extend_from_slice(&buf[..n]);
        Ok(())
    });
    if let Err(err) = result {
        error = if cfg.udp_source_port.is_some() {
            format!("{}; worker={worker_id} seq={seq}", describe_io_error(&err))
        } else {
            describe_io_error(&err)
        };
    }

    finish_sample(
        ts_ms,
        Protocol::Udp,
        started,
        source_port,
        &response,
        &error,
        &cfg.expect,
    )
}

fn with_udp_socket<F>(
    addr: SocketAddr,
    cfg: &Config,
    socket: Option<&UdpSocket>,
    f: F,
) -> io::Result<()>
where
    F: FnOnce(&UdpSocket) -> io::Result<()>,
{
    if let Some(socket) = socket {
        return f(socket);
    }
    let socket = bind_udp_socket(addr, cfg)?;
    f(&socket)
}

fn bind_udp_socket(addr: SocketAddr, cfg: &Config) -> io::Result<UdpSocket> {
    let bind_addr = match (addr, cfg.udp_source_port) {
        (SocketAddr::V4(_), Some(port)) => format!("0.0.0.0:{port}"),
        (SocketAddr::V4(_), None) => "0.0.0.0:0".to_string(),
        (SocketAddr::V6(_), Some(port)) => format!("[::]:{port}"),
        (SocketAddr::V6(_), None) => "[::]:0".to_string(),
    };
    let socket = UdpSocket::bind(&bind_addr)?;
    socket.set_read_timeout(Some(cfg.timeout))?;
    socket.set_write_timeout(Some(cfg.timeout))?;
    socket.connect(addr)?;
    Ok(socket)
}

fn failed_sample(protocol: Protocol, error: String) -> Sample {
    Sample {
        ts_ms: unix_ms(),
        protocol,
        source_port: None,
        ok: false,
        latency_us: 0,
        backend: "-".to_string(),
        error,
    }
}

fn finish_sample(
    ts_ms: u128,
    protocol: Protocol,
    started: Instant,
    source_port: Option<u16>,
    response: &[u8],
    error: &str,
    expect: &str,
) -> Sample {
    let body = String::from_utf8_lossy(response);
    let ok = !response.is_empty() && body.contains(expect);
    Sample {
        ts_ms,
        protocol,
        source_port,
        ok,
        latency_us: started.elapsed().as_micros(),
        backend: extract_private_ipv4(&body).unwrap_or("-").to_string(),
        error: if ok {
            String::new()
        } else if error.is_empty() {
            sanitize(&body)
        } else {
            sanitize(error)
        },
    }
}

fn record_sample(stats: &mut BTreeMap<Protocol, Stats>, sample: &Sample) {
    let stats = stats.entry(sample.protocol).or_default();
    stats.total += 1;
    stats.latencies_us.push(sample.latency_us);
    if let Some(port) = sample.source_port {
        stats.source_ports.insert(port);
    }
    if sample.ok {
        stats.ok += 1;
        *stats.backends.entry(sample.backend.clone()).or_default() += 1;
    } else {
        stats.fail += 1;
        *stats.errors.entry(sample.error.clone()).or_default() += 1;
    }
}

fn write_sample(raw: &Arc<Mutex<RawOutput<File>>>, sample: &Sample) {
    raw.lock()
        .expect("raw output mutex poisoned")
        .record(sample);
}

fn merge_stats(target: &mut BTreeMap<Protocol, Stats>, source: BTreeMap<Protocol, Stats>) {
    for (protocol, mut incoming) in source {
        let stats = target.entry(protocol).or_default();
        stats.total += incoming.total;
        stats.ok += incoming.ok;
        stats.fail += incoming.fail;
        stats.latencies_us.append(&mut incoming.latencies_us);
        stats.source_ports.append(&mut incoming.source_ports);
        for (backend, count) in incoming.backends {
            *stats.backends.entry(backend).or_default() += count;
        }
        for (error, count) in incoming.errors {
            *stats.errors.entry(error).or_default() += count;
        }
    }
}

fn print_summary(cfg: &Config, stats: &BTreeMap<Protocol, Stats>) {
    let elapsed = cfg.duration.as_secs_f64();
    println!("edge-lb HA bench summary");
    println!(
        "target={}:{} protocol={} duration={}s concurrency={} interval={} tcp_conn_mode={} udp_socket_mode={} payload={}",
        cfg.target,
        cfg.port,
        protocol_arg_name(cfg.protocol),
        cfg.duration.as_secs(),
        cfg.concurrency,
        interval_name(cfg.interval),
        tcp_conn_mode_name(cfg.tcp_conn_mode),
        udp_socket_mode_name(cfg.udp_socket_mode),
        String::from_utf8_lossy(&cfg.payload).trim_end()
    );
    if let Some(path) = &cfg.out {
        println!("raw_results={}", path.display());
        println!(
            "raw_rows={}",
            stats.values().map(|stats| stats.total).sum::<u64>()
        );
    }
    println!();

    for (protocol, stats) in stats {
        let mut latencies = stats.latencies_us.clone();
        latencies.sort_unstable();
        let success_rate = if stats.total == 0 {
            0.0
        } else {
            stats.ok as f64 * 100.0 / stats.total as f64
        };
        println!(
            "{} total={} ok={} fail={} success_rate={:.2}% rps={:.1} source_ports={} avg_ms={:.3} p50_ms={:.3} p95_ms={:.3} p99_ms={:.3} max_ms={:.3}",
            protocol_name(*protocol),
            stats.total,
            stats.ok,
            stats.fail,
            success_rate,
            stats.total as f64 / elapsed,
            stats.source_ports.len(),
            average_ms(&latencies),
            percentile_ms(&latencies, 50.0),
            percentile_ms(&latencies, 95.0),
            percentile_ms(&latencies, 99.0),
            latencies.last().copied().unwrap_or(0) as f64 / 1000.0,
        );
        for (backend, count) in &stats.backends {
            println!(
                "{} backend={} ok={}",
                protocol_name(*protocol),
                backend,
                count
            );
        }
        for (error, count) in &stats.errors {
            println!(
                "{} error={} count={}",
                protocol_name(*protocol),
                error,
                count
            );
        }
        println!();
    }
}

fn average_ms(values: &[u128]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let sum: u128 = values.iter().sum();
    sum as f64 / values.len() as f64 / 1000.0
}

fn percentile_ms(values: &[u128], percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let idx = ((values.len() as f64 - 1.0) * percentile / 100.0).round() as usize;
    values[idx] as f64 / 1000.0
}

fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|err| format!("resolving {host}:{port}: {err}"))?
        .next()
        .ok_or_else(|| format!("no address resolved for {host}:{port}"))
}

fn extract_private_ipv4(body: &str) -> Option<&str> {
    let key = "\"private_ipv4\":\"";
    let start = body.find(key)? + key.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn sanitize(value: &str) -> String {
    value
        .trim()
        .chars()
        .map(|ch| match ch {
            '\t' | '\r' | '\n' => ' ',
            _ => ch,
        })
        .collect::<String>()
}

fn describe_io_error(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "timed out".to_string(),
        _ => error.to_string(),
    }
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

fn protocols(protocol: ProtocolArg) -> Vec<Protocol> {
    match protocol {
        ProtocolArg::Tcp => vec![Protocol::Tcp],
        ProtocolArg::Udp => vec![Protocol::Udp],
        ProtocolArg::Both => vec![Protocol::Tcp, Protocol::Udp],
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn protocol_arg_name(protocol: ProtocolArg) -> &'static str {
    match protocol {
        ProtocolArg::Tcp => "tcp",
        ProtocolArg::Udp => "udp",
        ProtocolArg::Both => "both",
    }
}

fn interval_name(interval: Option<Duration>) -> String {
    match interval {
        Some(value) => format!("{}us", value.as_micros()),
        None => "none".to_string(),
    }
}

fn udp_socket_mode_name(mode: UdpSocketMode) -> &'static str {
    match mode {
        UdpSocketMode::ReusePerWorker => "reuse-per-worker",
        UdpSocketMode::NewPerRequest => "new-per-request",
    }
}

fn tcp_conn_mode_name(mode: TcpConnMode) -> &'static str {
    match mode {
        TcpConnMode::NewPerRequest => "new-per-request",
        TcpConnMode::ReusePerWorker => "reuse-per-worker",
    }
}

fn parse_args(args: Vec<String>) -> Result<Config, String> {
    let mut cfg = Config {
        target: "192.168.0.6".to_string(),
        port: 8080,
        protocol: ProtocolArg::Both,
        duration: Duration::from_secs(60),
        concurrency: 8,
        payload: b"discover\n".to_vec(),
        timeout: Duration::from_millis(1000),
        expect: "\"private_ipv4\"".to_string(),
        out: None,
        udp_source_port: None,
        interval: None,
        udp_socket_mode: UdpSocketMode::ReusePerWorker,
        tcp_conn_mode: TcpConnMode::NewPerRequest,
    };

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "--target" | "--vip" => {
                cfg.target = next_value(&args, &mut i, arg)?;
            }
            "--port" => {
                cfg.port = parse_port(&next_value(&args, &mut i, arg)?, "--port")?;
            }
            "--protocol" => {
                cfg.protocol = parse_protocol(&next_value(&args, &mut i, arg)?)?;
            }
            "--duration" => {
                cfg.duration = Duration::from_secs(parse_positive_u64(
                    &next_value(&args, &mut i, arg)?,
                    "--duration",
                )?);
            }
            "--concurrency" => {
                cfg.concurrency =
                    parse_positive_usize(&next_value(&args, &mut i, arg)?, "--concurrency")?;
            }
            "--payload" => {
                let mut payload = next_value(&args, &mut i, arg)?;
                if !payload.ends_with('\n') {
                    payload.push('\n');
                }
                cfg.payload = payload.into_bytes();
            }
            "--timeout-ms" => {
                cfg.timeout = Duration::from_millis(parse_positive_u64(
                    &next_value(&args, &mut i, arg)?,
                    "--timeout-ms",
                )?);
            }
            "--expect" => {
                cfg.expect = next_value(&args, &mut i, arg)?;
            }
            "--out" => {
                cfg.out = Some(PathBuf::from(next_value(&args, &mut i, arg)?));
            }
            "--udp-source-port" => {
                cfg.udp_source_port = Some(parse_port(
                    &next_value(&args, &mut i, arg)?,
                    "--udp-source-port",
                )?);
            }
            "--interval-us" => {
                cfg.interval = Some(Duration::from_micros(parse_positive_u64(
                    &next_value(&args, &mut i, arg)?,
                    "--interval-us",
                )?));
            }
            "--interval-ms" => {
                cfg.interval = Some(Duration::from_millis(parse_positive_u64(
                    &next_value(&args, &mut i, arg)?,
                    "--interval-ms",
                )?));
            }
            "--udp-new-socket-per-request" => {
                cfg.udp_socket_mode = UdpSocketMode::NewPerRequest;
            }
            "--tcp-reuse-conn" => {
                cfg.tcp_conn_mode = TcpConnMode::ReusePerWorker;
            }
            "-h" | "--help" => {
                usage();
                process::exit(0);
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
        i += 1;
    }
    if cfg.udp_source_port.is_some()
        && matches!(cfg.protocol, ProtocolArg::Udp | ProtocolArg::Both)
        && cfg.concurrency > 1
    {
        return Err(
            "--udp-source-port requires --concurrency 1 because a UDP source port can only be bound by one worker"
                .to_string(),
        );
    }
    Ok(cfg)
}

fn next_value(args: &[String], i: &mut usize, name: &str) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{name} requires a value"))
}

fn parse_protocol(value: &str) -> Result<ProtocolArg, String> {
    match value {
        "tcp" => Ok(ProtocolArg::Tcp),
        "udp" => Ok(ProtocolArg::Udp),
        "both" => Ok(ProtocolArg::Both),
        _ => Err("--protocol must be tcp, udp, or both".to_string()),
    }
}

fn parse_port(value: &str, name: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("{name} must be in range 1..=65535"))?;
    if port == 0 {
        return Err(format!("{name} must be in range 1..=65535"));
    }
    Ok(port)
}

fn parse_positive_u64(value: &str, name: &str) -> Result<u64, String> {
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be positive"))?;
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(value)
}

fn parse_positive_usize(value: &str, name: &str) -> Result<usize, String> {
    let value = value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be positive"))?;
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(value)
}

fn usage() {
    eprintln!(
        "Usage: ha-bench [--target IP] [--port PORT] [--protocol tcp|udp|both] \\
         [--duration SECONDS] [--concurrency N] [--payload TEXT] \\
         [--timeout-ms MS] [--expect TEXT] [--udp-source-port PORT] \\
         [--interval-us US|--interval-ms MS] [--tcp-reuse-conn] \\
         [--udp-new-socket-per-request] [--out FILE]\n\
         \n\
         Notes:\n\
           TCP opens a new connection per request by default and then shutdowns write, matching nc -N.\n\
           Use --tcp-reuse-conn to reuse one TCP connection per worker when the target supports multiple requests per connection.\n\
           UDP reuses one socket per worker by default. Use --udp-new-socket-per-request to increase source port samples and stress flow creation.\n\
           --udp-source-port is for hash stickiness checks and requires --concurrency 1.\n\
           Without --udp-source-port, UDP sockets bind ephemeral source ports according to the selected UDP socket mode."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_private_ipv4_from_discovery_body() {
        let body = r#"{"hostname":"node","private_ipv4":"192.168.0.14","client_port":12345}"#;
        assert_eq!(extract_private_ipv4(body), Some("192.168.0.14"));
    }

    #[test]
    fn udp_fixed_source_port_rejects_parallel_workers() {
        let err = parse_args(vec![
            "--protocol".to_string(),
            "udp".to_string(),
            "--udp-source-port".to_string(),
            "12345".to_string(),
            "--concurrency".to_string(),
            "2".to_string(),
        ])
        .expect_err("fixed UDP source port must reject parallel workers");
        assert!(err.contains("--udp-source-port requires --concurrency 1"));
    }

    #[test]
    fn timeout_errors_are_reported_consistently() {
        let err = io::Error::from(io::ErrorKind::WouldBlock);
        assert_eq!(describe_io_error(&err), "timed out");
    }

    #[test]
    fn interval_argument_sets_worker_delay() {
        let cfg = parse_args(vec![
            "--interval-ms".to_string(),
            "10".to_string(),
            "--duration".to_string(),
            "1".to_string(),
        ])
        .expect("interval should parse");
        assert_eq!(cfg.interval, Some(Duration::from_millis(10)));
    }

    #[test]
    fn udp_socket_reuse_is_default_and_can_be_overridden() {
        let default_cfg = parse_args(Vec::new()).expect("default args should parse");
        assert_eq!(default_cfg.udp_socket_mode, UdpSocketMode::ReusePerWorker);

        let new_socket_cfg = parse_args(vec!["--udp-new-socket-per-request".to_string()])
            .expect("udp socket mode should parse");
        assert_eq!(new_socket_cfg.udp_socket_mode, UdpSocketMode::NewPerRequest);
    }

    #[test]
    fn stats_count_unique_source_ports() {
        let mut stats = BTreeMap::new();
        let mut sample = Sample {
            ts_ms: 0,
            protocol: Protocol::Udp,
            source_port: Some(40000),
            ok: true,
            latency_us: 10,
            backend: "192.168.0.13".to_string(),
            error: String::new(),
        };

        record_sample(&mut stats, &sample);
        record_sample(&mut stats, &sample);
        sample.source_port = Some(40001);
        record_sample(&mut stats, &sample);

        let udp = stats.get(&Protocol::Udp).expect("udp stats should exist");
        assert_eq!(udp.total, 3);
        assert_eq!(udp.source_ports.len(), 2);
    }

    #[test]
    fn tcp_connection_reuse_is_opt_in() {
        let default_cfg = parse_args(Vec::new()).expect("default args should parse");
        assert_eq!(default_cfg.tcp_conn_mode, TcpConnMode::NewPerRequest);

        let reuse_cfg =
            parse_args(vec!["--tcp-reuse-conn".to_string()]).expect("tcp mode should parse");
        assert_eq!(reuse_cfg.tcp_conn_mode, TcpConnMode::ReusePerWorker);
    }

    #[test]
    fn reused_tcp_retries_closed_connection_once() {
        let err = io::Error::from(io::ErrorKind::UnexpectedEof);
        assert!(should_retry_reused_tcp(&Err(err), &[]));
        assert!(!should_retry_reused_tcp(&Ok(()), b"ok"));
    }
}
