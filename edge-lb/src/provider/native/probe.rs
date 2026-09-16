//! Native target health probe worker.
//!
//! Runs probes independently of the API read path: the scheduler below owns
//! health evaluation, writes observed `currState` back into the native proxy
//! state, and refreshes the eBPF health map when a transition happens.
//! The API stays a pure reader of observed state. Desired target-group
//! configuration is never modified here.

use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

use anyhow::Result;

use crate::config::{Config, Listener, TargetGroup};

/// Default probe period when the target group does not configure one.
pub const DEFAULT_PERIOD_SECS: u64 = 5;
/// Default consecutive failures before a target is marked unhealthy.
pub const DEFAULT_RETRIES: u32 = 2;
/// Probe types supported by the native worker. `none` disables probing.
const EXECUTABLE_PROBES: [&str; 5] = ["ping", "tcp", "udp", "http", "https"];
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Ok,
    Fail,
}

/// One scheduled probe target: a target-group target observed under every
/// listener protocol that references its group. The probe uses `port`, while
/// `names` use each listener's forwarding target port because that is the
/// runtime identity stored by the native datapath.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub names: Vec<String>,
    pub address: IpAddr,
    pub port: u16,
    pub probe_type: String,
    pub probe_req: Option<String>,
    pub probe_resp: Option<String>,
    pub expected_status: Option<u16>,
    pub skip_tls_verify: bool,
    pub timeout: Duration,
    pub period: Duration,
    pub retries: u32,
}

/// Runtime probe state per backend target (worker memory only).
#[derive(Debug, Default)]
struct ProbeRuntime {
    consecutive_failures: u32,
}

pub fn run_worker(cfg: Config) {
    let mut runtimes: HashMap<String, ProbeRuntime> = HashMap::new();
    let mut schedule = HashMap::<String, (ProbeTarget, Instant)>::new();
    let clients = ProbeClients::new();
    tracing::info!("[probe] native target probe worker started");
    while !crate::runtime::shutdown::requested() {
        probe_round(&cfg, &clients, &mut schedule, &mut runtimes);
        std::thread::sleep(Duration::from_secs(1));
    }
    tracing::info!("[probe] shutdown requested");
}

/// Keep independent deadlines; a short-period group must not accelerate every probe.
fn probe_round(
    cfg: &Config,
    clients: &ProbeClients,
    schedule: &mut HashMap<String, (ProbeTarget, Instant)>,
    runtimes: &mut HashMap<String, ProbeRuntime>,
) {
    let effective = match hydrated_probe_config(cfg) {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!("[probe] native proxy state refresh failed: {error:#}");
            return;
        }
    };
    let targets = scheduled_targets(&effective);
    let keys = targets
        .iter()
        .map(|target| names_key(&target.names))
        .collect::<BTreeSet<_>>();
    schedule.retain(|key, _| keys.contains(key));
    runtimes.retain(|key, _| keys.contains(key));
    let mut outcomes = Vec::new();
    for target in &targets {
        let key = names_key(&target.names);
        let now = Instant::now();
        if !probe_is_due(schedule, &key, target, now) {
            continue;
        }
        if schedule
            .get(&key)
            .is_some_and(|(previous, _)| previous != target)
        {
            runtimes.remove(&key);
        }
        let outcome = probe_target_with_clients(target, clients);
        schedule.insert(key, (target.clone(), Instant::now() + target.period));
        outcomes.push((target, outcome));
    }
    if outcomes.is_empty() {
        return;
    }
    // Do not publish a result for a probe definition removed or edited during I/O.
    let current = match hydrated_probe_config(cfg) {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!("[probe] native proxy state refresh failed: {error:#}");
            return;
        }
    };
    let current_targets = scheduled_targets(&current);
    outcomes.retain(|(target, _)| current_targets.contains(target));
    let transitions = apply_results(cfg, &outcomes, runtimes);
    if transitions > 0
        && let Err(e) = crate::linux::native_dnat::refresh_target_health(&current)
    {
        tracing::warn!("[probe] native health map refresh failed: {e:#}");
    }
}

fn hydrated_probe_config(cfg: &Config) -> Result<Config> {
    let mut effective = cfg.clone();
    super::hydrate_proxy_config_from_api(&mut effective)?;
    crate::control::merge_active_backend_subscriptions(&mut effective)?;
    Ok(effective)
}

fn probe_is_due(
    schedule: &HashMap<String, (ProbeTarget, Instant)>,
    key: &str,
    target: &ProbeTarget,
    now: Instant,
) -> bool {
    schedule
        .get(key)
        .is_none_or(|(previous, due)| previous != target || now >= *due)
}

/// Expand monitored target groups into probe targets. Backend target addresses are
/// resolved through the backend inventory so `backend = name` targets probe
/// the live underlay address even when the stored record was created while
/// the backend was offline.
pub fn scheduled_targets(cfg: &Config) -> Vec<ProbeTarget> {
    let mut out = Vec::new();
    for group in monitored_groups(cfg) {
        let probe_type = normalized_probe_type(group);
        if !EXECUTABLE_PROBES.contains(&probe_type.as_str()) {
            continue;
        }
        let probe_port = if probe_type == "ping" {
            0
        } else {
            group
                .probe_port
                .or_else(|| {
                    cfg.listeners
                        .iter()
                        .find(|listener| listener.target_group == group.name)
                        .map(|listener| listener.target_port)
                        .filter(|port| *port != 0)
                })
                .unwrap_or(0)
        };
        let period_secs = u64::from(group.period_secs.unwrap_or(DEFAULT_PERIOD_SECS as u32)).max(1);
        let timeout = Duration::from_secs(period_secs.min(3)).max(Duration::from_millis(500));
        let retries = group.retries.unwrap_or(DEFAULT_RETRIES).max(1);
        for target in &group.targets {
            let datapath_address = cfg.resolve_backend_target_address(target);
            let probe_address = cfg.resolve_backend_probe_address(target);
            if datapath_address.is_unspecified()
                || datapath_address.is_loopback()
                || probe_address.is_unspecified()
                || probe_address.is_loopback()
            {
                continue;
            }
            let listener_identities = listener_identities(cfg, &group.name);
            if listener_identities.is_empty() {
                continue;
            }
            let names = listener_identities
                .iter()
                .map(|(protocol, target_port)| {
                    target_health_identity(&group.name, datapath_address, protocol, *target_port)
                })
                .collect::<Vec<_>>();
            out.push(ProbeTarget {
                names,
                address: probe_address,
                port: probe_port,
                probe_type: probe_type.clone(),
                probe_req: group.probe_req.clone(),
                probe_resp: group.probe_resp.clone(),
                expected_status: group.probe_status,
                skip_tls_verify: group.probe_skip_tls_verify,
                timeout,
                period: Duration::from_secs(period_secs),
                retries,
            });
        }
    }
    out
}

fn monitored_groups(cfg: &Config) -> Vec<&TargetGroup> {
    let bound_groups = cfg
        .listeners
        .iter()
        .map(|listener| listener.target_group.as_str())
        .collect::<std::collections::HashSet<_>>();
    cfg.target_groups
        .iter()
        .filter(|group| bound_groups.contains(group.name.as_str()))
        .filter(|group| group.monitor)
        .filter(|group| {
            group
                .probe_type
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty() && !value.eq_ignore_ascii_case("none"))
        })
        .collect()
}

fn normalized_probe_type(group: &TargetGroup) -> String {
    group
        .probe_type
        .clone()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Runtime identities of every listener bound to this group. The target port
/// is deliberately kept separate from the health probe port.
fn listener_identities(cfg: &Config, group: &str) -> BTreeSet<(String, u16)> {
    cfg.listeners
        .iter()
        .filter(|listener: &&Listener| listener.target_group == group)
        .flat_map(|listener| {
            listener
                .protocols
                .iter()
                .map(|protocol| (protocol.as_str().to_string(), listener.target_port))
        })
        .collect()
}

pub fn target_health_identity(
    group: &str,
    address: IpAddr,
    protocol: &str,
    service_port: u16,
) -> String {
    format!(
        "{}:{}_{}_{}",
        group,
        address,
        protocol.trim().to_ascii_lowercase(),
        service_port
    )
}

/// Execute one probe.
pub fn probe_target(target: &ProbeTarget) -> ProbeOutcome {
    probe_target_with_clients(target, &ProbeClients::new())
}

struct ProbeClients {
    secure: Option<reqwest::blocking::Client>,
    insecure: Option<reqwest::blocking::Client>,
}

impl ProbeClients {
    fn new() -> Self {
        let build = |accept_invalid_certs| {
            reqwest::blocking::Client::builder()
                .pool_idle_timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .danger_accept_invalid_certs(accept_invalid_certs)
                .build()
                .ok()
        };
        Self {
            secure: build(false),
            insecure: build(true),
        }
    }
}

fn probe_target_with_clients(target: &ProbeTarget, clients: &ProbeClients) -> ProbeOutcome {
    match target.probe_type.as_str() {
        "ping" => probe_ping(target),
        "tcp" => probe_tcp(target),
        "udp" => probe_udp(target),
        "http" => probe_http(target, clients, false),
        "https" => probe_http(target, clients, true),
        other => {
            tracing::debug!("[probe] probe type {other:?} not executable; skipping");
            ProbeOutcome::Ok
        }
    }
}

fn probe_ping(target: &ProbeTarget) -> ProbeOutcome {
    let IpAddr::V4(address) = target.address else {
        return ProbeOutcome::Fail;
    };

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        tracing::debug!("[probe] ping socket creation failed for {address}");
        return ProbeOutcome::Fail;
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval {
        tv_sec: target.timeout.as_secs().try_into().unwrap_or(i64::MAX),
        tv_usec: i64::from(target.timeout.subsec_micros()),
    };
    let timeout_len = std::mem::size_of_val(&timeout) as libc::socklen_t;
    let timeout_result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            timeout_len,
        )
    };
    if timeout_result < 0 {
        return ProbeOutcome::Fail;
    }

    let identifier = std::process::id() as u16;
    let sequence = (Instant::now().elapsed().subsec_nanos() as u16).wrapping_add(identifier);
    let mut packet = [0u8; 8];
    packet[0] = 8;
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    let checksum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());

    let destination = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    };
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (&destination as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&destination) as libc::socklen_t,
        )
    };
    if sent != packet.len() as libc::ssize_t {
        return ProbeOutcome::Fail;
    }

    let mut response = [0u8; 1500];
    let received = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            response.as_mut_ptr().cast(),
            response.len(),
            0,
        )
    };
    if received < 8 {
        return ProbeOutcome::Fail;
    }
    let bytes = &response[..received as usize];
    let offset = if bytes[0] >> 4 == 4 {
        usize::from(bytes[0] & 0x0f) * 4
    } else {
        0
    };
    if bytes.len() < offset + 8 {
        return ProbeOutcome::Fail;
    }
    let icmp = &bytes[offset..offset + 8];
    if icmp[0] == 0
        && icmp[1] == 0
        && u16::from_be_bytes([icmp[4], icmp[5]]) == identifier
        && u16::from_be_bytes([icmp[6], icmp[7]]) == sequence
    {
        ProbeOutcome::Ok
    } else {
        ProbeOutcome::Fail
    }
}

fn icmp_checksum(packet: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < packet.len() {
        sum += u32::from(u16::from_be_bytes([packet[index], packet[index + 1]]));
        index += 2;
    }
    if let Some(&byte) = packet.get(index) {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn probe_tcp(target: &ProbeTarget) -> ProbeOutcome {
    let deadline = Instant::now() + target.timeout;
    match tcp_connect(target.address, target.port, target.timeout) {
        Ok(mut stream) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || stream.set_write_timeout(Some(remaining)).is_err() {
                return ProbeOutcome::Fail;
            }
            if let Some(request) = target.probe_req.as_deref().filter(|v| !v.is_empty())
                && std::io::Write::write_all(&mut stream, request.as_bytes()).is_err()
            {
                return ProbeOutcome::Fail;
            }
            if let Some(expected) = target.probe_resp.as_deref().filter(|v| !v.is_empty()) {
                let mut response = Vec::new();
                let mut buf = [0u8; 1024];
                while response.len() < MAX_RESPONSE_BYTES {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
                        break;
                    }
                    match std::io::Read::read(&mut stream, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(size) => response.extend_from_slice(&buf[..size]),
                    }
                    if response
                        .windows(expected.len())
                        .any(|bytes| bytes == expected.as_bytes())
                    {
                        return ProbeOutcome::Ok;
                    }
                }
                return ProbeOutcome::Fail;
            }
            ProbeOutcome::Ok
        }
        Err(e) => {
            tracing::debug!("[probe] tcp {}:{} failed: {e}", target.address, target.port);
            ProbeOutcome::Fail
        }
    }
}

fn probe_udp(target: &ProbeTarget) -> ProbeOutcome {
    use std::net::UdpSocket;
    let addr = SocketAddr::new(target.address, target.port);
    let bind = if target.address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = UdpSocket::bind(bind) else {
        return ProbeOutcome::Fail;
    };
    if socket.connect(addr).is_err() {
        return ProbeOutcome::Fail;
    }
    let payload = target.probe_req.clone().unwrap_or_default();
    if socket.set_write_timeout(Some(target.timeout)).is_err()
        || socket.send(payload.as_bytes()).is_err()
    {
        return ProbeOutcome::Fail;
    }
    // Best-effort UDP probe: an ICMP port-unreachable surfaces as a read
    // error on the connected socket; silence within the window counts as ok.
    if socket.set_read_timeout(Some(target.timeout)).is_err() {
        return ProbeOutcome::Fail;
    }
    let mut buf = [0u8; 65535];
    match socket.recv(&mut buf) {
        Ok(_size)
            if target
                .probe_resp
                .as_deref()
                .is_none_or(|expected| expected.is_empty()) =>
        {
            ProbeOutcome::Ok
        }
        Ok(size)
            if String::from_utf8_lossy(&buf[..size])
                .contains(target.probe_resp.as_deref().unwrap_or_default()) =>
        {
            ProbeOutcome::Ok
        }
        Ok(_) => ProbeOutcome::Fail,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            ProbeOutcome::Fail
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) && target.probe_resp.as_deref().is_none_or(str::is_empty) =>
        {
            ProbeOutcome::Ok
        }
        Err(_) => ProbeOutcome::Fail,
    }
}

fn probe_http(target: &ProbeTarget, clients: &ProbeClients, tls: bool) -> ProbeOutcome {
    let scheme = if tls { "https" } else { "http" };
    let host = SocketAddr::new(target.address, target.port);
    let path = target
        .probe_req
        .clone()
        .filter(|req| req.starts_with('/'))
        .unwrap_or_else(|| "/".to_string());
    let url = format!("{scheme}://{host}{path}");
    let client = if tls && target.skip_tls_verify {
        clients.insecure.as_ref()
    } else {
        clients.secure.as_ref()
    };
    let Some(client) = client else {
        return ProbeOutcome::Fail;
    };
    match client.get(&url).timeout(target.timeout).send() {
        Ok(mut response) => {
            let status = response.status().as_u16();
            if http_status_is_healthy(status, target.expected_status) {
                // Consume a bounded body to validate matching and permit connection reuse.
                use std::io::Read;
                let mut body = Vec::new();
                if response
                    .by_ref()
                    .take((MAX_RESPONSE_BYTES + 1) as u64)
                    .read_to_end(&mut body)
                    .is_err()
                    || body.len() > MAX_RESPONSE_BYTES
                {
                    return ProbeOutcome::Fail;
                }
                if target
                    .probe_resp
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .is_none_or(|expected| {
                        body.windows(expected.len())
                            .any(|bytes| bytes == expected.as_bytes())
                    })
                {
                    ProbeOutcome::Ok
                } else {
                    ProbeOutcome::Fail
                }
            } else {
                tracing::debug!("[probe] {url} returned status {status}");
                ProbeOutcome::Fail
            }
        }
        Err(e) => {
            tracing::debug!("[probe] {url} failed: {e}");
            ProbeOutcome::Fail
        }
    }
}

fn http_status_is_healthy(status: u16, expected: Option<u16>) -> bool {
    expected.map_or((200..400).contains(&status), |value| value == status)
}

fn tcp_connect(address: IpAddr, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addr = SocketAddr::new(address, port);
    let mut last_err = None;
    for resolved in addr
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("resolving {addr}: {e}"))?
    {
        match TcpStream::connect_timeout(&resolved, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(anyhow::anyhow!(
        "tcp connect to {addr} failed: {}",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no address".into())
    ))
}

/// Fold probe outcomes into observed target health and report how many
/// records transitioned (each record name counts once).
fn apply_results(
    cfg: &Config,
    outcomes: &[(&ProbeTarget, ProbeOutcome)],
    runtimes: &mut HashMap<String, ProbeRuntime>,
) -> usize {
    // One decision per probe target, applied to every protocol identity.
    let mut transitions = 0usize;
    let mut updates: Vec<(String, &'static str, u32)> = Vec::new();
    for (target, outcome) in outcomes {
        let runtime = runtimes.entry(names_key(&target.names)).or_default();
        let (next_state, failures) = match outcome {
            ProbeOutcome::Ok => {
                runtime.consecutive_failures = 0;
                ("ok", 0)
            }
            ProbeOutcome::Fail => {
                runtime.consecutive_failures = runtime.consecutive_failures.saturating_add(1);
                ("nok", runtime.consecutive_failures)
            }
        };
        for name in &target.names {
            if next_state != "nok" || failures >= target.retries {
                updates.push((name.clone(), next_state, failures));
            }
        }
    }
    let result = crate::provider::native::store::mutate_target_health(cfg, |targets| {
        for (name, next_state, _) in &updates {
            let Some(entry) = targets.iter_mut().find(|entry| &entry.name == name) else {
                continue;
            };
            if entry.current_state.as_deref() == Some(next_state) {
                continue;
            }
            tracing::info!(
                "[probe] target {name}: {} -> {next_state}",
                entry.current_state.as_deref().unwrap_or("unknown")
            );
            entry.current_state = Some(next_state.to_string());
            transitions += 1;
        }
    });
    if let Err(e) = result {
        tracing::warn!("[probe] persisting observed target health failed: {e:#}");
        return 0;
    }
    transitions
}

fn names_key(names: &[String]) -> String {
    names.first().cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BackendNode, BackendTarget, Config, FileConfig, Listener, Protocol, TargetGroup,
    };
    use std::path::PathBuf;

    fn local_probe(kind: &str, port: u16) -> ProbeTarget {
        ProbeTarget {
            names: vec!["test".to_string()],
            address: "127.0.0.1".parse().unwrap(),
            port,
            probe_type: kind.to_string(),
            probe_req: Some("health".to_string()),
            probe_resp: Some("healthy".to_string()),
            expected_status: None,
            skip_tls_verify: false,
            timeout: Duration::from_millis(500),
            period: Duration::from_secs(15),
            retries: 3,
        }
    }

    #[test]
    fn tcp_matching_spans_multiple_reads() {
        use std::io::{Read, Write};
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let target = local_probe("tcp", server.local_addr().unwrap().port());
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 6];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"health");
            stream.write_all(b"hea").unwrap();
            std::thread::sleep(Duration::from_millis(30));
            stream.write_all(b"lthy").unwrap();
        });
        assert_eq!(probe_tcp(&target), ProbeOutcome::Ok);
        thread.join().unwrap();
    }

    #[test]
    fn udp_silence_fails_only_when_a_response_is_required() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut target = local_probe("udp", server.local_addr().unwrap().port());
        target.timeout = Duration::from_millis(30);
        assert_eq!(probe_udp(&target), ProbeOutcome::Fail);
        target.probe_resp = None;
        assert_eq!(probe_udp(&target), ProbeOutcome::Ok);
    }

    #[test]
    fn http_uses_exact_path_status_and_response_body() {
        use std::io::{Read, Write};
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut target = local_probe("http", server.local_addr().unwrap().port());
        target.timeout = Duration::from_secs(2);
        target.probe_req = Some("/health?full=1".to_string());
        target.expected_status = Some(200);
        let thread = std::thread::spawn(move || {
            for body in ["healthy", "failure"] {
                let (mut stream, _) = server.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0; 1];
                while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                    stream.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                assert!(request.starts_with(b"GET /health?full=1 HTTP/1.1\r\n"));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{body}"
                )
                .unwrap();
            }
        });
        let clients = ProbeClients::new();
        assert_eq!(probe_http(&target, &clients, false), ProbeOutcome::Ok);
        assert_eq!(probe_http(&target, &clients, false), ProbeOutcome::Fail);
        thread.join().unwrap();
    }

    #[test]
    fn independent_probe_periods_and_config_changes_are_respected() {
        let now = Instant::now();
        let mut target = local_probe("tcp", 8080);
        let schedule = HashMap::from([("test".to_string(), (target.clone(), now + target.period))]);
        assert!(!probe_is_due(
            &schedule,
            "test",
            &target,
            now + Duration::from_secs(5)
        ));
        assert!(probe_is_due(
            &schedule,
            "test",
            &target,
            now + Duration::from_secs(15)
        ));
        target.probe_resp = Some("changed".to_string());
        assert!(probe_is_due(&schedule, "test", &target, now));
    }

    #[test]
    fn different_groups_never_share_runtime_identity() {
        let mut cfg = cfg_with_group(true, Some("tcp"));
        let mut group = cfg.file.target_groups[0].clone();
        group.name = "other".to_string();
        cfg.file.target_groups.push(group);
        let mut listener = cfg.file.listeners[0].clone();
        listener.name = "other".to_string();
        listener.target_group = "other".to_string();
        cfg.file.listeners.push(listener);
        let targets = scheduled_targets(&cfg);
        assert_eq!(targets.len(), 2);
        assert_ne!(names_key(&targets[0].names), names_key(&targets[1].names));
    }

    fn cfg_with_group(monitor: bool, probe_type: Option<&str>) -> Config {
        let group = TargetGroup {
            name: "web".to_string(),
            monitor,
            probe_type: probe_type.map(str::to_string),
            probe_port: None,
            probe_req: None,
            probe_resp: None,
            probe_status: None,
            probe_skip_tls_verify: false,
            period_secs: Some(5),
            retries: Some(2),
            targets: vec![BackendTarget {
                backend: None,
                address: "192.0.2.10".parse().unwrap(),
                weight: 1,
            }],
        };
        let listener = Listener {
            name: "web".to_string(),
            port: 80,
            target_port: 8080,
            target_group: "web".to_string(),
            protocols: vec![Protocol::Tcp],
            ..Listener::default()
        };
        let file = FileConfig {
            target_groups: vec![group],
            listeners: vec![listener],
            ..FileConfig::default()
        };
        Config {
            path: PathBuf::from("/tmp/edge-lb-probe-test.toml"),
            file,
        }
    }

    #[test]
    fn unsupported_probe_types_are_not_scheduled() {
        for probe in ["none", ""] {
            let cfg = cfg_with_group(true, if probe.is_empty() { None } else { Some(probe) });
            assert!(scheduled_targets(&cfg).is_empty(), "probe {probe:?}");
        }
    }

    #[test]
    fn ping_probe_is_scheduled_without_a_port() {
        let cfg = cfg_with_group(true, Some("ping"));
        let targets = scheduled_targets(&cfg);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].port, 0);
        assert_eq!(targets[0].probe_type, "ping");
    }

    #[test]
    fn unmonitored_groups_are_not_scheduled() {
        let cfg = cfg_with_group(false, Some("tcp"));
        assert!(scheduled_targets(&cfg).is_empty());
    }

    #[test]
    fn executable_target_uses_listener_protocol_identity() {
        let cfg = cfg_with_group(true, Some("http"));
        let targets = scheduled_targets(&cfg);
        assert_eq!(targets.len(), 1);
        let target = &targets[0];
        assert_eq!(target.probe_type, "http");
        assert_eq!(target.port, 8080, "probe port falls back to service port");
        assert_eq!(target.retries, 2);
        assert_eq!(target.period, Duration::from_secs(5));
        assert_eq!(
            target.names,
            vec![target_health_identity(
                "web",
                "192.0.2.10".parse().unwrap(),
                "tcp",
                8080
            )]
        );
    }

    #[test]
    fn probe_port_does_not_change_listener_target_identity() {
        let mut cfg = cfg_with_group(true, Some("http"));
        cfg.file.target_groups[0].probe_port = Some(9090);
        let targets = scheduled_targets(&cfg);
        assert_eq!(targets[0].port, 9090);
        assert_eq!(
            targets[0].names,
            vec![target_health_identity(
                "web",
                "192.0.2.10".parse().unwrap(),
                "tcp",
                8080
            )]
        );
    }

    #[test]
    fn monitored_backend_target_uses_same_service_address_for_probe_and_health() {
        let mut cfg = cfg_with_group(true, Some("tcp"));
        cfg.file.backend_nodes.push(BackendNode {
            name: "backend-1".to_string(),
            public_ip: "198.51.100.20".parse().unwrap(),
            underlay_ip: "192.0.2.20".parse().unwrap(),
            overlay_ip: "10.255.255.2/24".to_string(),
        });
        cfg.file.target_groups[0].targets[0] = BackendTarget {
            backend: Some("backend-1".to_string()),
            address: "192.0.2.20".parse().unwrap(),
            weight: 1,
        };

        let targets = scheduled_targets(&cfg);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].address, "192.0.2.20".parse::<IpAddr>().unwrap());
        assert_eq!(
            targets[0].names,
            vec![target_health_identity(
                "web",
                "192.0.2.20".parse().unwrap(),
                "tcp",
                8080
            )]
        );
    }

    #[test]
    fn multiple_listener_protocols_expand_to_one_name_each() {
        let mut cfg = cfg_with_group(true, Some("tcp"));
        cfg.file.listeners[0].protocols = vec![Protocol::Tcp, Protocol::Udp];
        let targets = scheduled_targets(&cfg);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].names.len(), 2);
    }

    #[test]
    fn unresolvable_auto_addresses_are_skipped() {
        let mut cfg = cfg_with_group(true, Some("tcp"));
        cfg.file.target_groups[0].targets[0].address = "0.0.0.0".parse().unwrap();
        assert!(scheduled_targets(&cfg).is_empty());
    }

    #[test]
    fn target_health_identity_matches_store_convention() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(
            target_health_identity("web", ip, "TCP", 8080),
            "web:192.0.2.10_tcp_8080"
        );
    }

    #[test]
    fn http_status_rule_accepts_success_redirects_by_default() {
        assert!(http_status_is_healthy(200, None));
        assert!(http_status_is_healthy(302, None));
        assert!(!http_status_is_healthy(199, None));
        assert!(!http_status_is_healthy(400, None));
    }

    #[test]
    fn http_status_rule_supports_exact_expected_status() {
        assert!(http_status_is_healthy(204, Some(204)));
        assert!(!http_status_is_healthy(200, Some(204)));
    }
}
