//! Local native flow-map snapshots for gateway restarts.

use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use edge_lb_common::{NativeFlowKey, NativeFlowValue};
use sha2::{Digest, Sha256};

use crate::{
    config::{Config, GatewayFlowPersistenceConfig},
    linux::native_dnat,
    provider::native::{NativeListener, listeners_from_config},
    runtime::shutdown,
};

const MAGIC: &[u8; 8] = b"ELBFLOW1";
const FORMAT_VERSION: u32 = 1;
const FLOW_MAP_ABI_VERSION: u32 = 1;
const CHECKSUM_LEN: usize = 32;
const RESTORE_BATCH_SIZE: usize = 4096;
const SNAPSHOT_FILE: &str = "native-flows.snapshot";

#[derive(Debug, Clone, Default)]
pub struct FlowPersistenceStatus {
    pub enabled: bool,
    pub snapshot_records: usize,
    pub snapshot_bytes: u64,
    pub snapshot_duration_ms: u64,
    pub snapshot_errors_total: u64,
    pub restore_records_total: u64,
    pub restore_skipped_expired_total: u64,
    pub restore_skipped_config_total: u64,
    pub restore_skipped_incomplete_total: u64,
    pub restore_duration_ms: u64,
    pub restore_errors_total: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SnapshotSummary {
    pub records: usize,
    pub bytes: u64,
    pub duration: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct RestoreSummary {
    pub restored_pairs: usize,
    pub skipped_expired: usize,
    pub skipped_config: usize,
    pub skipped_incomplete: usize,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
struct Snapshot {
    saved_at_unix_ns: u64,
    node_name: String,
    config_digest: [u8; 32],
    entries: Vec<SnapshotEntry>,
}

#[derive(Debug, Clone, Copy)]
struct SnapshotEntry {
    key: NativeFlowKey,
    value: NativeFlowValue,
    last_seen_age_ns: u64,
}

#[derive(Debug, Clone)]
struct SnapshotPair {
    forward_key: NativeFlowKey,
    reverse_key: NativeFlowKey,
    value: NativeFlowValue,
    last_seen_age_ns: u64,
}

pub fn spawn_worker(cfg: &Config) -> Result<Option<JoinHandle<()>>> {
    let settings = settings(cfg);
    set_status(|status| status.enabled = settings.enabled);
    if !settings.enabled {
        return Ok(None);
    }
    let interval = Duration::from_secs(settings.interval_secs.max(5));
    let cfg = cfg.clone();
    let handle = std::thread::Builder::new()
        .name("edge-lb-flow-persist".to_string())
        .stack_size(1024 * 1024)
        .spawn(move || {
            tracing::info!(
                "[flow-persist] native flow snapshots enabled interval={}s max_records={}",
                interval.as_secs(),
                settings.max_records
            );
            while !shutdown::requested() {
                std::thread::sleep(interval);
                if shutdown::requested() {
                    break;
                }
                if let Err(error) = write_snapshot(&cfg) {
                    set_status(|status| {
                        status.snapshot_errors_total =
                            status.snapshot_errors_total.saturating_add(1);
                    });
                    tracing::warn!("[flow-persist] snapshot failed: {error:#}");
                }
            }
        })
        .context("spawning native flow persistence worker")?;
    Ok(Some(handle))
}

pub fn restore_on_start(cfg: &Config) -> Result<Option<RestoreSummary>> {
    let settings = settings(cfg);
    set_status(|status| status.enabled = settings.enabled);
    if !settings.enabled || !settings.restore_on_start {
        return Ok(None);
    }
    if !is_active_gateway(cfg) {
        tracing::debug!("[flow-persist] delaying native flow restore until this gateway is active");
        return Ok(None);
    }
    let path = snapshot_path(cfg);
    if !path.exists() {
        tracing::debug!(
            "[flow-persist] no native flow snapshot at {}",
            path.display()
        );
        return Ok(None);
    }
    if !has_restore_candidates(cfg)? {
        tracing::debug!(
            "[flow-persist] delaying native flow restore until listener targets are available"
        );
        return Ok(None);
    }
    match restore_from_path(cfg, &path) {
        Ok(summary) => {
            set_status(|status| {
                status.restore_records_total = status
                    .restore_records_total
                    .saturating_add(summary.restored_pairs as u64);
                status.restore_skipped_expired_total = status
                    .restore_skipped_expired_total
                    .saturating_add(summary.skipped_expired as u64);
                status.restore_skipped_config_total = status
                    .restore_skipped_config_total
                    .saturating_add(summary.skipped_config as u64);
                status.restore_skipped_incomplete_total = status
                    .restore_skipped_incomplete_total
                    .saturating_add(summary.skipped_incomplete as u64);
                status.restore_duration_ms = millis(summary.duration);
            });
            tracing::info!(
                "[flow-persist] restored {} native flow pair(s), skipped expired={} config={} incomplete={} in {}ms",
                summary.restored_pairs,
                summary.skipped_expired,
                summary.skipped_config,
                summary.skipped_incomplete,
                millis(summary.duration)
            );
            Ok(Some(summary))
        }
        Err(error) => {
            set_status(|status| {
                status.restore_errors_total = status.restore_errors_total.saturating_add(1);
            });
            Err(error)
        }
    }
}

fn has_restore_candidates(cfg: &Config) -> Result<bool> {
    let mut runtime_cfg = cfg.clone();
    crate::provider::native::hydrate_proxy_config_from_api(&mut runtime_cfg)
        .context("loading canonical proxy configuration for flow restore preflight")?;
    Ok(!listeners_from_config(&runtime_cfg)?.is_empty())
}

pub fn flush_on_shutdown(cfg: &Config) {
    let settings = settings(cfg);
    if !settings.enabled || !settings.flush_on_shutdown {
        return;
    }
    match write_snapshot(cfg) {
        Ok(Some(summary)) => tracing::info!(
            "[flow-persist] shutdown snapshot wrote {} flow pair(s), {} bytes in {}ms",
            summary.records,
            summary.bytes,
            millis(summary.duration)
        ),
        Ok(None) => {}
        Err(error) => {
            set_status(|status| {
                status.snapshot_errors_total = status.snapshot_errors_total.saturating_add(1);
            });
            tracing::warn!("[flow-persist] shutdown snapshot failed: {error:#}");
        }
    }
}

pub fn write_snapshot(cfg: &Config) -> Result<Option<SnapshotSummary>> {
    let settings = settings(cfg);
    set_status(|status| status.enabled = settings.enabled);
    if !settings.enabled {
        return Ok(None);
    }
    let started = Instant::now();
    let mut runtime_cfg = cfg.clone();
    crate::provider::native::hydrate_proxy_config_from_api(&mut runtime_cfg)
        .context("loading canonical proxy configuration for flow snapshot")?;
    let listeners = listeners_from_config(&runtime_cfg)?;
    let flows = native_dnat::dump_flows(&runtime_cfg)?;
    let now_mono_ns = native_dnat::monotonic_now_ns();
    let pairs = collect_snapshot_pairs(&flows, now_mono_ns, &settings);
    let digest = config_digest(&listeners)?;
    let snapshot = Snapshot {
        saved_at_unix_ns: unix_now_ns(),
        node_name: runtime_cfg.node_name.clone(),
        config_digest: digest,
        entries: snapshot_entries_from_pairs(&pairs),
    };
    let path = snapshot_path(&runtime_cfg);
    if pairs.is_empty() && path.exists() {
        let summary = SnapshotSummary {
            records: 0,
            bytes: fs::metadata(&path)
                .map(|meta| meta.len())
                .unwrap_or_default(),
            duration: started.elapsed(),
        };
        set_status(|status| {
            status.snapshot_records = summary.records;
            status.snapshot_bytes = summary.bytes;
            status.snapshot_duration_ms = millis(summary.duration);
        });
        tracing::debug!(
            "[flow-persist] keeping existing native flow snapshot because current flow map is empty"
        );
        return Ok(Some(summary));
    }
    let bytes = encode_snapshot(&snapshot)?;
    write_atomic(&path, &bytes)?;
    let summary = SnapshotSummary {
        records: pairs.len(),
        bytes: bytes.len() as u64,
        duration: started.elapsed(),
    };
    set_status(|status| {
        status.snapshot_records = summary.records;
        status.snapshot_bytes = summary.bytes;
        status.snapshot_duration_ms = millis(summary.duration);
    });
    tracing::debug!(
        "[flow-persist] snapshot wrote {} flow pair(s), {} bytes in {}ms",
        summary.records,
        summary.bytes,
        summary.snapshot_duration_ms()
    );
    Ok(Some(summary))
}

pub fn status() -> FlowPersistenceStatus {
    status_cell()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
}

fn restore_from_path(cfg: &Config, path: &Path) -> Result<RestoreSummary> {
    let started = Instant::now();
    let snapshot = read_snapshot(path)?;
    let mut runtime_cfg = cfg.clone();
    crate::provider::native::hydrate_proxy_config_from_api(&mut runtime_cfg)
        .context("loading canonical proxy configuration for flow restore")?;
    let listeners = listeners_from_config(&runtime_cfg)?;
    let current_digest = config_digest(&listeners)?;
    if current_digest != snapshot.config_digest {
        tracing::debug!(
            "[flow-persist] snapshot config digest differs; restoring only matching listener/target endpoints"
        );
    }
    if snapshot.node_name != runtime_cfg.node_name {
        tracing::debug!(
            "[flow-persist] snapshot node {} differs from local node {}; restoring by local config",
            snapshot.node_name,
            runtime_cfg.node_name
        );
    }
    let listener_index = ListenerRestoreIndex::new(&listeners)?;
    let elapsed_ns = unix_elapsed_ns(snapshot.saved_at_unix_ns, unix_now_ns());
    let pairs = collect_restore_pairs(&snapshot.entries);
    let mut summary = RestoreSummary::default();
    let mut restore_entries = Vec::new();
    for pair in pairs {
        let Some(pair) = pair else {
            summary.skipped_incomplete += 1;
            continue;
        };
        let restored_age = pair.last_seen_age_ns.saturating_add(elapsed_ns);
        if flow_age_expired(restored_age, pair.value.timeout_secs) {
            summary.skipped_expired += 1;
            continue;
        }
        let Some(value) = remap_value(pair.value, restored_age, pair.forward_key, &listener_index)
        else {
            summary.skipped_config += 1;
            continue;
        };
        let forward_key = pair.forward_key;
        let reverse_key = forward_key.reverse_for(value);
        restore_entries.push((forward_key, value));
        restore_entries.push((reverse_key, value));
        summary.restored_pairs += 1;
    }
    for chunk in restore_entries.chunks(RESTORE_BATCH_SIZE) {
        native_dnat::upsert_flows(&runtime_cfg, chunk)?;
    }
    native_dnat::sweep_flows_and_refresh_loads(&runtime_cfg)?;
    summary.duration = started.elapsed();
    Ok(summary)
}

fn settings(cfg: &Config) -> GatewayFlowPersistenceConfig {
    cfg.gateway.flow_persistence.clone().unwrap_or_default()
}

fn is_active_gateway(cfg: &Config) -> bool {
    cfg.active_gateway()
        .map(|gateway| gateway.name == cfg.node_name || gateway.underlay_ip == cfg.underlay_ip)
        .unwrap_or(true)
}

fn snapshot_path(cfg: &Config) -> PathBuf {
    cfg.state_dir.join(SNAPSHOT_FILE)
}

fn collect_snapshot_pairs(
    flows: &[(NativeFlowKey, NativeFlowValue)],
    now_ns: u64,
    settings: &GatewayFlowPersistenceConfig,
) -> Vec<SnapshotPair> {
    let min_remaining_ns = settings
        .min_remaining_ttl_secs
        .saturating_mul(1_000_000_000);
    let mut groups: HashMap<(NativeFlowKey, NativeFlowKey), Vec<SnapshotEntry>> = HashMap::new();
    for (key, value) in flows {
        let age = flow_age(value.last_seen_ns, now_ns);
        if remaining_ttl_ns(age, value.timeout_secs).is_some_and(|ttl| ttl < min_remaining_ns) {
            continue;
        }
        let pair_key = native_dnat::canonical_flow_pair(*key, *value);
        groups.entry(pair_key).or_default().push(SnapshotEntry {
            key: *key,
            value: *value,
            last_seen_age_ns: age,
        });
    }
    let mut pairs = groups
        .into_iter()
        .filter_map(|((left, right), entries)| pair_from_entries(left, right, &entries))
        .collect::<Vec<_>>();
    pairs.sort_by_key(|pair| pair.last_seen_age_ns);
    pairs.truncate(settings.max_records);
    pairs
}

fn snapshot_entries_from_pairs(pairs: &[SnapshotPair]) -> Vec<SnapshotEntry> {
    pairs
        .iter()
        .flat_map(|pair| {
            [
                SnapshotEntry {
                    key: pair.forward_key,
                    value: pair.value,
                    last_seen_age_ns: pair.last_seen_age_ns,
                },
                SnapshotEntry {
                    key: pair.reverse_key,
                    value: pair.value,
                    last_seen_age_ns: pair.last_seen_age_ns,
                },
            ]
        })
        .collect()
}

fn collect_restore_pairs(entries: &[SnapshotEntry]) -> Vec<Option<SnapshotPair>> {
    let mut groups: HashMap<(NativeFlowKey, NativeFlowKey), Vec<SnapshotEntry>> = HashMap::new();
    for entry in entries {
        let pair_key = native_dnat::canonical_flow_pair(entry.key, entry.value);
        groups.entry(pair_key).or_default().push(*entry);
    }
    groups
        .into_iter()
        .map(|((left, right), entries)| pair_from_entries(left, right, &entries))
        .collect()
}

fn pair_from_entries(
    left: NativeFlowKey,
    right: NativeFlowKey,
    entries: &[SnapshotEntry],
) -> Option<SnapshotPair> {
    if left == right {
        return None;
    }
    let has_left = entries.iter().any(|entry| entry.key == left);
    let has_right = entries.iter().any(|entry| entry.key == right);
    if !has_left || !has_right {
        return None;
    }
    let entry = entries
        .iter()
        .min_by_key(|entry| entry.last_seen_age_ns)
        .copied()?;
    let (forward_key, reverse_key) = forward_reverse_keys(entry.key, entry.value);
    Some(SnapshotPair {
        forward_key,
        reverse_key,
        value: entry.value,
        last_seen_age_ns: entry.last_seen_age_ns,
    })
}

fn forward_reverse_keys(
    key: NativeFlowKey,
    value: NativeFlowValue,
) -> (NativeFlowKey, NativeFlowKey) {
    if key.src == value.target && key.sport == value.target_port.to_be() {
        (key.forward_for(value), key)
    } else {
        (key, key.reverse_for(value))
    }
}

#[derive(Clone, Copy)]
struct ListenerRuntimeRef<'a> {
    listener_id: u32,
    listener: &'a NativeListener,
}

struct ListenerRestoreIndex<'a> {
    by_id: HashMap<u32, ListenerRuntimeRef<'a>>,
    by_socket: HashMap<(u32, u16, u8), ListenerRuntimeRef<'a>>,
}

impl<'a> ListenerRestoreIndex<'a> {
    fn new(listeners: &'a [NativeListener]) -> Result<Self> {
        let mut by_id = HashMap::new();
        let mut by_socket = HashMap::new();
        for (listener_id, listener) in native_dnat::stable_listener_assignments(listeners)? {
            let entry = ListenerRuntimeRef {
                listener_id,
                listener,
            };
            by_id.insert(listener_id, entry);
            by_socket.insert(
                (
                    ipv4_to_u32(listener.key.vip_ip),
                    listener.key.vip_port.to_be(),
                    listener.key.protocol.ip_proto(),
                ),
                entry,
            );
        }
        Ok(Self { by_id, by_socket })
    }

    fn get(
        &self,
        old_listener_id: u32,
        forward_key: NativeFlowKey,
        value: NativeFlowValue,
    ) -> Option<ListenerRuntimeRef<'a>> {
        if let Some(entry) = self.by_id.get(&old_listener_id).copied()
            && listener_matches(entry.listener, forward_key, value)
        {
            return Some(entry);
        }
        self.by_socket
            .get(&(value.vip, value.vip_port, forward_key.proto))
            .copied()
            .filter(|entry| listener_matches(entry.listener, forward_key, value))
    }
}

fn listener_matches(
    listener: &NativeListener,
    forward_key: NativeFlowKey,
    value: NativeFlowValue,
) -> bool {
    ipv4_to_u32(listener.key.vip_ip) == value.vip
        && listener.key.vip_port.to_be() == value.vip_port
        && forward_key.dst == value.vip
        && forward_key.dport == value.vip_port
        && forward_key.proto == listener.key.protocol.ip_proto()
}

fn remap_value(
    value: NativeFlowValue,
    restored_age_ns: u64,
    forward_key: NativeFlowKey,
    listeners: &ListenerRestoreIndex<'_>,
) -> Option<NativeFlowValue> {
    let listener = listeners.get(value.listener_id, forward_key, value)?;
    let target_id = listener
        .listener
        .targets
        .iter()
        .position(|target| {
            ipv4_to_u32(target.address) == value.target && target.port == value.target_port
        })
        .or_else(|| {
            let target_id = usize::try_from(value.target_id).ok()?;
            let target = listener.listener.targets.get(target_id)?;
            (target.port == value.target_port).then_some(target_id)
        })?;
    let target = listener.listener.targets.get(target_id)?;
    Some(NativeFlowValue {
        listener_id: listener.listener_id,
        target_id: target_id as u32,
        target: ipv4_to_u32(target.address),
        target_port: target.port,
        last_seen_ns: native_dnat::monotonic_now_ns().saturating_sub(restored_age_ns),
        ..value
    })
}

fn encode_snapshot(snapshot: &Snapshot) -> Result<Vec<u8>> {
    if snapshot.node_name.len() > u16::MAX as usize {
        bail!("node name too long for flow snapshot");
    }
    if snapshot.entries.len() > u32::MAX as usize {
        bail!("too many flow entries for flow snapshot");
    }
    let mut out = Vec::with_capacity(128 + snapshot.entries.len() * 48 + CHECKSUM_LEN);
    out.extend_from_slice(MAGIC);
    put_u32(&mut out, FORMAT_VERSION);
    put_u32(&mut out, FLOW_MAP_ABI_VERSION);
    put_u64(&mut out, snapshot.saved_at_unix_ns);
    put_u16(&mut out, snapshot.node_name.len() as u16);
    out.extend_from_slice(snapshot.node_name.as_bytes());
    out.extend_from_slice(&snapshot.config_digest);
    put_u32(&mut out, snapshot.entries.len() as u32);
    for entry in &snapshot.entries {
        encode_entry(&mut out, *entry);
    }
    let checksum = Sha256::digest(&out);
    out.extend_from_slice(&checksum);
    Ok(out)
}

fn read_snapshot(path: &Path) -> Result<Snapshot> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    decode_snapshot(&bytes).with_context(|| format!("parsing {}", path.display()))
}

fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot> {
    if bytes.len() < MAGIC.len() + CHECKSUM_LEN {
        bail!("flow snapshot is too short");
    }
    let payload_len = bytes.len() - CHECKSUM_LEN;
    let expected = Sha256::digest(&bytes[..payload_len]);
    if expected.as_slice() != &bytes[payload_len..] {
        bail!("flow snapshot checksum mismatch");
    }
    let mut input = Cursor::new(&bytes[..payload_len]);
    input.expect(MAGIC)?;
    let version = input.u32()?;
    if version != FORMAT_VERSION {
        bail!("unsupported flow snapshot version {version}");
    }
    let abi = input.u32()?;
    if abi != FLOW_MAP_ABI_VERSION {
        bail!("unsupported flow map ABI version {abi}");
    }
    let saved_at_unix_ns = input.u64()?;
    let node_len = input.u16()? as usize;
    let node_name = String::from_utf8(input.bytes(node_len)?.to_vec())
        .context("flow snapshot node name is not UTF-8")?;
    let mut config_digest = [0u8; 32];
    config_digest.copy_from_slice(input.bytes(32)?);
    let entry_count = input.u32()? as usize;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        entries.push(decode_entry(&mut input)?);
    }
    input.finish()?;
    Ok(Snapshot {
        saved_at_unix_ns,
        node_name,
        config_digest,
        entries,
    })
}

fn encode_entry(out: &mut Vec<u8>, entry: SnapshotEntry) {
    put_u32(out, entry.key.src);
    put_u32(out, entry.key.dst);
    put_u16(out, entry.key.sport);
    put_u16(out, entry.key.dport);
    out.push(entry.key.proto);
    put_u32(out, entry.value.listener_id);
    put_u32(out, entry.value.target_id);
    put_u32(out, entry.value.vip);
    put_u32(out, entry.value.target);
    put_u16(out, entry.value.vip_port);
    put_u16(out, entry.value.target_port);
    put_u32(out, entry.value.timeout_secs);
    put_u64(out, entry.last_seen_age_ns);
}

fn decode_entry(input: &mut Cursor<'_>) -> Result<SnapshotEntry> {
    let key = NativeFlowKey {
        src: input.u32()?,
        dst: input.u32()?,
        sport: input.u16()?,
        dport: input.u16()?,
        proto: input.u8()?,
        _pad: [0; 3],
    };
    let value = NativeFlowValue {
        listener_id: input.u32()?,
        target_id: input.u32()?,
        vip: input.u32()?,
        target: input.u32()?,
        vip_port: input.u16()?,
        target_port: input.u16()?,
        timeout_secs: input.u32()?,
        last_seen_ns: 0,
    };
    Ok(SnapshotEntry {
        key,
        value,
        last_seen_age_ns: input.u64()?,
    })
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("snapshot.tmp");
    {
        let mut file = File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    if let Some(parent) = path.parent()
        && let Ok(dir) = File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn config_digest(listeners: &[NativeListener]) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    for (listener_id, listener) in native_dnat::stable_listener_assignments(listeners)? {
        put_digest_u32(&mut hasher, listener_id);
        put_digest_u32(&mut hasher, ipv4_to_u32(listener.key.vip_ip));
        put_digest_u16(&mut hasher, listener.key.vip_port);
        hasher.update([listener.key.protocol.ip_proto()]);
        put_digest_u32(&mut hasher, listener.targets.len() as u32);
        for target in &listener.targets {
            put_digest_u32(&mut hasher, ipv4_to_u32(target.address));
            put_digest_u16(&mut hasher, target.port);
        }
    }
    Ok(hasher.finalize().into())
}

fn flow_age(last_seen_ns: u64, now_ns: u64) -> u64 {
    if last_seen_ns == 0 {
        0
    } else {
        now_ns.saturating_sub(last_seen_ns)
    }
}

fn remaining_ttl_ns(age_ns: u64, timeout_secs: u32) -> Option<u64> {
    if timeout_secs == 0 {
        return None;
    }
    Some(
        u64::from(timeout_secs)
            .saturating_mul(1_000_000_000)
            .saturating_sub(age_ns),
    )
}

fn flow_age_expired(age_ns: u64, timeout_secs: u32) -> bool {
    timeout_secs != 0 && age_ns >= u64::from(timeout_secs).saturating_mul(1_000_000_000)
}

fn unix_elapsed_ns(saved_at: u64, now: u64) -> u64 {
    now.saturating_sub(saved_at)
}

fn unix_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| {
            duration
                .as_secs()
                .saturating_mul(1_000_000_000)
                .saturating_add(u64::from(duration.subsec_nanos()))
        })
        .unwrap_or_default()
}

fn ipv4_to_u32(value: Ipv4Addr) -> u32 {
    u32::from_be_bytes(value.octets())
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_digest_u16(hasher: &mut Sha256, value: u16) {
    hasher.update(value.to_le_bytes());
}

fn put_digest_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

impl SnapshotSummary {
    fn snapshot_duration_ms(&self) -> u64 {
        millis(self.duration)
    }
}

fn set_status(update: impl FnOnce(&mut FlowPersistenceStatus)) {
    let mut status = status_cell()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    update(&mut status);
}

fn status_cell() -> &'static Mutex<FlowPersistenceStatus> {
    static STATUS: OnceLock<Mutex<FlowPersistenceStatus>> = OnceLock::new();
    STATUS.get_or_init(|| Mutex::new(FlowPersistenceStatus::default()))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<()> {
        let actual = self.bytes(expected.len())?;
        if actual != expected {
            bail!("bad flow snapshot magic");
        }
        Ok(())
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| anyhow!("flow snapshot offset overflow"))?;
        if end > self.bytes.len() {
            bail!("truncated flow snapshot");
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(*self
            .bytes(1)?
            .first()
            .ok_or_else(|| anyhow!("truncated flow snapshot"))?)
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self.bytes(2)?.try_into().unwrap();
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.bytes(4)?.try_into().unwrap();
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.bytes(8)?.try_into().unwrap();
        Ok(u64::from_le_bytes(bytes))
    }

    fn finish(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            bail!("flow snapshot has trailing bytes");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::provider::native::{NativeListenerKey, NativeProtocol, NativeTarget};

    use super::*;

    fn flow_entry(source_port: u16, last_seen_ns: u64) -> (NativeFlowKey, NativeFlowValue) {
        let key = NativeFlowKey {
            src: ipv4_to_u32(Ipv4Addr::new(198, 51, 100, 10)),
            dst: ipv4_to_u32(Ipv4Addr::new(192, 0, 2, 10)),
            sport: source_port.to_be(),
            dport: 5060u16.to_be(),
            proto: 17,
            _pad: [0; 3],
        };
        let value = NativeFlowValue {
            listener_id: 7,
            target_id: 0,
            vip: key.dst,
            target: ipv4_to_u32(Ipv4Addr::new(192, 0, 2, 20)),
            vip_port: 5060u16.to_be(),
            target_port: 5060,
            timeout_secs: 240,
            last_seen_ns,
        };
        (key, value)
    }

    #[test]
    fn snapshot_round_trip_preserves_age_not_monotonic_time() {
        let (key, value) = flow_entry(40000, 90);
        let snapshot = Snapshot {
            saved_at_unix_ns: 1_000,
            node_name: "gateway-a".to_string(),
            config_digest: [9; 32],
            entries: vec![SnapshotEntry {
                key,
                value,
                last_seen_age_ns: 10,
            }],
        };
        let bytes = encode_snapshot(&snapshot).unwrap();
        let decoded = decode_snapshot(&bytes).unwrap();
        assert_eq!(decoded.saved_at_unix_ns, 1_000);
        assert_eq!(decoded.node_name, "gateway-a");
        assert_eq!(decoded.config_digest, [9; 32]);
        assert_eq!(decoded.entries[0].key, key);
        assert_eq!(decoded.entries[0].value.last_seen_ns, 0);
        assert_eq!(decoded.entries[0].last_seen_age_ns, 10);
    }

    #[test]
    fn snapshot_collection_requires_complete_flow_pair() {
        let (forward, value) = flow_entry(40000, 90);
        let settings = GatewayFlowPersistenceConfig {
            enabled: true,
            max_records: 100,
            ..GatewayFlowPersistenceConfig::default()
        };
        assert!(
            collect_snapshot_pairs(&[(forward, value)], 100, &settings).is_empty(),
            "single-sided NAT state must not be persisted"
        );
        let reverse = forward.reverse_for(value);
        let pairs = collect_snapshot_pairs(&[(forward, value), (reverse, value)], 100, &settings);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].forward_key, forward);
        assert_eq!(pairs[0].reverse_key, reverse);
        assert_eq!(pairs[0].last_seen_age_ns, 10);
    }

    #[test]
    fn expired_and_nearly_expired_flows_are_not_snapshotted() {
        let (forward, value) = flow_entry(40000, 1);
        let reverse = forward.reverse_for(value);
        let settings = GatewayFlowPersistenceConfig {
            enabled: true,
            min_remaining_ttl_secs: 5,
            max_records: 100,
            ..GatewayFlowPersistenceConfig::default()
        };
        let now = 236 * 1_000_000_000;
        assert!(
            collect_snapshot_pairs(&[(forward, value), (reverse, value)], now, &settings)
                .is_empty()
        );
    }

    #[test]
    fn elapsed_wall_time_ages_snapshot_records() {
        assert_eq!(unix_elapsed_ns(100, 90), 0);
        assert_eq!(unix_elapsed_ns(100, 175), 75);
        assert!(flow_age_expired(240_000_000_000, 240));
        assert!(!flow_age_expired(239_999_999_999, 240));
    }

    #[test]
    fn restore_remaps_target_id_from_current_endpoint_order() {
        let (forward, value) = flow_entry(40000, 90);
        let listener = NativeListener {
            name: "sip".to_string(),
            target_group: "sip-targets".to_string(),
            key: NativeListenerKey {
                vip_ip: Ipv4Addr::new(192, 0, 2, 10),
                vip_port: 5060,
                protocol: NativeProtocol::Udp,
            },
            select: 0,
            inactive_timeout_secs: 240,
            dscp: 46,
            targets: vec![
                NativeTarget {
                    address: Ipv4Addr::new(192, 0, 2, 21),
                    port: 5060,
                    weight: 1,
                    state: Default::default(),
                },
                NativeTarget {
                    address: Ipv4Addr::new(192, 0, 2, 20),
                    port: 5060,
                    weight: 1,
                    state: Default::default(),
                },
            ],
        };
        let listeners = ListenerRestoreIndex {
            by_id: HashMap::from([(
                7,
                ListenerRuntimeRef {
                    listener_id: 7,
                    listener: &listener,
                },
            )]),
            by_socket: HashMap::new(),
        };

        let remapped = remap_value(value, 10, forward, &listeners).unwrap();
        assert_eq!(remapped.target_id, 1);
        assert_eq!(remapped.target, ipv4_to_u32(Ipv4Addr::new(192, 0, 2, 20)));
    }

    #[test]
    fn restore_remaps_cross_gateway_target_address_by_target_id() {
        let (forward, mut value) = flow_entry(40000, 90);
        value.target_id = 1;
        value.target = ipv4_to_u32(Ipv4Addr::new(10, 255, 15, 3));
        let listener = NativeListener {
            name: "sip".to_string(),
            target_group: "sip-targets".to_string(),
            key: NativeListenerKey {
                vip_ip: Ipv4Addr::new(192, 0, 2, 10),
                vip_port: 5060,
                protocol: NativeProtocol::Udp,
            },
            select: 0,
            inactive_timeout_secs: 240,
            dscp: 46,
            targets: vec![
                NativeTarget {
                    address: Ipv4Addr::new(10, 255, 16, 2),
                    port: 5060,
                    weight: 1,
                    state: Default::default(),
                },
                NativeTarget {
                    address: Ipv4Addr::new(10, 255, 16, 3),
                    port: 5060,
                    weight: 1,
                    state: Default::default(),
                },
            ],
        };
        let listeners = ListenerRestoreIndex {
            by_id: HashMap::from([(
                7,
                ListenerRuntimeRef {
                    listener_id: 7,
                    listener: &listener,
                },
            )]),
            by_socket: HashMap::new(),
        };

        let remapped = remap_value(value, 10, forward, &listeners).unwrap();
        assert_eq!(remapped.target_id, 1);
        assert_eq!(remapped.target, ipv4_to_u32(Ipv4Addr::new(10, 255, 16, 3)));
        assert_eq!(remapped.target_port, 5060);
    }

    #[test]
    fn restore_rejects_protocol_mismatch_even_when_listener_id_matches() {
        let (forward, value) = flow_entry(40000, 90);
        let listener = NativeListener {
            name: "sip".to_string(),
            target_group: "sip-targets".to_string(),
            key: NativeListenerKey {
                vip_ip: Ipv4Addr::new(192, 0, 2, 10),
                vip_port: 5060,
                protocol: NativeProtocol::Tcp,
            },
            select: 0,
            inactive_timeout_secs: 240,
            dscp: 46,
            targets: vec![NativeTarget {
                address: Ipv4Addr::new(192, 0, 2, 20),
                port: 5060,
                weight: 1,
                state: Default::default(),
            }],
        };
        let listeners = ListenerRestoreIndex {
            by_id: HashMap::from([(
                7,
                ListenerRuntimeRef {
                    listener_id: 7,
                    listener: &listener,
                },
            )]),
            by_socket: HashMap::new(),
        };

        assert!(remap_value(value, 10, forward, &listeners).is_none());
    }

    #[test]
    fn restore_can_remap_listener_id_from_socket_identity() {
        let (forward, mut value) = flow_entry(40000, 90);
        value.listener_id = 99;
        let listener = NativeListener {
            name: "sip".to_string(),
            target_group: "sip-targets".to_string(),
            key: NativeListenerKey {
                vip_ip: Ipv4Addr::new(192, 0, 2, 10),
                vip_port: 5060,
                protocol: NativeProtocol::Udp,
            },
            select: 0,
            inactive_timeout_secs: 240,
            dscp: 46,
            targets: vec![NativeTarget {
                address: Ipv4Addr::new(192, 0, 2, 20),
                port: 5060,
                weight: 1,
                state: Default::default(),
            }],
        };
        let listeners = ListenerRestoreIndex {
            by_id: HashMap::new(),
            by_socket: HashMap::from([(
                (value.vip, value.vip_port, forward.proto),
                ListenerRuntimeRef {
                    listener_id: 7,
                    listener: &listener,
                },
            )]),
        };

        let remapped = remap_value(value, 10, forward, &listeners).unwrap();
        assert_eq!(remapped.listener_id, 7);
        assert_eq!(remapped.target_id, 0);
    }
}
