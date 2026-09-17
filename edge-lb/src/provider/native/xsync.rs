//! Native persistent connection-state replication channel.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tokio::{sync::mpsc, time::timeout};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, transport::Endpoint};

use crate::{
    config::Config,
    control::pb::{self, flow_sync_client::FlowSyncClient},
    linux::native_dnat,
    runtime::{ha, shutdown},
};

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const PENDING_FLUSH_INTERVAL: Duration = Duration::from_millis(50);
const RECONCILE_RECOVERY_INTERVAL: Duration = Duration::from_secs(2);
const RECONCILE_HEALTHY_INTERVAL: Duration = Duration::from_secs(10);
const RECONCILE_RECOVERY_ROUNDS: u8 = 3;
const MAX_SYNC_OPS_PER_BATCH: usize = 4096;

#[derive(Debug, Clone, serde::Serialize)]
pub struct XsyncStatus {
    pub state: String,
    pub peer: Option<String>,
    pub last_error: Option<String>,
    pub last_ack_applied: usize,
}

static STATUS: OnceLock<Mutex<XsyncStatus>> = OnceLock::new();

fn status() -> &'static Mutex<XsyncStatus> {
    STATUS.get_or_init(|| {
        Mutex::new(XsyncStatus {
            state: "disabled".to_string(),
            peer: None,
            last_error: None,
            last_ack_applied: 0,
        })
    })
}

pub fn snapshot() -> XsyncStatus {
    status()
        .lock()
        .expect("xsync status mutex poisoned")
        .clone()
}

/// gRPC implementation of the gateway-to-gateway xSync stream.
pub async fn replicate(
    cfg: &Config,
    request: Request<tonic::Streaming<pb::FlowSyncRequest>>,
) -> std::result::Result<
    Response<ReceiverStream<std::result::Result<pb::FlowSyncResponse, Status>>>,
    Status,
> {
    let remote = request.remote_addr();
    let mut inbound = request.into_inner();
    let first = inbound
        .message()
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::invalid_argument("missing flow sync request"))?;
    authorize_proto_request(cfg, remote, &first)
        .map_err(|e| Status::permission_denied(e.to_string()))?;
    let (tx, rx) = mpsc::channel(4);
    let cfg = cfg.clone();
    tokio::spawn(async move {
        let mut current = Some(first);
        loop {
            let request = match current.take() {
                Some(request) => request,
                None => match inbound.message().await {
                    Ok(Some(request)) => request,
                    Ok(None) | Err(_) => break,
                },
            };
            if let Err(error) = authorize_proto_request(&cfg, remote, &request) {
                let _ = tx
                    .send(Err(Status::permission_denied(error.to_string())))
                    .await;
                break;
            }
            let applied = match apply_proto_request(&cfg, &request) {
                Ok(value) => value,
                Err(error) => {
                    let _ = tx.send(Err(Status::internal(error.to_string()))).await;
                    break;
                }
            };
            set_ack(applied);
            if tx
                .send(Ok(pb::FlowSyncResponse {
                    applied: applied as u64,
                }))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    set_state("connected", remote.map(|value| value.to_string()), None);
    Ok(Response::new(ReceiverStream::new(rx)))
}

fn authorize_proto_request(
    cfg: &Config,
    source: Option<std::net::SocketAddr>,
    request: &pb::FlowSyncRequest,
) -> Result<()> {
    let source = source.context("missing flow sync peer address")?;
    let state_dir = Path::new(&*cfg.state_dir);
    let ha_cfg = ha::load_for_state_dir(state_dir)?;
    let peer = ha_cfg
        .peers
        .first()
        .context("xsync peer is not configured")?;
    let peer_ip = peer
        .underlay_ip
        .parse::<std::net::IpAddr>()
        .context("bad xsync peer address")?;
    if source.ip() != peer_ip {
        bail!(
            "xsync source {} is not configured peer {}",
            source.ip(),
            peer_ip
        );
    }
    if request.source != peer.name {
        bail!(
            "xsync source {:?} does not match configured peer {:?}",
            request.source,
            peer.name
        );
    }
    if !ha::session_token_matches(state_dir, &request.token)? {
        bail!("authentication failed for {}", request.source);
    }
    if crate::provider::native::ha::state(cfg)?.state == "MASTER" {
        bail!("MASTER gateway refuses replicated flow state");
    }
    Ok(())
}

fn apply_proto_request(cfg: &Config, request: &pb::FlowSyncRequest) -> Result<usize> {
    let entries = request
        .entries
        .iter()
        .map(entry_from_proto)
        .collect::<Result<Vec<_>>>()?;
    let deletes = request
        .deletes
        .iter()
        .map(key_from_proto)
        .collect::<Result<Vec<_>>>()?;
    Ok(native_dnat::upsert_flows(cfg, &entries)? + native_dnat::delete_flows(cfg, &deletes)?)
}

fn key_to_proto(key: &edge_lb_common::NativeFlowKey) -> pb::FlowKey {
    pb::FlowKey {
        src: key.src,
        dst: key.dst,
        sport: u32::from(key.sport),
        dport: u32::from(key.dport),
        proto: u32::from(key.proto),
    }
}

fn key_from_proto(key: &pb::FlowKey) -> Result<edge_lb_common::NativeFlowKey> {
    Ok(edge_lb_common::NativeFlowKey {
        src: key.src,
        dst: key.dst,
        sport: u16::try_from(key.sport).context("flow sport out of range")?,
        dport: u16::try_from(key.dport).context("flow dport out of range")?,
        proto: u8::try_from(key.proto).context("flow protocol out of range")?,
        _pad: [0; 3],
    })
}

fn entry_to_proto(entry: &native_dnat::FlowEntry, now_ns: u64) -> pb::FlowEntry {
    let (key, value) = entry;
    pb::FlowEntry {
        key: Some(key_to_proto(key)),
        value: Some(pb::FlowValue {
            listener_id: value.listener_id,
            target_id: value.target_id,
            vip: value.vip,
            target: value.target,
            vip_port: u32::from(value.vip_port),
            target_port: u32::from(value.target_port),
            timeout_secs: value.timeout_secs,
            last_seen_age_ns: flow_age_ns(value.last_seen_ns, now_ns),
        }),
    }
}

fn entry_from_proto(entry: &pb::FlowEntry) -> Result<native_dnat::FlowEntry> {
    entry_from_proto_at(entry, native_dnat::monotonic_now_ns())
}

fn entry_from_proto_at(entry: &pb::FlowEntry, now_ns: u64) -> Result<native_dnat::FlowEntry> {
    let key = key_from_proto(entry.key.as_ref().context("flow entry key is required")?)?;
    let value = entry
        .value
        .as_ref()
        .context("flow entry value is required")?;
    Ok((
        key,
        edge_lb_common::NativeFlowValue {
            listener_id: value.listener_id,
            target_id: value.target_id,
            vip: value.vip,
            target: value.target,
            vip_port: u16::try_from(value.vip_port).context("flow VIP port out of range")?,
            target_port: u16::try_from(value.target_port)
                .context("flow target port out of range")?,
            timeout_secs: value.timeout_secs,
            last_seen_ns: local_last_seen_ns(value.last_seen_age_ns, now_ns),
        },
    ))
}

fn flow_age_ns(last_seen_ns: u64, now_ns: u64) -> u64 {
    if last_seen_ns == 0 {
        0
    } else {
        now_ns.saturating_sub(last_seen_ns)
    }
}

fn local_last_seen_ns(age_ns: u64, now_ns: u64) -> u64 {
    if age_ns == 0 {
        now_ns
    } else {
        now_ns.saturating_sub(age_ns)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowBatchState {
    Upsert(native_dnat::FlowEntry),
    Delete(edge_lb_common::NativeFlowKey),
}

#[derive(Default)]
struct PendingFlowBatch {
    states: HashMap<edge_lb_common::NativeFlowKey, FlowBatchState>,
    oldest_update_at: Option<Instant>,
}

#[derive(Debug, Default)]
struct FlowSyncBatch {
    entries: Vec<native_dnat::FlowEntry>,
    deletes: Vec<edge_lb_common::NativeFlowKey>,
}

impl FlowSyncBatch {
    fn operation_count(&self) -> usize {
        self.entries.len().saturating_add(self.deletes.len())
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.deletes.is_empty()
    }
}

impl PendingFlowBatch {
    fn operation_count(&self) -> usize {
        self.states.len()
    }

    fn apply_mutations(&mut self, mutations: &[native_dnat::FlowMutation], now: Instant) {
        if mutations.is_empty() {
            return;
        }
        self.mark_updated(now);
        for mutation in mutations {
            match *mutation {
                native_dnat::FlowMutation::Upsert(entry) => self.apply_upsert(entry),
                native_dnat::FlowMutation::Delete(key) => self.apply_delete(key),
            }
        }
    }

    fn apply_entries(
        &mut self,
        entries: impl IntoIterator<Item = native_dnat::FlowEntry>,
        now: Instant,
    ) {
        let mut updated = false;
        for entry in entries {
            if !updated {
                self.mark_updated(now);
                updated = true;
            }
            self.apply_upsert(entry);
        }
    }

    fn apply_deletes(
        &mut self,
        deletes: impl IntoIterator<Item = edge_lb_common::NativeFlowKey>,
        now: Instant,
    ) {
        let mut updated = false;
        for key in deletes {
            if !updated {
                self.mark_updated(now);
                updated = true;
            }
            self.apply_delete(key);
        }
    }

    fn requeue_batch(&mut self, batch: FlowSyncBatch, now: Instant) {
        self.apply_deletes(batch.deletes, now);
        self.apply_entries(batch.entries, now);
    }

    fn should_flush(&self, now: Instant, force: bool) -> bool {
        if self.states.is_empty() {
            return false;
        }
        force
            || self.states.len() >= MAX_SYNC_OPS_PER_BATCH
            || self
                .oldest_update_at
                .is_some_and(|oldest| now.duration_since(oldest) >= PENDING_FLUSH_INTERVAL)
    }

    fn take_limited_batch(&mut self) -> FlowSyncBatch {
        let mut keys = Vec::new();
        for (key, state) in &self.states {
            if matches!(state, FlowBatchState::Upsert(_)) {
                keys.push(*key);
                if keys.len() >= MAX_SYNC_OPS_PER_BATCH {
                    break;
                }
            }
        }
        if keys.len() < MAX_SYNC_OPS_PER_BATCH {
            for (key, state) in &self.states {
                if matches!(state, FlowBatchState::Delete(_)) {
                    keys.push(*key);
                    if keys.len() >= MAX_SYNC_OPS_PER_BATCH {
                        break;
                    }
                }
            }
        }
        let mut batch = FlowSyncBatch::default();
        for key in keys {
            match self.states.remove(&key) {
                Some(FlowBatchState::Upsert(entry)) => batch.entries.push(entry),
                Some(FlowBatchState::Delete(key)) => batch.deletes.push(key),
                None => {}
            }
        }
        if self.states.is_empty() {
            self.oldest_update_at = None;
        } else {
            self.oldest_update_at = Some(Instant::now());
        }
        batch
    }

    fn apply_upsert(&mut self, entry: native_dnat::FlowEntry) {
        let key = entry.0;
        if self.states.get(&key).is_none_or(|existing| match existing {
            FlowBatchState::Upsert((_, value)) => entry.1.last_seen_ns >= value.last_seen_ns,
            FlowBatchState::Delete(_) => true,
        }) {
            self.states.insert(key, FlowBatchState::Upsert(entry));
        }
    }

    fn apply_delete(&mut self, key: edge_lb_common::NativeFlowKey) {
        self.states.insert(key, FlowBatchState::Delete(key));
    }

    fn mark_updated(&mut self, now: Instant) {
        if self.oldest_update_at.is_none() {
            self.oldest_update_at = Some(now);
        }
    }
}

struct FullReconcileSchedule {
    next_at: Instant,
    recovery_rounds: u8,
}

impl FullReconcileSchedule {
    fn new(now: Instant) -> Self {
        Self {
            next_at: now,
            recovery_rounds: 0,
        }
    }

    fn due(&self, now: Instant) -> bool {
        now >= self.next_at
    }

    fn mark_completed(&mut self, now: Instant) {
        let interval = if self.recovery_rounds > 0 {
            self.recovery_rounds = self.recovery_rounds.saturating_sub(1);
            RECONCILE_RECOVERY_INTERVAL
        } else {
            RECONCILE_HEALTHY_INTERVAL
        };
        self.next_at = now + interval;
    }

    fn force_recovery(&mut self, now: Instant) {
        self.next_at = now;
        self.recovery_rounds = RECONCILE_RECOVERY_ROUNDS;
    }
}

fn flow_ack_covers_sent(expected: usize, accepted: u64) -> bool {
    usize::try_from(accepted) == Ok(expected)
}

fn sweep_flows_for_xsync(cfg: &Config) -> Result<usize> {
    if native_dnat::native_config_uses_least_connections(cfg)? {
        native_dnat::sweep_flows_and_refresh_loads(cfg)
    } else {
        native_dnat::sweep_flows(cfg)
    }
}

pub fn run_worker(cfg: Config) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!("[xsync] runtime init failed: {error}");
            return;
        }
    };
    runtime.block_on(client_loop_grpc(cfg));
}

async fn client_loop_grpc(cfg: Config) {
    let mut replica = HashMap::new();
    let mut backoff = Duration::from_millis(250);
    while !shutdown::requested() {
        if let Err(error) = sync_session_grpc(&cfg, &mut replica).await {
            set_error(format!("{error:#}"));
            tracing::debug!("[xsync] gRPC session ended: {error:#}");
        }
        let max = ha::load_for_state_dir(Path::new(&*cfg.state_dir))
            .ok()
            .map(|v| v.xsync.reconnect_max_ms.max(250))
            .unwrap_or(5000);
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(max));
    }
}

async fn sync_session_grpc(
    cfg: &Config,
    replica: &mut HashMap<edge_lb_common::NativeFlowKey, u64>,
) -> Result<()> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    if !ha_cfg.enabled
        || !ha_cfg.connection_sync
        || crate::provider::native::ha::state(cfg)?.state != "MASTER"
    {
        tokio::time::sleep(Duration::from_secs(1)).await;
        return Ok(());
    }
    let peer = ha_cfg
        .peers
        .first()
        .context("xsync peer is not configured")?;
    let token = ha::load_secrets_for_state_dir(Path::new(&*cfg.state_dir))?
        .context("xsync peer token unavailable")?
        .session_token;
    let control_port = cfg
        .control_plane
        .listen
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or(ha_cfg.xsync.port);
    let endpoint = format!("http://{}:{}", peer.underlay_ip, control_port);
    let channel = Endpoint::from_shared(endpoint.clone())
        .context("building xSync endpoint")?
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await
        .with_context(|| format!("connecting xSync endpoint {endpoint}"))?;
    let mut client = FlowSyncClient::new(channel);
    let (tx, rx) = mpsc::channel(4);
    tx.send(pb::FlowSyncRequest {
        source: cfg.node_name.clone(),
        token: token.clone(),
        entries: Vec::new(),
        deletes: Vec::new(),
    })
    .await
    .context("sending xSync handshake")?;
    let mut response = client
        .replicate(Request::new(ReceiverStream::new(rx)))
        .await?
        .into_inner();
    timeout(Duration::from_secs(5), response.message())
        .await??
        .context("xSync handshake was not acknowledged")?;
    replica.clear();
    let mut events = native_dnat::open_flow_events(cfg)?;
    let mut reconcile = FullReconcileSchedule::new(Instant::now());
    let mut pending = PendingFlowBatch::default();
    tracing::info!("[xsync] connected to {} via gRPC", endpoint);
    set_state("connected", Some(endpoint), None);
    loop {
        if shutdown::requested() {
            return Ok(());
        }
        if crate::provider::native::ha::state(cfg)?.state != "MASTER" {
            set_state("standby", None, None);
            return Ok(());
        }
        let mutations = events
            .as_mut()
            .map(native_dnat::drain_flow_events)
            .unwrap_or_default();
        let now = Instant::now();
        pending.apply_mutations(&mutations, now);
        let mut force_flush = false;
        if reconcile.due(now) {
            if let Err(error) = sweep_flows_for_xsync(cfg) {
                tracing::debug!("[xsync] native flow sweep skipped: {error:#}");
            }
            let flows = native_dnat::dump_flows(cfg)?;
            let current = flows.iter().map(|(key, _)| *key).collect::<HashSet<_>>();
            let entries = flows.into_iter().filter(|(key, value)| {
                replica
                    .get(key)
                    .is_none_or(|seen| value.last_seen_ns > *seen)
            });
            let deletes = replica.keys().filter(|key| !current.contains(key)).copied();
            pending.apply_deletes(deletes, now);
            pending.apply_entries(entries, now);
            reconcile.mark_completed(Instant::now());
            force_flush = true;
        }
        if pending.should_flush(Instant::now(), force_flush) {
            let batch = pending.take_limited_batch();
            if batch.is_empty() {
                tokio::time::sleep(EVENT_POLL_INTERVAL).await;
                continue;
            }
            let expected = batch.operation_count();
            let sync_now_ns = native_dnat::monotonic_now_ns();
            tx.send(pb::FlowSyncRequest {
                source: cfg.node_name.clone(),
                token: token.clone(),
                entries: batch
                    .entries
                    .iter()
                    .map(|entry| entry_to_proto(entry, sync_now_ns))
                    .collect(),
                deletes: batch.deletes.iter().map(key_to_proto).collect(),
            })
            .await
            .context("sending xSync request")?;
            let ack = timeout(Duration::from_secs(5), response.message())
                .await??
                .context("xSync peer closed stream")?;
            set_ack(usize::try_from(ack.applied).unwrap_or(usize::MAX));
            if !flow_ack_covers_sent(expected, ack.applied) {
                tracing::debug!(
                    "[xsync] peer accepted {} of {} flow operation(s); retaining replica backlog",
                    ack.applied,
                    expected
                );
                pending.requeue_batch(batch, Instant::now());
                reconcile.force_recovery(Instant::now());
            } else {
                for (key, value) in batch.entries {
                    replica.insert(key, value.last_seen_ns);
                }
                for key in batch.deletes {
                    replica.remove(&key);
                }
            }
        }
        tokio::time::sleep(EVENT_POLL_INTERVAL).await;
    }
}

fn set_state(state_value: &str, peer: Option<String>, error: Option<String>) {
    let mut value = status().lock().expect("xsync status mutex poisoned");
    value.state = state_value.to_string();
    if peer.is_some() {
        value.peer = peer;
    }
    value.last_error = error;
}

fn set_ack(applied: usize) {
    status()
        .lock()
        .expect("xsync status mutex poisoned")
        .last_ack_applied = applied;
}

fn set_error(error: String) {
    set_state("error", None, Some(error));
}

#[cfg(test)]
mod tests {
    use crate::control::pb;
    use crate::linux::native_dnat;

    use edge_lb_common::{NativeFlowKey, NativeFlowValue};

    #[test]
    fn grpc_poll_interval_is_bounded() {
        assert_eq!(super::EVENT_POLL_INTERVAL.as_millis(), 25);
    }

    #[test]
    fn standby_state_name_is_stable() {
        super::set_state("standby", None, None);
        assert_eq!(super::snapshot().state, "standby");
    }

    #[test]
    fn flow_sync_sends_age_instead_of_local_monotonic_time() {
        let entry = (
            NativeFlowKey {
                src: 1,
                dst: 2,
                sport: 12345,
                dport: 80,
                proto: 6,
                _pad: [0; 3],
            },
            NativeFlowValue {
                listener_id: 7,
                target_id: 9,
                vip: 2,
                target: 3,
                vip_port: 80,
                target_port: 8080,
                timeout_secs: 60,
                last_seen_ns: 900,
            },
        );

        let proto = super::entry_to_proto(&entry, 1_000);

        assert_eq!(proto.value.unwrap().last_seen_age_ns, 100);
    }

    #[test]
    fn flow_sync_rebases_age_to_receiver_monotonic_time() {
        let entry = pb::FlowEntry {
            key: Some(pb::FlowKey {
                src: 1,
                dst: 2,
                sport: 12345,
                dport: 80,
                proto: 6,
            }),
            value: Some(pb::FlowValue {
                listener_id: 7,
                target_id: 9,
                vip: 2,
                target: 3,
                vip_port: 80,
                target_port: 8080,
                timeout_secs: 60,
                last_seen_age_ns: 100,
            }),
        };

        let (_, value) = super::entry_from_proto_at(&entry, 5_000).unwrap();

        assert_eq!(value.last_seen_ns, 4_900);
    }

    #[test]
    fn flow_sync_zero_age_maps_to_receiver_now() {
        assert_eq!(super::local_last_seen_ns(0, 5_000), 5_000);
    }

    #[test]
    fn pending_flow_batch_keeps_last_operation_for_each_key() {
        let key = test_key(12345);
        let value = test_value(900);
        let mut pending = super::PendingFlowBatch::default();

        pending.apply_mutations(
            &[
                native_dnat::FlowMutation::Delete(key),
                native_dnat::FlowMutation::Upsert((key, value)),
            ],
            std::time::Instant::now(),
        );
        let batch = pending.take_limited_batch();

        assert_eq!(batch.entries, vec![(key, value)]);
        assert!(batch.deletes.is_empty());
        assert_eq!(pending.operation_count(), 0);
    }

    #[test]
    fn pending_flow_batch_keeps_latest_upsert_and_drops_shadowed_delete() {
        let key = test_key(12345);
        let mut pending = super::PendingFlowBatch::default();
        let now = std::time::Instant::now();

        pending.apply_deletes([key, key], now);
        pending.apply_entries(
            [
                (key, test_value(900)),
                (key, test_value(1_100)),
                (test_key(12346), test_value(1_000)),
            ],
            now,
        );
        let batch = pending.take_limited_batch();

        assert_eq!(
            batch
                .entries
                .iter()
                .find(|(item, _)| *item == key)
                .unwrap()
                .1
                .last_seen_ns,
            1_100
        );
        assert!(batch.deletes.is_empty());
    }

    #[test]
    fn flow_ack_must_cover_every_sent_operation_before_advancing_replica_index() {
        assert!(super::flow_ack_covers_sent(2, 2));
        assert!(!super::flow_ack_covers_sent(2, 1));
        assert!(!super::flow_ack_covers_sent(1, u64::MAX));
    }

    #[test]
    fn flow_batch_limit_prioritizes_upserts_and_defers_excess_deletes() {
        let mut pending = super::PendingFlowBatch::default();
        let now = std::time::Instant::now();

        pending.apply_entries(
            (0..super::MAX_SYNC_OPS_PER_BATCH)
                .map(|idx| (test_key(idx as u16), test_value(u64::from(idx as u32)))),
            now,
        );
        pending.apply_deletes([test_key(60_000)], now);
        let batch = pending.take_limited_batch();

        assert_eq!(batch.entries.len(), super::MAX_SYNC_OPS_PER_BATCH);
        assert!(batch.deletes.is_empty());
        assert_eq!(pending.operation_count(), 1);
    }

    #[test]
    fn flow_batch_limit_keeps_total_operations_bounded() {
        let mut pending = super::PendingFlowBatch::default();
        let now = std::time::Instant::now();

        pending.apply_entries([(test_key(60_000), test_value(1))], now);
        pending.apply_deletes(
            (0..super::MAX_SYNC_OPS_PER_BATCH).map(|idx| test_key(idx as u16)),
            now,
        );
        let batch = pending.take_limited_batch();

        assert_eq!(batch.entries.len(), 1);
        assert_eq!(batch.deletes.len(), super::MAX_SYNC_OPS_PER_BATCH - 1);
        assert_eq!(batch.operation_count(), super::MAX_SYNC_OPS_PER_BATCH);
        assert_eq!(pending.operation_count(), 1);
    }

    #[test]
    fn pending_flow_batch_requeues_unacked_batch() {
        let key = test_key(12345);
        let value = test_value(900);
        let mut pending = super::PendingFlowBatch::default();
        let now = std::time::Instant::now();

        pending.apply_entries([(key, value)], now);
        let batch = pending.take_limited_batch();
        assert_eq!(pending.operation_count(), 0);

        pending.requeue_batch(batch, now);
        let batch = pending.take_limited_batch();

        assert_eq!(batch.entries, vec![(key, value)]);
        assert!(batch.deletes.is_empty());
    }

    #[test]
    fn pending_flow_batch_flushes_after_delay_or_batch_limit() {
        let mut pending = super::PendingFlowBatch::default();
        let now = std::time::Instant::now();

        assert!(!pending.should_flush(now, false));
        pending.apply_entries([(test_key(1), test_value(1))], now);

        assert!(!pending.should_flush(now, false));
        assert!(pending.should_flush(now, true));
        assert!(pending.should_flush(now + super::PENDING_FLUSH_INTERVAL, false));
    }

    #[test]
    fn full_reconcile_schedule_starts_due_then_uses_healthy_interval() {
        let now = std::time::Instant::now();
        let mut schedule = super::FullReconcileSchedule::new(now);

        assert!(schedule.due(now));
        schedule.mark_completed(now);

        assert!(!schedule.due(now + super::RECONCILE_HEALTHY_INTERVAL / 2));
        assert!(schedule.due(now + super::RECONCILE_HEALTHY_INTERVAL));
    }

    #[test]
    fn full_reconcile_schedule_uses_recovery_rounds_after_forced_repair() {
        let now = std::time::Instant::now();
        let mut schedule = super::FullReconcileSchedule::new(now);

        schedule.mark_completed(now);
        schedule.force_recovery(now);

        assert!(schedule.due(now));
        schedule.mark_completed(now);
        assert!(!schedule.due(now + super::RECONCILE_RECOVERY_INTERVAL / 2));
        assert!(schedule.due(now + super::RECONCILE_RECOVERY_INTERVAL));
    }

    fn test_key(sport: u16) -> NativeFlowKey {
        NativeFlowKey {
            src: 1,
            dst: 2,
            sport,
            dport: 80,
            proto: 6,
            _pad: [0; 3],
        }
    }

    fn test_value(last_seen_ns: u64) -> NativeFlowValue {
        NativeFlowValue {
            listener_id: 7,
            target_id: 9,
            vip: 2,
            target: 3,
            vip_port: 80,
            target_port: 8080,
            timeout_secs: 60,
            last_seen_ns,
        }
    }
}
