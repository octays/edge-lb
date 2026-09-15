//! Native IPv4 default-DNAT TC datapath.
//!
//! The daemon owns the Aya object and its maps. The ingress program performs
//! the forward rewrite and the return program restores the listener source on
//! packets arriving from the backend overlay.

use std::{
    collections::{BTreeMap, HashMap as StdHashMap, HashSet},
    fs,
    path::PathBuf,
};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf,
    maps::{HashMap, Map, MapData, RingBuf},
    programs::tc::{
        NlOptions, SchedClassifier, TcAttachOptions, TcAttachType, TcHandle, qdisc_detach_program,
    },
};
use edge_lb_common::{
    DEFAULT_PERSIST_TIMEOUT_SECS, MAX_TARGETS_PER_LISTENER, NATIVE_CONSISTENT_HASH_BUCKETS,
    NATIVE_DNAT_INGRESS_PROGRAM, NATIVE_DNAT_RETURN_PROGRAM, NATIVE_LISTENER_ID_CAPACITY,
    NativeConsistentHashBucketKey, NativeConsistentHashBucketValue, NativeListenerLookupKey,
    NativeListenerLookupValue, NativeTargetKey, NativeTargetLoadKey, NativeTargetValue,
    native_consistent_bucket_score,
};
use sha2::{Digest, Sha256};

use crate::{
    config::Config,
    provider::native::{
        NativeTargetState, TargetHealthList, listeners_from_config, target_health_native,
    },
};

const LISTENERS: &str = "NATIVE_LISTENERS";
const TARGETS: &str = "NATIVE_TARGETS";
const CHASH_BUCKETS: &str = "NATIVE_CHASH_BUCKETS";
const FLOWS: &str = "NATIVE_FLOWS";
const STATS: &str = "NATIVE_STATS";
const FLOW_EVENTS: &str = "NATIVE_FLOW_EVENTS";
const RR_COUNTERS: &str = "NATIVE_RR_COUNTERS";
const ACTIVE_FLOWS: &str = "NATIVE_ACTIVE_FLOWS";
const MAPS: [&str; 8] = [
    LISTENERS,
    TARGETS,
    CHASH_BUCKETS,
    FLOWS,
    RR_COUNTERS,
    ACTIVE_FLOWS,
    STATS,
    FLOW_EVENTS,
];
const INGRESS_PREF_OFFSET: u16 = 10;
const RETURN_PREF_OFFSET: u16 = 11;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_ebpf.rs"));
}

pub struct NativeDnatAttachment {
    _bpf: Option<Ebpf>,
    pin_dir: PathBuf,
    underlay: String,
    overlay: String,
    pref: u16,
}

/// The current attachment. Holding it means every re-apply closes the previous
/// object's map fds and detaches its filters.
static CURRENT: std::sync::Mutex<Option<NativeDnatAttachment>> = std::sync::Mutex::new(None);
static CURRENT_SIGNATURE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistentHashBucketDigest {
    pub listener_id: u32,
    pub listener_name: String,
    pub vip: String,
    pub port: u16,
    pub protocol: &'static str,
    pub bucket_count: u32,
    pub digest: String,
}

impl Drop for NativeDnatAttachment {
    fn drop(&mut self) {
        let _ = qdisc_detach_program(
            &self.underlay,
            TcAttachType::Ingress,
            NATIVE_DNAT_INGRESS_PROGRAM,
        );
        let _ = qdisc_detach_program(
            &self.overlay,
            TcAttachType::Ingress,
            NATIVE_DNAT_RETURN_PROGRAM,
        );
        crate::linux::tc::delete_ingress_pref_best_effort(
            &self.underlay,
            self.pref + INGRESS_PREF_OFFSET,
        );
        crate::linux::tc::delete_ingress_pref_best_effort(
            &self.overlay,
            self.pref + RETURN_PREF_OFFSET,
        );
        for name in MAPS {
            let _ = fs::remove_file(self.pin_dir.join(name));
        }
        let _ = fs::remove_dir(&self.pin_dir);
    }
}

impl NativeDnatAttachment {
    fn matches_config(&self, cfg: &Config) -> bool {
        let n = cfg.network();
        self.underlay == n.underlay_dev
            && self.overlay == n.vxlan_dev
            && self.pref == cfg.gateway_cfg().dscp_pref
    }
}

fn pin_dir(cfg: &Config) -> PathBuf {
    cfg.pin_dir().join("native-dnat")
}
fn pin_path(cfg: &Config, name: &str) -> PathBuf {
    pin_dir(cfg).join(name)
}

fn read_object() -> Result<Vec<u8>> {
    if let Some(bytes) = embedded::embedded_ebpf() {
        return Ok(bytes.to_vec());
    }
    Err(anyhow!(
        "native DNAT eBPF object is not embedded; build with `make release`"
    ))
}

pub fn attach_owned(cfg: &Config) -> Result<NativeDnatAttachment> {
    let listeners = listeners_from_config(cfg)?;
    if listeners.is_empty() {
        bail!("native DNAT requires at least one listener");
    }
    let n = cfg.network();
    let mut bpf = Ebpf::load(&read_object()?).context("failed to load native DNAT eBPF object")?;
    let observed_targets = target_health_native(cfg).ok();
    let pin_dir = pin_dir(cfg);
    fs::create_dir_all(&pin_dir)
        .with_context(|| format!("failed to create {}", pin_dir.display()))?;
    for name in MAPS {
        let _ = fs::remove_file(pin_path(cfg, name));
    }

    let listener_ids = stable_listener_assignments(&listeners)?;
    {
        let mut listener_map: HashMap<
            &mut MapData,
            NativeListenerLookupKey,
            NativeListenerLookupValue,
        > = HashMap::try_from(
            bpf.map_mut(LISTENERS)
                .ok_or_else(|| anyhow!("{LISTENERS} map missing"))?,
        )?;
        for (listener_id, listener) in &listener_ids {
            let weight_total = listener
                .targets
                .iter()
                .filter(|target| {
                    native_target_is_active(observed_targets.as_ref(), listener, target)
                })
                .map(|target| target.weight)
                .filter(|weight| *weight > 0)
                .sum::<u32>();
            listener_map.insert(
                NativeListenerLookupKey {
                    vip: u32::from_be_bytes(listener.key.vip_ip.octets()),
                    port: listener.key.vip_port.to_be(),
                    proto: listener.key.protocol.ip_proto(),
                    _pad: 0,
                },
                NativeListenerLookupValue {
                    listener_id: *listener_id,
                    target_base: 0,
                    target_count: listener.targets.len() as u32,
                    weight_total,
                    select: listener.select,
                    flags: 1,
                    timeout_secs: if listener.select == crate::config::LbSelect::Persist.code() {
                        DEFAULT_PERSIST_TIMEOUT_SECS
                    } else {
                        listener.inactive_timeout_secs
                    },
                    dscp: listener.dscp,
                },
                0,
            )?;
        }
    }
    {
        let mut targets: HashMap<&mut MapData, NativeTargetKey, NativeTargetValue> =
            HashMap::try_from(
                bpf.map_mut(TARGETS)
                    .ok_or_else(|| anyhow!("{TARGETS} map missing"))?,
            )?;
        for (listener_id, listener) in &listener_ids {
            validate_listener_target_count(listener)?;
            for (target_id, target) in listener.targets.iter().enumerate() {
                if !native_target_is_active(observed_targets.as_ref(), listener, target) {
                    continue;
                }
                targets.insert(
                    NativeTargetKey {
                        listener_id: *listener_id,
                        target_id: target_id as u32,
                    },
                    NativeTargetValue {
                        address: u32::from_be_bytes(target.address.octets()),
                        port: target.port,
                        weight: target.weight.min(u16::MAX as u32) as u16,
                        flags: 1,
                    },
                    0,
                )?;
            }
        }
    }
    {
        let mut buckets: HashMap<
            &mut MapData,
            NativeConsistentHashBucketKey,
            NativeConsistentHashBucketValue,
        > = HashMap::try_from(
            bpf.map_mut(CHASH_BUCKETS)
                .ok_or_else(|| anyhow!("{CHASH_BUCKETS} map missing"))?,
        )?;
        for (key, value) in
            desired_consistent_hash_buckets(&listener_ids, observed_targets.as_ref())?
        {
            buckets.insert(key, value, 0)?;
        }
    }
    for name in MAPS {
        bpf.map(name)
            .ok_or_else(|| anyhow!("{name} map missing"))?
            .pin(pin_path(cfg, name))
            .with_context(|| format!("pinning native DNAT map {name}"))?;
    }

    let pref = cfg.gateway_cfg().dscp_pref;
    crate::linux::tc::add_clsact_best_effort(&n.underlay_dev);
    crate::linux::tc::add_clsact_best_effort(&n.vxlan_dev);
    crate::linux::tc::delete_ingress_pref_best_effort(&n.underlay_dev, pref + INGRESS_PREF_OFFSET);
    crate::linux::tc::delete_ingress_pref_best_effort(&n.vxlan_dev, pref + RETURN_PREF_OFFSET);
    attach_program(
        &mut bpf,
        NATIVE_DNAT_INGRESS_PROGRAM,
        &n.underlay_dev,
        pref + INGRESS_PREF_OFFSET,
    )?;
    attach_program(
        &mut bpf,
        NATIVE_DNAT_RETURN_PROGRAM,
        &n.vxlan_dev,
        pref + RETURN_PREF_OFFSET,
    )?;
    Ok(NativeDnatAttachment {
        _bpf: Some(bpf),
        pin_dir,
        underlay: n.underlay_dev.clone(),
        overlay: n.vxlan_dev.clone(),
        pref,
    })
}

fn observed_target_is_active(
    observed: Option<&TargetHealthList>,
    group: &str,
    address: std::net::Ipv4Addr,
    protocol: u8,
    port: u16,
) -> bool {
    let Some(observed) = observed else {
        return true;
    };
    let protocol = match protocol {
        6 => "tcp",
        17 => "udp",
        _ => return true,
    };
    observed
        .entries
        .iter()
        // Probe port and forwarding port are independent. Health belongs to
        // the native health identity, which is keyed by the forwarding
        // port; filtering on probe_port would miss valid observations when a
        // group probes a different port from the listener target port.
        .filter(|entry| {
            entry.target_group == group
                && entry.name == format!("{group}:{address}_{protocol}_{port}")
        })
        .all(|entry| {
            !matches!(
                entry.current_state.as_deref(),
                Some("nok") | Some("inactive") | Some("down")
            )
        })
}

fn native_target_is_active(
    observed: Option<&TargetHealthList>,
    listener: &crate::provider::native::NativeListener,
    target: &crate::provider::native::NativeTarget,
) -> bool {
    matches!(target.state, NativeTargetState::Active)
        && observed_target_is_active(
            observed,
            &listener.target_group,
            target.address,
            listener.key.protocol.ip_proto(),
            target.port,
        )
}

fn validate_listener_target_count(
    listener: &crate::provider::native::NativeListener,
) -> Result<()> {
    if listener.targets.len() > MAX_TARGETS_PER_LISTENER as usize {
        bail!(
            "listener {} has {} targets; max {}",
            listener.key.vip_port,
            listener.targets.len(),
            MAX_TARGETS_PER_LISTENER
        );
    }
    Ok(())
}

fn attach_program(bpf: &mut Ebpf, name: &str, dev: &str, priority: u16) -> Result<()> {
    let program: &mut SchedClassifier = bpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("{name} program missing"))?
        .try_into()
        .with_context(|| format!("{name} is not a TC classifier"))?;
    program.load().with_context(|| format!("loading {name}"))?;
    program
        .attach_with_options(
            dev,
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions {
                priority,
                handle: TcHandle::from(1),
                classid: None,
            }),
        )
        .with_context(|| format!("attaching {name} to {dev} ingress pref {priority}"))?;
    Ok(())
}

/// Attach and keep the attachment in the process-wide slot, dropping the
/// previous one first (detach + unpin + close fds). The brief filter gap
/// between drop and attach is bounded by the reconcile interval.
pub fn apply(cfg: &Config) -> Result<()> {
    // An automatic target group can temporarily have no matched backends.
    // Keep the control-plane listener, but remove any stale datapath instead
    // of making the gateway daemon fail its startup/reconcile cycle.
    let listeners = listeners_from_config(cfg)?;
    if listeners.is_empty() {
        return cleanup(cfg);
    }
    let signature = format!("{listeners:?}");
    let mut current = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    let mut current_signature = CURRENT_SIGNATURE.lock().unwrap_or_else(|e| e.into_inner());
    // Keep the running programs and flow map in place while only listener,
    // target or health state changes. Rebuilding the object would create a
    // packet gap and discard active NAT flow state.
    if let Some(active) = current.as_ref()
        && active.matches_config(cfg)
        && attached(cfg)
    {
        if let Err(error) = sync_pinned_datapath(cfg, &listeners) {
            tracing::warn!(
                "[native-dnat] pinned map refresh failed, reattaching datapath: {error:#}"
            );
        } else {
            *current_signature = Some(signature);
            return Ok(());
        }
    }
    if let Some(old) = current.take() {
        drop(old);
    }
    *current = Some(attach_owned(cfg)?);
    *current_signature = Some(signature);
    Ok(())
}

fn sync_pinned_datapath(
    cfg: &Config,
    listeners: &[crate::provider::native::NativeListener],
) -> Result<()> {
    let listener_ids = stable_listener_assignments(listeners)?;
    sync_listener_map(cfg, &listener_ids)?;
    sync_target_map(cfg, &listener_ids)?;
    sync_consistent_hash_bucket_map(cfg, &listener_ids)?;
    Ok(())
}

fn sync_listener_map(
    cfg: &Config,
    listener_ids: &[(u32, &crate::provider::native::NativeListener)],
) -> Result<()> {
    let map_data = MapData::from_pin(pin_path(cfg, LISTENERS))
        .with_context(|| format!("opening {LISTENERS}"))?;
    let map =
        Map::from_map_data(map_data).with_context(|| format!("{LISTENERS} is not a hash map"))?;
    let mut listener_map: HashMap<MapData, NativeListenerLookupKey, NativeListenerLookupValue> =
        HashMap::try_from(map).with_context(|| format!("{LISTENERS} key/value layout mismatch"))?;
    let observed_targets = target_health_native(cfg).ok();
    let mut desired = HashSet::new();
    for (listener_id, listener) in listener_ids {
        let key = NativeListenerLookupKey {
            vip: u32::from_be_bytes(listener.key.vip_ip.octets()),
            port: listener.key.vip_port.to_be(),
            proto: listener.key.protocol.ip_proto(),
            _pad: 0,
        };
        desired.insert(key);
        let weight_total = listener
            .targets
            .iter()
            .filter(|target| native_target_is_active(observed_targets.as_ref(), listener, target))
            .map(|target| target.weight)
            .filter(|weight| *weight > 0)
            .sum::<u32>();
        listener_map.insert(
            key,
            NativeListenerLookupValue {
                listener_id: *listener_id,
                target_base: 0,
                target_count: listener.targets.len() as u32,
                weight_total,
                select: listener.select,
                flags: 1,
                timeout_secs: if listener.select == crate::config::LbSelect::Persist.code() {
                    DEFAULT_PERSIST_TIMEOUT_SECS
                } else {
                    listener.inactive_timeout_secs
                },
                dscp: listener.dscp,
            },
            0,
        )?;
    }
    let existing = listener_map
        .iter()
        .map(|entry| entry.map(|(key, _)| key))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("iterating {LISTENERS}"))?;
    for key in existing {
        if !desired.contains(&key) {
            let _ = listener_map.remove(&key);
        }
    }
    Ok(())
}

fn sync_target_map(
    cfg: &Config,
    listener_ids: &[(u32, &crate::provider::native::NativeListener)],
) -> Result<()> {
    let map_data =
        MapData::from_pin(pin_path(cfg, TARGETS)).with_context(|| format!("opening {TARGETS}"))?;
    let map =
        Map::from_map_data(map_data).with_context(|| format!("{TARGETS} is not a hash map"))?;
    let mut targets: HashMap<MapData, NativeTargetKey, NativeTargetValue> =
        HashMap::try_from(map).with_context(|| format!("{TARGETS} key/value layout mismatch"))?;
    let observed_targets = target_health_native(cfg).ok();
    let mut desired = HashSet::new();
    for (listener_id, listener) in listener_ids {
        validate_listener_target_count(listener)?;
        for (target_id, target) in listener.targets.iter().enumerate() {
            if !native_target_is_active(observed_targets.as_ref(), listener, target) {
                continue;
            }
            let key = NativeTargetKey {
                listener_id: *listener_id,
                target_id: target_id as u32,
            };
            desired.insert(key);
            targets.insert(
                key,
                NativeTargetValue {
                    address: u32::from_be_bytes(target.address.octets()),
                    port: target.port,
                    weight: target.weight.min(u16::MAX as u32) as u16,
                    flags: 1,
                },
                0,
            )?;
        }
    }
    let existing = targets
        .iter()
        .map(|entry| entry.map(|(key, _)| key))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("iterating {TARGETS}"))?;
    for key in existing {
        if !desired.contains(&key) {
            let _ = targets.remove(&key);
        }
    }
    Ok(())
}

fn sync_consistent_hash_bucket_map(
    cfg: &Config,
    listener_ids: &[(u32, &crate::provider::native::NativeListener)],
) -> Result<()> {
    let map_data = MapData::from_pin(pin_path(cfg, CHASH_BUCKETS))
        .with_context(|| format!("opening {CHASH_BUCKETS}"))?;
    let map = Map::from_map_data(map_data)
        .with_context(|| format!("{CHASH_BUCKETS} is not a hash map"))?;
    let mut buckets: HashMap<
        MapData,
        NativeConsistentHashBucketKey,
        NativeConsistentHashBucketValue,
    > = HashMap::try_from(map)
        .with_context(|| format!("{CHASH_BUCKETS} key/value layout mismatch"))?;
    let observed_targets = target_health_native(cfg).ok();
    let desired = desired_consistent_hash_buckets(listener_ids, observed_targets.as_ref())?;
    for (key, value) in &desired {
        buckets.insert(*key, *value, 0)?;
    }
    let existing = buckets
        .iter()
        .map(|entry| entry.map(|(key, _)| key))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("iterating {CHASH_BUCKETS}"))?;
    for key in existing {
        if !desired.contains_key(&key) {
            let _ = buckets.remove(&key);
        }
    }
    Ok(())
}

fn desired_consistent_hash_buckets(
    listener_ids: &[(u32, &crate::provider::native::NativeListener)],
    observed_targets: Option<&TargetHealthList>,
) -> Result<StdHashMap<NativeConsistentHashBucketKey, NativeConsistentHashBucketValue>> {
    let mut desired = StdHashMap::new();
    for (listener_id, listener) in listener_ids {
        validate_listener_target_count(listener)?;
        if listener.select != crate::config::LbSelect::ConsistentHash.code() {
            continue;
        }
        let mut targets = Vec::new();
        for (target_id, target) in listener.targets.iter().enumerate() {
            if !native_target_is_active(observed_targets, listener, target) || target.weight == 0 {
                continue;
            }
            targets.push((
                target_id as u32,
                NativeTargetValue {
                    address: u32::from_be_bytes(target.address.octets()),
                    port: target.port,
                    weight: target.weight.min(u16::MAX as u32) as u16,
                    flags: 1,
                },
            ));
        }
        if targets.is_empty() {
            continue;
        }
        for bucket in 0..NATIVE_CONSISTENT_HASH_BUCKETS {
            if let Some(target_id) = choose_consistent_hash_bucket_target(bucket, &targets) {
                desired.insert(
                    NativeConsistentHashBucketKey {
                        listener_id: *listener_id,
                        bucket,
                    },
                    NativeConsistentHashBucketValue { target_id },
                );
            }
        }
    }
    Ok(desired)
}

fn choose_consistent_hash_bucket_target(
    bucket: u32,
    targets: &[(u32, NativeTargetValue)],
) -> Option<u32> {
    let mut selected = None;
    let mut best_score = 0u64;
    for (target_id, target) in targets {
        let score = native_consistent_bucket_score(bucket, target);
        if selected.is_none() || score > best_score {
            selected = Some(*target_id);
            best_score = score;
        }
    }
    selected
}

pub fn consistent_hash_bucket_digests(cfg: &Config) -> Result<Vec<ConsistentHashBucketDigest>> {
    let listeners = listeners_from_config(cfg)?;
    let listener_ids = stable_listener_assignments(&listeners)?;
    let map_data = MapData::from_pin(pin_path(cfg, CHASH_BUCKETS))
        .with_context(|| format!("opening {CHASH_BUCKETS}"))?;
    let map = Map::from_map_data(map_data)
        .with_context(|| format!("{CHASH_BUCKETS} is not a hash map"))?;
    let buckets: HashMap<MapData, NativeConsistentHashBucketKey, NativeConsistentHashBucketValue> =
        HashMap::try_from(map)
            .with_context(|| format!("{CHASH_BUCKETS} key/value layout mismatch"))?;
    let mut by_listener: StdHashMap<u32, BTreeMap<u32, u32>> = StdHashMap::new();
    for entry in buckets.iter() {
        let (key, value) = entry.with_context(|| format!("iterating {CHASH_BUCKETS}"))?;
        by_listener
            .entry(key.listener_id)
            .or_default()
            .insert(key.bucket, value.target_id);
    }

    let mut out = Vec::new();
    for (listener_id, listener) in listener_ids {
        if listener.select != crate::config::LbSelect::ConsistentHash.code() {
            continue;
        }
        let present = by_listener.remove(&listener_id).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(listener_id.to_be_bytes());
        hasher.update(NATIVE_CONSISTENT_HASH_BUCKETS.to_be_bytes());
        for bucket in 0..NATIVE_CONSISTENT_HASH_BUCKETS {
            hasher.update(bucket.to_be_bytes());
            let target_id = present.get(&bucket).copied().unwrap_or(u32::MAX);
            hasher.update(target_id.to_be_bytes());
        }
        out.push(ConsistentHashBucketDigest {
            listener_id,
            listener_name: listener.name.clone(),
            vip: listener.key.vip_ip.to_string(),
            port: listener.key.vip_port,
            protocol: native_protocol_name(listener.key.protocol),
            bucket_count: NATIVE_CONSISTENT_HASH_BUCKETS,
            digest: hex::encode(hasher.finalize()),
        });
    }
    Ok(out)
}

fn native_protocol_name(protocol: crate::provider::native::NativeProtocol) -> &'static str {
    match protocol {
        crate::provider::native::NativeProtocol::Tcp => "tcp",
        crate::provider::native::NativeProtocol::Udp => "udp",
    }
}

/// A flow-table entry as exchanged with the HA peer. Field order is the wire
/// contract; both gateways in a pair share one architecture, so the raw
/// repr(C) integers serialize consistently.
pub type FlowEntry = (
    edge_lb_common::NativeFlowKey,
    edge_lb_common::NativeFlowValue,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowMutation {
    Upsert(FlowEntry),
    Delete(edge_lb_common::NativeFlowKey),
}

pub type FlowEventReader = RingBuf<MapData>;

/// Open the pinned event stream. Older datapath objects may not have this map.
pub fn open_flow_events(cfg: &Config) -> Result<Option<FlowEventReader>> {
    let pin = pin_path(cfg, FLOW_EVENTS);
    if !pin.exists() {
        return Ok(None);
    }
    let data = MapData::from_pin(&pin).with_context(|| format!("opening pinned {FLOW_EVENTS}"))?;
    let map = Map::from_map_data(data).with_context(|| format!("{FLOW_EVENTS} is not a map"))?;
    Ok(Some(RingBuf::try_from(map).with_context(|| {
        format!("{FLOW_EVENTS} is not a ring buffer")
    })?))
}

/// Drain flow mutations without blocking the xSync worker.
pub fn drain_flow_events(reader: &mut FlowEventReader) -> Vec<FlowMutation> {
    let mut events = Vec::new();
    while let Some(item) = reader.next() {
        if item.len() != std::mem::size_of::<edge_lb_common::NativeFlowEvent>() {
            tracing::warn!(
                "[native-dnat] ignoring flow event with unexpected size {}",
                item.len()
            );
            continue;
        }
        let event = unsafe {
            std::ptr::read_unaligned(item.as_ptr() as *const edge_lb_common::NativeFlowEvent)
        };
        events.push(if event.op == 2 {
            FlowMutation::Delete(event.key)
        } else {
            FlowMutation::Upsert((event.key, event.value))
        });
    }
    events
}

fn open_pinned_flows(
    cfg: &Config,
) -> Result<Option<HashMap<MapData, edge_lb_common::NativeFlowKey, edge_lb_common::NativeFlowValue>>>
{
    let pin = pin_path(cfg, FLOWS);
    if !pin.exists() {
        return Ok(None);
    }
    let map_data = MapData::from_pin(&pin).with_context(|| format!("opening pinned {FLOWS}"))?;
    let map = Map::from_map_data(map_data).with_context(|| format!("{FLOWS} is not a hash map"))?;
    let flows: HashMap<MapData, edge_lb_common::NativeFlowKey, edge_lb_common::NativeFlowValue> =
        HashMap::try_from(map).with_context(|| format!("{FLOWS} key/value layout mismatch"))?;
    Ok(Some(flows))
}

fn stable_listener_assignments(
    listeners: &[crate::provider::native::NativeListener],
) -> Result<Vec<(u32, &crate::provider::native::NativeListener)>> {
    if listeners.len() > NATIVE_LISTENER_ID_CAPACITY as usize {
        bail!(
            "native listener count {} exceeds id capacity {}",
            listeners.len(),
            NATIVE_LISTENER_ID_CAPACITY
        );
    }
    let mut ordered = listeners.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|listener| listener_sort_key(listener));
    let mut used = HashSet::new();
    let mut out = Vec::with_capacity(ordered.len());
    for listener in ordered {
        let mut id = stable_listener_id(listener);
        for _ in 0..NATIVE_LISTENER_ID_CAPACITY {
            if used.insert(id) {
                out.push((id, listener));
                break;
            }
            id += 1;
            if id > NATIVE_LISTENER_ID_CAPACITY {
                id = 1;
            }
        }
    }
    if out.len() != listeners.len() {
        bail!("native listener id space exhausted");
    }
    Ok(out)
}

fn listener_sort_key(listener: &crate::provider::native::NativeListener) -> (u32, u16, u8) {
    (
        u32::from_be_bytes(listener.key.vip_ip.octets()),
        listener.key.vip_port,
        listener.key.protocol.ip_proto(),
    )
}

fn stable_listener_id(listener: &crate::provider::native::NativeListener) -> u32 {
    let (vip, port, proto) = listener_sort_key(listener);
    let mut hash = 0x811c_9dc5u32;
    for byte in vip
        .to_be_bytes()
        .into_iter()
        .chain(port.to_be_bytes())
        .chain([proto])
    {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    (hash % NATIVE_LISTENER_ID_CAPACITY) + 1
}

/// Dump the pinned flow table. Empty when the datapath is not attached.
pub fn dump_flows(cfg: &Config) -> Result<Vec<FlowEntry>> {
    let Some(flows) = open_pinned_flows(cfg)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in flows.iter() {
        out.push(entry.with_context(|| format!("iterating {FLOWS}"))?);
    }
    Ok(out)
}

pub fn sweep_flows_and_refresh_loads(cfg: &Config) -> Result<usize> {
    let now = monotonic_now_ns();
    let Some(mut flows) = open_pinned_flows(cfg)? else {
        return Ok(0);
    };
    let mut expired = Vec::new();
    let mut loads = StdHashMap::<NativeTargetLoadKey, u32>::new();
    let mut seen_pairs =
        HashSet::<(edge_lb_common::NativeFlowKey, edge_lb_common::NativeFlowKey)>::new();
    for entry in flows.iter() {
        let (key, value) = entry.with_context(|| format!("iterating {FLOWS}"))?;
        if flow_expired(value.last_seen_ns, value.timeout_secs, now) {
            expired.push(key);
            continue;
        }
        let pair = canonical_flow_pair(key, value);
        if seen_pairs.insert(pair) {
            let load_key = NativeTargetLoadKey {
                listener_id: value.listener_id,
                target_id: value.target_id,
            };
            loads
                .entry(load_key)
                .and_modify(|load| *load = load.saturating_add(1))
                .or_insert(1);
        }
    }
    for key in &expired {
        let _ = flows.remove(key);
    }
    replace_active_flows(cfg, &loads)?;
    Ok(expired.len())
}

/// Upsert replicated flow entries into the pinned flow table. An entry is
/// only mutated when it is new or strictly fresher than the local copy, so
/// a lagging MASTER replica never regresses a flow's last-seen timestamp.
/// Returns how many entries were accepted by an attached datapath. Idempotent
/// no-ops count as accepted; a missing flow map accepts nothing.
pub fn upsert_flows(cfg: &Config, entries: &[FlowEntry]) -> Result<usize> {
    let pin = pin_path(cfg, FLOWS);
    if !pin.exists() {
        // Datapath detached on this node: nothing to apply. The caller may
        // treat this as success; entries would be rebuilt on next attach.
        return Ok(0);
    }
    let Some(mut flows) = open_pinned_flows(cfg)? else {
        return Ok(0);
    };
    let mut accepted = 0usize;
    for (key, value) in entries {
        if flow_apply_applies(flows.get(key, 0).ok().as_ref(), value) {
            flows.insert(*key, *value, 0)?;
        }
        accepted += 1;
    }
    Ok(accepted)
}

/// Delete replicated flow-map records. Missing keys are treated as already
/// applied so reconnects and duplicate delete events remain idempotent.
pub fn delete_flows(cfg: &Config, keys: &[edge_lb_common::NativeFlowKey]) -> Result<usize> {
    let pin = pin_path(cfg, FLOWS);
    if !pin.exists() {
        return Ok(0);
    }
    let Some(mut flows) = open_pinned_flows(cfg)? else {
        return Ok(0);
    };
    let mut accepted = 0usize;
    for key in keys {
        let _ = flows.remove(key);
        accepted += 1;
    }
    Ok(accepted)
}

/// Apply decision, extracted for tests: apply when absent or when the
/// replica's `last_seen_ns` is newer than the local one.
fn flow_apply_applies(
    local: Option<&edge_lb_common::NativeFlowValue>,
    replica: &edge_lb_common::NativeFlowValue,
) -> bool {
    match local {
        None => true,
        Some(local) => replica.last_seen_ns > local.last_seen_ns,
    }
}

fn flow_expired(last_seen_ns: u64, timeout_secs: u32, now_ns: u64) -> bool {
    if last_seen_ns == 0 || timeout_secs == 0 {
        return false;
    }
    now_ns.saturating_sub(last_seen_ns) > timeout_secs as u64 * 1_000_000_000
}

pub(crate) fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

fn canonical_flow_pair(
    key: edge_lb_common::NativeFlowKey,
    value: edge_lb_common::NativeFlowValue,
) -> (edge_lb_common::NativeFlowKey, edge_lb_common::NativeFlowKey) {
    let target_port = value.target_port.to_be();
    let (forward, reverse) = if key.src == value.target && key.sport == target_port {
        let forward = key.forward_for(value);
        (forward, key)
    } else {
        let reverse = key.reverse_for(value);
        (key, reverse)
    };
    if flow_key_sort_tuple(&forward) <= flow_key_sort_tuple(&reverse) {
        (forward, reverse)
    } else {
        (reverse, forward)
    }
}

fn flow_key_sort_tuple(key: &edge_lb_common::NativeFlowKey) -> (u32, u32, u16, u16, u8) {
    (key.src, key.dst, key.sport, key.dport, key.proto)
}

fn replace_active_flows(cfg: &Config, loads: &StdHashMap<NativeTargetLoadKey, u32>) -> Result<()> {
    let pin = pin_path(cfg, ACTIVE_FLOWS);
    if !pin.exists() {
        return Ok(());
    }
    let map_data =
        MapData::from_pin(&pin).with_context(|| format!("opening pinned {ACTIVE_FLOWS}"))?;
    let map = Map::from_map_data(map_data)
        .with_context(|| format!("{ACTIVE_FLOWS} is not a hash map"))?;
    let mut active: HashMap<MapData, NativeTargetLoadKey, u32> = HashMap::try_from(map)
        .with_context(|| format!("{ACTIVE_FLOWS} key/value layout mismatch"))?;
    let existing = active
        .iter()
        .map(|entry| entry.map(|(key, _)| key))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("iterating {ACTIVE_FLOWS}"))?;
    for key in existing {
        if !loads.contains_key(&key) {
            let _ = active.remove(&key);
        }
    }
    for (key, value) in loads {
        active.insert(*key, *value, 0)?;
    }
    Ok(())
}

/// Refresh endpoint membership in the pinned TARGETS map from observed probe
/// state, without touching TC attachment or the running programs. Unhealthy
/// targets are removed from the eBPF target map instead of being kept with an
/// inactive flag.
pub fn refresh_target_health(cfg: &Config) -> Result<()> {
    let pin = pin_path(cfg, TARGETS);
    if !pin.exists() {
        return Ok(());
    }
    let listeners = listeners_from_config(cfg)?;
    let listener_ids = stable_listener_assignments(&listeners)?;
    let observed = target_health_native(cfg).ok();
    sync_target_map(cfg, &listener_ids)?;
    sync_consistent_hash_bucket_map(cfg, &listener_ids)?;
    refresh_listener_weights(cfg, &listeners, observed.as_ref())?;
    Ok(())
}

fn refresh_listener_weights(
    cfg: &Config,
    listeners: &[crate::provider::native::NativeListener],
    observed: Option<&TargetHealthList>,
) -> Result<()> {
    let pin = pin_path(cfg, LISTENERS);
    if !pin.exists() {
        return Ok(());
    }
    let map_data =
        MapData::from_pin(&pin).with_context(|| format!("opening pinned {LISTENERS}"))?;
    let map =
        Map::from_map_data(map_data).with_context(|| format!("{LISTENERS} is not a hash map"))?;
    let mut listener_map: HashMap<MapData, NativeListenerLookupKey, NativeListenerLookupValue> =
        HashMap::try_from(map).with_context(|| format!("{LISTENERS} key/value layout mismatch"))?;
    for (listener_id, listener) in stable_listener_assignments(listeners)? {
        let key = NativeListenerLookupKey {
            vip: u32::from_be_bytes(listener.key.vip_ip.octets()),
            port: listener.key.vip_port.to_be(),
            proto: listener.key.protocol.ip_proto(),
            _pad: 0,
        };
        let Some(mut value) = listener_map.get(&key, 0).ok() else {
            continue;
        };
        value.listener_id = listener_id;
        value.weight_total = listener
            .targets
            .iter()
            .filter(|target| native_target_is_active(observed, listener, target))
            .map(|target| target.weight)
            .filter(|weight| *weight > 0)
            .sum();
        listener_map.insert(key, value, 0).with_context(|| {
            format!(
                "updating native listener weight for listener {}",
                listener_id
            )
        })?;
    }
    Ok(())
}

pub fn cleanup(cfg: &Config) -> Result<()> {
    let mut current = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    let mut current_signature = CURRENT_SIGNATURE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = current.take() {
        drop(old);
    }
    *current_signature = None;
    let n = cfg.network();
    let pref = cfg.gateway_cfg().dscp_pref;
    let _ = qdisc_detach_program(
        &n.underlay_dev,
        TcAttachType::Ingress,
        NATIVE_DNAT_INGRESS_PROGRAM,
    );
    let _ = qdisc_detach_program(
        &n.vxlan_dev,
        TcAttachType::Ingress,
        NATIVE_DNAT_RETURN_PROGRAM,
    );
    crate::linux::tc::delete_ingress_pref_best_effort(&n.underlay_dev, pref + INGRESS_PREF_OFFSET);
    crate::linux::tc::delete_ingress_pref_best_effort(&n.vxlan_dev, pref + RETURN_PREF_OFFSET);
    for name in MAPS {
        let _ = fs::remove_file(pin_path(cfg, name));
    }
    let _ = fs::remove_dir(pin_dir(cfg));
    Ok(())
}

pub fn attached(cfg: &Config) -> bool {
    let pref = cfg.gateway_cfg().dscp_pref;
    crate::linux::tc::show_ingress(&cfg.network().underlay_dev)
        .unwrap_or_default()
        .lines()
        .any(|line| {
            line.contains(&format!("pref {}", pref + INGRESS_PREF_OFFSET))
                && line.contains(NATIVE_DNAT_INGRESS_PROGRAM)
        })
}

pub fn stats(cfg: &Config) -> Result<edge_lb_common::NativeDatapathStats> {
    let data =
        MapData::from_pin(pin_path(cfg, STATS)).context("native DNAT stats map is not pinned")?;
    let map = Map::from_map_data(data)?;
    let stats: aya::maps::PerCpuArray<MapData, edge_lb_common::NativeDatapathStats> =
        map.try_into()?;
    let values = stats.get(&0, 0)?;
    Ok(values.iter().copied().fold(
        edge_lb_common::NativeDatapathStats::default(),
        |mut total, value| {
            total.listener_hit = total.listener_hit.saturating_add(value.listener_hit);
            total.listener_miss = total.listener_miss.saturating_add(value.listener_miss);
            total.return_miss = total.return_miss.saturating_add(value.return_miss);
            total.target_miss = total.target_miss.saturating_add(value.target_miss);
            total.rewritten = total.rewritten.saturating_add(value.rewritten);
            total.checksum_error = total.checksum_error.saturating_add(value.checksum_error);
            total.chash_bucket_hit = total
                .chash_bucket_hit
                .saturating_add(value.chash_bucket_hit);
            total.chash_bucket_miss = total
                .chash_bucket_miss
                .saturating_add(value.chash_bucket_miss);
            total.chash_bucket_unusable = total
                .chash_bucket_unusable
                .saturating_add(value.chash_bucket_unusable);
            total.chash_fallback = total.chash_fallback.saturating_add(value.chash_fallback);
            total
        },
    ))
}

#[cfg(test)]
mod tests {
    use aya::programs::SchedClassifier;
    use std::net::Ipv4Addr;

    fn flow_key(src: u32, dst: u32, sport: u16, dport: u16) -> edge_lb_common::NativeFlowKey {
        edge_lb_common::NativeFlowKey {
            src,
            dst,
            sport: sport.to_be(),
            dport: dport.to_be(),
            proto: 6,
            _pad: [0; 3],
        }
    }

    #[test]
    fn flow_expiry_uses_monotonic_nanoseconds() {
        assert!(!super::flow_expired(0, 1, 10_000_000_000));
        assert!(!super::flow_expired(1_000_000_000, 0, 10_000_000_000));
        assert!(!super::flow_expired(1_000_000_000, 10, 5_000_000_000));
        assert!(super::flow_expired(1_000_000_000, 3, 5_000_000_001));
    }

    #[test]
    fn canonical_flow_pair_is_identical_from_both_directions() {
        let forward = flow_key(0x0a00_0001, 0xc0a8_000a, 40000, 80);
        let reverse = flow_key(0xc0a8_000b, 0x0a00_0001, 8080, 40000);
        let value = edge_lb_common::NativeFlowValue {
            vip: 0xc0a8_000a,
            target: 0xc0a8_000b,
            vip_port: 80_u16.to_be(),
            target_port: 8080,
            ..edge_lb_common::NativeFlowValue::default()
        };
        assert_eq!(
            super::canonical_flow_pair(forward, value),
            super::canonical_flow_pair(reverse, value)
        );
    }

    #[test]
    fn preferences_are_disjoint_from_marker() {
        assert_eq!(super::INGRESS_PREF_OFFSET, 10);
        assert_eq!(super::RETURN_PREF_OFFSET, 11);
    }

    #[test]
    fn health_identity_uses_forwarding_port_not_probe_port() {
        let target = crate::provider::native::TargetHealthEntry {
            host_name: "192.0.2.10".to_string(),
            name: "web:192.0.2.10_tcp_8080".to_string(),
            target_group: "web".to_string(),
            probe_type: Some("http".to_string()),
            probe_port: Some(9090),
            current_state: Some("nok".to_string()),
            ..crate::provider::native::TargetHealthEntry::default()
        };
        let list = super::TargetHealthList {
            entries: vec![target],
        };

        assert!(!super::observed_target_is_active(
            Some(&list),
            "web",
            "192.0.2.10".parse().unwrap(),
            6,
            8080,
        ));
    }

    #[test]
    fn native_target_active_requires_config_and_observed_health() {
        let listener = crate::provider::native::NativeListener {
            name: "web-tcp".to_string(),
            target_group: "web".to_string(),
            key: crate::provider::native::NativeListenerKey {
                vip_ip: Ipv4Addr::new(198, 51, 100, 10),
                vip_port: 80,
                protocol: crate::provider::native::NativeProtocol::Tcp,
            },
            select: 0,
            inactive_timeout_secs: 60,
            dscp: 46,
            targets: Vec::new(),
        };
        let mut target = crate::provider::native::NativeTarget {
            address: Ipv4Addr::new(192, 0, 2, 10),
            port: 8080,
            weight: 1,
            state: crate::provider::native::NativeTargetState::Active,
        };

        assert!(super::native_target_is_active(None, &listener, &target));

        let ok = super::TargetHealthList {
            entries: vec![crate::provider::native::TargetHealthEntry {
                host_name: "192.0.2.10".to_string(),
                name: "web:192.0.2.10_tcp_8080".to_string(),
                target_group: "web".to_string(),
                current_state: Some("ok".to_string()),
                ..crate::provider::native::TargetHealthEntry::default()
            }],
        };
        assert!(super::native_target_is_active(
            Some(&ok),
            &listener,
            &target
        ));

        let nok = super::TargetHealthList {
            entries: vec![crate::provider::native::TargetHealthEntry {
                host_name: "192.0.2.10".to_string(),
                name: "web:192.0.2.10_tcp_8080".to_string(),
                target_group: "web".to_string(),
                current_state: Some("nok".to_string()),
                ..crate::provider::native::TargetHealthEntry::default()
            }],
        };
        assert!(!super::native_target_is_active(
            Some(&nok),
            &listener,
            &target
        ));

        target.state = crate::provider::native::NativeTargetState::Inactive;
        assert!(!super::native_target_is_active(
            Some(&ok),
            &listener,
            &target
        ));
    }

    fn listener(
        ip: [u8; 4],
        port: u16,
        protocol: crate::provider::native::NativeProtocol,
    ) -> crate::provider::native::NativeListener {
        crate::provider::native::NativeListener {
            name: format!("{protocol:?}-{port}"),
            target_group: "targets".to_string(),
            key: crate::provider::native::NativeListenerKey {
                vip_ip: Ipv4Addr::from(ip),
                vip_port: port,
                protocol,
            },
            select: 0,
            inactive_timeout_secs: 60,
            dscp: 46,
            targets: Vec::new(),
        }
    }

    #[test]
    fn stable_listener_ids_do_not_depend_on_config_order() {
        let first = vec![
            listener(
                [192, 0, 2, 10],
                80,
                crate::provider::native::NativeProtocol::Tcp,
            ),
            listener(
                [192, 0, 2, 10],
                80,
                crate::provider::native::NativeProtocol::Udp,
            ),
            listener(
                [192, 0, 2, 11],
                443,
                crate::provider::native::NativeProtocol::Tcp,
            ),
        ];
        let mut second = first.clone();
        second.reverse();

        let mut first_ids = super::stable_listener_assignments(&first)
            .expect("assign first")
            .into_iter()
            .map(|(id, listener)| (super::listener_sort_key(listener), id))
            .collect::<Vec<_>>();
        let mut second_ids = super::stable_listener_assignments(&second)
            .expect("assign second")
            .into_iter()
            .map(|(id, listener)| (super::listener_sort_key(listener), id))
            .collect::<Vec<_>>();
        first_ids.sort();
        second_ids.sort();

        assert_eq!(first_ids, second_ids);
        assert_eq!(
            first_ids
                .iter()
                .map(|(_, id)| *id)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            first_ids.len()
        );
    }

    #[test]
    fn consistent_hash_bucket_generation_tracks_health() {
        let mut listener = listener(
            [192, 0, 2, 10],
            5060,
            crate::provider::native::NativeProtocol::Udp,
        );
        listener.select = crate::config::LbSelect::ConsistentHash.code();
        listener.targets = vec![
            crate::provider::native::NativeTarget {
                address: Ipv4Addr::new(192, 0, 2, 20),
                port: 5060,
                weight: 1,
                state: crate::provider::native::NativeTargetState::Active,
            },
            crate::provider::native::NativeTarget {
                address: Ipv4Addr::new(192, 0, 2, 21),
                port: 5060,
                weight: 1,
                state: crate::provider::native::NativeTargetState::Active,
            },
        ];
        let listener_ids = vec![(1, &listener)];

        let desired = super::desired_consistent_hash_buckets(&listener_ids, None)
            .expect("build buckets without observed health");
        assert_eq!(
            desired.len(),
            edge_lb_common::NATIVE_CONSISTENT_HASH_BUCKETS as usize
        );
        assert!(desired.values().any(|value| value.target_id == 0));
        assert!(desired.values().any(|value| value.target_id == 1));

        let unhealthy = super::TargetHealthList {
            entries: vec![crate::provider::native::TargetHealthEntry {
                host_name: "192.0.2.20".to_string(),
                name: "targets:192.0.2.20_udp_5060".to_string(),
                target_group: "targets".to_string(),
                current_state: Some("nok".to_string()),
                ..crate::provider::native::TargetHealthEntry::default()
            }],
        };
        let desired = super::desired_consistent_hash_buckets(&listener_ids, Some(&unhealthy))
            .expect("build buckets with observed health");
        assert_eq!(
            desired.len(),
            edge_lb_common::NATIVE_CONSISTENT_HASH_BUCKETS as usize
        );
        assert!(desired.values().all(|value| value.target_id == 1));
    }

    #[test]
    fn consistent_hash_buckets_are_not_generated_for_other_selectors() {
        let mut listener = listener(
            [192, 0, 2, 10],
            5060,
            crate::provider::native::NativeProtocol::Udp,
        );
        listener.targets = vec![crate::provider::native::NativeTarget {
            address: Ipv4Addr::new(192, 0, 2, 20),
            port: 5060,
            weight: 1,
            state: crate::provider::native::NativeTargetState::Active,
        }];
        let listener_ids = vec![(1, &listener)];

        let desired =
            super::desired_consistent_hash_buckets(&listener_ids, None).expect("build buckets");
        assert!(desired.is_empty());
    }

    /// Load the ingress classifier without attaching. Privileged only; on
    /// failure the full verifier log is printed so load errors (e.g. the
    /// E2BIG truncated-log case seen in containers) are diagnosable.
    #[test]
    fn native_ingress_program_loads_when_privileged() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/bpfel-unknown-none/release/edge-lb-ebpf");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: {} not built", path.display());
            return;
        };
        let mut bpf = match aya::Ebpf::load(&bytes) {
            Ok(bpf) => bpf,
            Err(e) => panic!("Ebpf::load failed: {e}"),
        };
        let program: &mut SchedClassifier = bpf
            .program_mut(edge_lb_common::NATIVE_DNAT_INGRESS_PROGRAM)
            .expect("native_dnat_ingress missing")
            .try_into()
            .expect("not a classifier");
        if let Err(e) = program.load() {
            let log = match &e {
                aya::programs::ProgramError::LoadError { verifier_log, .. } => {
                    format!("{verifier_log}")
                }
                other => format!("{other}"),
            };
            panic!("program load failed: {e}\n--- full verifier log ---\n{log}");
        }
    }
}
