//! DSCP marker eBPF loader (Aya). The classifier is attached at
//! `eth0 ingress`, ahead of the native datapath, and its
//! maps stay pinned under the agent-owned bpffs dir for stats and live
//! reconfiguration.

use std::{collections::BTreeSet, fs, path::Path, path::PathBuf, time::Duration};

use anyhow::{Context, Result, anyhow};
use aya::{
    Ebpf,
    maps::{Array, HashMap, Map, MapData, PerCpuArray},
    programs::tc::{
        NlOptions, SchedClassifier, TcAttachOptions, TcAttachType, TcHandle, qdisc_detach_program,
    },
};
use edge_lb_common::{DSCP_PORT_MAP_CAPACITY, MAX_PORTS, Stats};

use crate::config::Config;

use super::tc;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_ebpf.rs"));
}

const TARGET_PORTS: &str = "TARGET_PORTS";
const DSCP_CFG: &str = "DSCP_CFG";
const STATS: &str = "STATS";
static MAP_UPDATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub struct DscpAttachment {
    bpf: Option<Ebpf>,
    pin_dir: PathBuf,
}

impl DscpAttachment {
    pub fn persist(mut self) {
        if let Some(bpf) = self.bpf.take() {
            std::mem::forget(bpf);
        }
        std::mem::forget(self);
    }
}

impl Drop for DscpAttachment {
    fn drop(&mut self) {
        self.bpf.take();
        for name in [TARGET_PORTS, DSCP_CFG, STATS] {
            let path = self.pin_dir.join(name);
            if path.exists() {
                fs::remove_file(path).ok();
            }
        }
        fs::remove_dir(&self.pin_dir).ok();
    }
}

fn pin_dir(cfg: &Config) -> PathBuf {
    cfg.pin_dir()
}

fn pin_path(cfg: &Config, name: &str) -> std::path::PathBuf {
    pin_dir(cfg).join(name)
}

pub fn config_pin(cfg: &Config) -> PathBuf {
    pin_path(cfg, DSCP_CFG)
}

/// True when our bpf filter sits at the configured priority on `dev`.
pub fn attached(cfg: &Config, dev: &str) -> bool {
    let out = tc::show_ingress(dev).unwrap_or_default();
    out.lines()
        .any(|line| line.contains(&format!("pref {}", pref(cfg))) && line.contains("dscp_mark"))
}

/// All marker maps must match before an existing attachment can be reused.
pub fn maps_match_current_abi(cfg: &Config) -> bool {
    pinned_ports(cfg).is_ok()
        && pinned_array::<u32>(cfg, DSCP_CFG).is_ok()
        && pinned_per_cpu_array::<Stats>(cfg, STATS)
            .and_then(|stats| stats.get(&0, 0).map(|_| ()).map_err(Into::into))
            .is_ok()
}

/// Load, configure and attach the marker. Replaces any previous filter at
/// the same priority so repeated applies converge.
#[allow(clippy::too_many_arguments)]
pub fn attach(
    cfg: &Config,
    dev: &str,
    dscp: u32,
    ports: &[u32],
    object_override: Option<&Path>,
) -> Result<()> {
    attach_owned(cfg, dev, dscp, ports, object_override)?.persist();
    Ok(())
}

pub fn attach_owned(
    cfg: &Config,
    dev: &str,
    dscp: u32,
    ports: &[u32],
    object_override: Option<&Path>,
) -> Result<DscpAttachment> {
    validate(dscp, ports)?;
    let _guard = MAP_UPDATE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let bytes = read_object(object_override)?;
    let mut bpf = Ebpf::load(&bytes).context("failed to load eBPF object")?;

    let pin_dir = pin_dir(cfg);
    fs::create_dir_all(&pin_dir)
        .with_context(|| format!("failed to create {}", pin_dir.display()))?;
    for name in [TARGET_PORTS, DSCP_CFG, STATS] {
        let path = pin_path(cfg, name);
        if path.exists() {
            fs::remove_file(&path).ok();
        }
    }

    write_ports(
        &mut HashMap::<&mut MapData, u32, u32>::try_from(
            bpf.map_mut(TARGET_PORTS)
                .ok_or_else(|| anyhow!("{TARGET_PORTS} map not found"))?,
        )?,
        ports,
    )?;
    let mut cfg_map: Array<&mut MapData, u32> = Array::try_from(
        bpf.map_mut(DSCP_CFG)
            .ok_or_else(|| anyhow!("{DSCP_CFG} map not found"))?,
    )?;
    cfg_map.set(0, dscp, 0)?;

    for name in [TARGET_PORTS, DSCP_CFG, STATS] {
        bpf.map(name)
            .ok_or_else(|| anyhow!("{name} map not found"))?
            .pin(pin_path(cfg, name))
            .with_context(|| format!("pinning {name}"))?;
    }

    tc::add_clsact_best_effort(dev);
    // Detach a previous instance of ourselves (best effort) before attaching.
    tc::delete_ingress_pref_best_effort(dev, pref(cfg));
    let program: &mut SchedClassifier = bpf
        .program_mut(edge_lb_common::PROGRAM_NAME)
        .ok_or_else(|| anyhow!("{} program not found", edge_lb_common::PROGRAM_NAME))?
        .try_into()
        .context("program is not a TC classifier")?;
    program.load().context("failed to load TC classifier")?;
    program
        .attach_with_options(
            dev,
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions {
                priority: pref(cfg),
                handle: TcHandle::from(1),
                classid: None,
            }),
        )
        .with_context(|| format!("failed to attach {dev} ingress pref {}", pref(cfg)))?;

    Ok(DscpAttachment {
        bpf: Some(bpf),
        pin_dir,
    })
}

fn read_object(object_override: Option<&Path>) -> Result<Vec<u8>> {
    if let Some(object) = object_override {
        return fs::read(object)
            .with_context(|| format!("failed to read eBPF object {}", object.display()));
    }

    if let Some(bytes) = embedded::embedded_ebpf() {
        return Ok(bytes.to_vec());
    }

    Err(anyhow!(
        "eBPF object is not embedded; build with `make release` or pass `--object <path>` for DSCP marker debugging"
    ))
}

pub fn detach(cfg: &Config, dev: &str) -> Result<()> {
    let _guard = MAP_UPDATE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    qdisc_detach_program(dev, TcAttachType::Ingress, edge_lb_common::PROGRAM_NAME).ok();
    tc::delete_ingress_pref_best_effort(dev, pref(cfg));
    for name in [TARGET_PORTS, DSCP_CFG, STATS] {
        let path = pin_path(cfg, name);
        if path.exists() {
            fs::remove_file(&path).ok();
        }
    }
    fs::remove_dir(pin_dir(cfg)).ok();
    Ok(())
}

pub fn pref(cfg: &Config) -> u16 {
    cfg.gateway_cfg().dscp_pref
}

/// Update ports/DSCP on the pinned maps of an already-running marker.
pub fn set(cfg: &Config, dscp: u32, ports: &[u32]) -> Result<()> {
    validate(dscp, ports)?;
    let _guard = MAP_UPDATE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut ports_map = pinned_ports(cfg)?;
    let mut cfg_map: Array<MapData, u32> = pinned_array(cfg, DSCP_CFG)?;
    write_ports(&mut ports_map, ports)?;
    if cfg_map.get(&0, 0)? != dscp {
        cfg_map.set(0, dscp, 0)?;
    }
    Ok(())
}

pub fn stats(cfg: &Config) -> Result<Stats> {
    let stats: PerCpuArray<MapData, Stats> = pinned_per_cpu_array(cfg, STATS)?;
    let values = stats
        .get(&0, 0)
        .map_err(|e| anyhow!("reading STATS: {e}"))?;
    Ok(sum_stats(values.iter().copied()))
}

/// Open a pinned map file as a typed array.
fn pinned_array<V: aya::Pod>(cfg: &Config, name: &str) -> Result<Array<MapData, V>> {
    let data =
        MapData::from_pin(pin_path(cfg, name)).with_context(|| format!("{name} is not pinned"))?;
    let map = Map::from_map_data(data).map_err(|e| anyhow!("opening {name}: {e}"))?;
    Array::try_from(map).map_err(|e| anyhow!("{name} is not an array map: {e}"))
}

fn pinned_ports(cfg: &Config) -> Result<HashMap<MapData, u32, u32>> {
    let data = MapData::from_pin(pin_path(cfg, TARGET_PORTS))?;
    let info = data.info()?;
    if info.map_type()? != aya::maps::MapType::Hash || info.max_entries() != DSCP_PORT_MAP_CAPACITY
    {
        return Err(anyhow!("TARGET_PORTS capacity does not match current ABI"));
    }
    HashMap::try_from(Map::from_map_data(data)?).context("TARGET_PORTS is not a port hash map")
}

/// Open a pinned map file as a typed per-CPU array.
fn pinned_per_cpu_array<V: aya::Pod>(cfg: &Config, name: &str) -> Result<PerCpuArray<MapData, V>> {
    let data =
        MapData::from_pin(pin_path(cfg, name)).with_context(|| format!("{name} is not pinned"))?;
    let map = Map::from_map_data(data).map_err(|e| anyhow!("opening {name}: {e}"))?;
    PerCpuArray::try_from(map).map_err(|e| anyhow!("{name} is not a per-CPU array map: {e}"))
}

fn sum_stats(values: impl IntoIterator<Item = Stats>) -> Stats {
    values
        .into_iter()
        .fold(Stats::default(), |mut total, value| {
            total.matched = total.matched.saturating_add(value.matched);
            total.changed = total.changed.saturating_add(value.changed);
            total
        })
}

fn validate(dscp: u32, ports: &[u32]) -> Result<()> {
    if dscp >= 64 {
        return Err(anyhow!("DSCP must be in 0..63, got {dscp}"));
    }
    let unique: BTreeSet<_> = ports.iter().copied().collect();
    if unique.len() > MAX_PORTS {
        return Err(anyhow!(
            "too many ports: max {MAX_PORTS}, got {}",
            unique.len()
        ));
    }
    for p in ports {
        if *p == 0 || *p > 65535 {
            return Err(anyhow!("port out of range: {p}"));
        }
    }
    Ok(())
}

fn write_ports<T: std::borrow::BorrowMut<MapData>>(
    map: &mut HashMap<T, u32, u32>,
    ports: &[u32],
) -> Result<()> {
    let desired: BTreeSet<_> = ports.iter().copied().collect();
    let existing = map
        .iter()
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    // Upsert before pruning. Common ports never disappear, even when all
    // slots in the configured set change. The map reserves room for both sets.
    let mut inserted = Vec::new();
    for port in &desired {
        if existing.get(port) != Some(&1) {
            if let Err(error) = map.insert(*port, 1, 0) {
                for key in inserted {
                    if let Err(rollback) = map.remove(&key) {
                        tracing::warn!("[dscp] rolling back port {key} failed: {rollback}");
                    }
                }
                return Err(error.into());
            }
            if !existing.contains_key(port) {
                inserted.push(*port);
            }
        }
    }
    for port in existing.keys().filter(|port| !desired.contains(port)) {
        map.remove(port)?;
    }
    Ok(())
}

/// Wait until `bpffs` shows our pins (mount races after boot).
pub fn wait_for_bpffs(timeout: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if Path::new("/sys/fs/bpf").exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(anyhow!("/sys/fs/bpf (bpffs) not mounted"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_validation_counts_unique_ports_and_accepts_an_empty_set() {
        assert!(validate(0, &[]).is_ok());
        assert!(validate(63, &[8080; MAX_PORTS + 1]).is_ok());
        assert!(validate(64, &[8080]).is_err());
        assert!(validate(46, &[0]).is_err());
        assert!(validate(46, &[65536]).is_err());
        assert!(validate(46, &(1..=MAX_PORTS as u32 + 1).collect::<Vec<_>>()).is_err());
    }

    #[test]
    fn port_hash_map_reconciles_full_sets_without_replacing_the_map() {
        use aya::maps::IterableMap;
        let bytes =
            read_object(None).expect("build the eBPF object before running privileged tests");
        let mut bpf = Ebpf::load(&bytes).unwrap();
        let mut ports =
            HashMap::<_, u32, u32>::try_from(bpf.map_mut(TARGET_PORTS).unwrap()).unwrap();
        let id = ports.map().info().unwrap().id();
        let first: Vec<u32> = (1..=MAX_PORTS as u32).collect();
        let second: Vec<u32> = (100..100 + MAX_PORTS as u32).collect();
        write_ports(&mut ports, &first).unwrap();
        assert_eq!(ports.keys().count(), MAX_PORTS);
        write_ports(&mut ports, &second).unwrap();
        assert_eq!(ports.keys().count(), MAX_PORTS);
        for port in first {
            assert!(ports.get(&port, 0).is_err());
        }
        for port in second {
            assert_eq!(ports.get(&port, 0).unwrap(), 1);
        }
        write_ports(&mut ports, &[80, 8080, 8080]).unwrap();
        assert_eq!(ports.keys().count(), 2);
        write_ports(&mut ports, &[8080]).unwrap();
        assert!(ports.get(&80, 0).is_err());
        write_ports(&mut ports, &[]).unwrap();
        assert_eq!(
            ports.keys().count(),
            0,
            "an empty map must not implicitly mark port 80"
        );
        assert_eq!(ports.map().info().unwrap().id(), id);
        let program: &mut SchedClassifier = bpf
            .program_mut(edge_lb_common::PROGRAM_NAME)
            .unwrap()
            .try_into()
            .unwrap();
        program
            .load()
            .expect("kernel verifier must accept the hash-map classifier");
    }

    #[test]
    fn stats_sum_adds_per_cpu_values() {
        let total = sum_stats([
            Stats {
                matched: 3,
                changed: 4,
            },
            Stats {
                matched: 30,
                changed: 40,
            },
        ]);

        assert_eq!(
            total,
            Stats {
                matched: 33,
                changed: 44,
            }
        );
    }

    /// The eBPF object (when built) must expose the classifier under the
    /// name the loader looks up, with all three maps.
    #[test]
    fn ebpf_object_loads_with_expected_program() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/bpfel-unknown-none/release/edge-lb-ebpf");
        let Ok(bytes) = fs::read(&path) else {
            // Object not built on this host; skip rather than fail.
            eprintln!("skipping: {} not built", path.display());
            return;
        };
        let bpf = Ebpf::load(&bytes).expect("aya must load the object");
        let program = bpf
            .program(edge_lb_common::PROGRAM_NAME)
            .expect("dscp_mark program must be found by name");
        let loaded: Result<&SchedClassifier, _> = program.try_into();
        assert!(loaded.is_ok(), "dscp_mark must be a TC classifier");
        for map in [TARGET_PORTS, DSCP_CFG, STATS] {
            assert!(bpf.map(map).is_some(), "{map} map missing");
        }
    }
}
