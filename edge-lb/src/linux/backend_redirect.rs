//! Backend Redirect-only return-path eBPF loader.

use std::{
    collections::HashSet,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket},
    path::PathBuf,
    thread::sleep,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use aya::{
    Ebpf,
    maps::{HashMap, MapData},
    programs::tc::{
        NlOptions, SchedClassifier, TcAttachOptions, TcAttachType, TcHandle, qdisc_detach_program,
    },
};
use edge_lb_common::backend_redirect::{
    BACKEND_RETURN_DSCP_MAP, BACKEND_RETURN_EGRESS_PROGRAM, BACKEND_RETURN_FLOWS_MAP,
    BACKEND_RETURN_INGRESS_PROGRAM, BACKEND_RETURN_STATS_MAP, BackendReturnDscp,
};

use crate::config::{Config, GatewayReturnPath};

const MAPS: [&str; 3] = [
    BACKEND_RETURN_DSCP_MAP,
    BACKEND_RETURN_FLOWS_MAP,
    BACKEND_RETURN_STATS_MAP,
];
const INGRESS_PREF_OFFSET: u16 = 20;
const EGRESS_PREF_OFFSET: u16 = 21;
const DEFAULT_PREF: u16 = 1;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_ebpf.rs"));
}

pub struct BackendRedirectAttachment {
    _bpf: Option<Ebpf>,
    pin_dir: PathBuf,
    vxlan_dev: String,
    underlay_dev: String,
    pref: u16,
}

static CURRENT: std::sync::Mutex<Option<BackendRedirectAttachment>> = std::sync::Mutex::new(None);

impl Drop for BackendRedirectAttachment {
    fn drop(&mut self) {
        let _ = qdisc_detach_program(
            &self.vxlan_dev,
            TcAttachType::Ingress,
            BACKEND_RETURN_INGRESS_PROGRAM,
        );
        let _ = qdisc_detach_program(
            &self.underlay_dev,
            TcAttachType::Ingress,
            BACKEND_RETURN_INGRESS_PROGRAM,
        );
        let _ = qdisc_detach_program(
            &self.underlay_dev,
            TcAttachType::Egress,
            BACKEND_RETURN_EGRESS_PROGRAM,
        );
        crate::linux::tc::delete_ingress_pref_best_effort(
            &self.vxlan_dev,
            self.pref + INGRESS_PREF_OFFSET,
        );
        crate::linux::tc::delete_ingress_pref_best_effort(
            &self.underlay_dev,
            self.pref + INGRESS_PREF_OFFSET,
        );
        crate::linux::tc::delete_egress_pref_best_effort(
            &self.underlay_dev,
            self.pref + EGRESS_PREF_OFFSET,
        );
        for name in MAPS {
            let _ = fs::remove_file(self.pin_dir.join(name));
        }
        let _ = fs::remove_dir(&self.pin_dir);
    }
}

impl BackendRedirectAttachment {
    fn matches_config(&self, cfg: &Config) -> bool {
        let n = cfg.network();
        self.vxlan_dev == n.vxlan_dev
            && self.underlay_dev == n.underlay_dev
            && self.pref == DEFAULT_PREF
    }
}

fn pin_dir(cfg: &Config) -> PathBuf {
    cfg.pin_dir().join("backend-redirect")
}

fn pin_path(cfg: &Config, name: &str) -> PathBuf {
    pin_dir(cfg).join(name)
}

fn read_object() -> Result<Vec<u8>> {
    if let Some(bytes) = embedded::embedded_ebpf() {
        return Ok(bytes.to_vec());
    }
    Err(anyhow!(
        "backend Redirect eBPF object is not embedded; build with `make release`"
    ))
}

fn prepare_object() -> Result<Ebpf> {
    let mut bpf = Ebpf::load(&read_object()?).context("loading backend Redirect object")?;
    for name in [
        BACKEND_RETURN_INGRESS_PROGRAM,
        BACKEND_RETURN_EGRESS_PROGRAM,
    ] {
        let program: &mut SchedClassifier = bpf
            .program_mut(name)
            .with_context(|| format!("missing {name}"))?
            .try_into()?;
        program
            .load()
            .with_context(|| format!("verifying {name}; existing attachment retained"))?;
    }
    Ok(bpf)
}

fn attach_prepared(cfg: &Config, mut bpf: Ebpf) -> Result<BackendRedirectAttachment> {
    let paths = cfg.backend_return_paths();
    if paths.is_empty() {
        bail!("backend Redirect requires at least one return path");
    }
    let n = cfg.network();
    let pin_dir = pin_dir(cfg);
    fs::create_dir_all(&pin_dir)
        .with_context(|| format!("failed to create {}", pin_dir.display()))?;
    for name in MAPS {
        let _ = fs::remove_file(pin_path(cfg, name));
    }
    {
        let mut dscp: HashMap<&mut MapData, u32, BackendReturnDscp> = HashMap::try_from(
            bpf.map_mut(BACKEND_RETURN_DSCP_MAP)
                .with_context(|| format!("{BACKEND_RETURN_DSCP_MAP} map missing"))?,
        )?;
        for path in paths {
            dscp.insert(path.dscp, return_contract(cfg, &path)?, 0)?;
        }
    }
    for name in MAPS {
        bpf.map(name)
            .ok_or_else(|| anyhow!("{name} map missing"))?
            .pin(pin_path(cfg, name))
            .with_context(|| format!("pinning backend Redirect map {name}"))?;
    }

    let pref = DEFAULT_PREF;
    crate::linux::tc::add_clsact_best_effort(&n.vxlan_dev);
    crate::linux::tc::add_clsact_best_effort(&n.underlay_dev);
    crate::linux::tc::delete_ingress_pref_best_effort(&n.vxlan_dev, pref + INGRESS_PREF_OFFSET);
    crate::linux::tc::delete_ingress_pref_best_effort(&n.underlay_dev, pref + INGRESS_PREF_OFFSET);
    crate::linux::tc::delete_egress_pref_best_effort(&n.underlay_dev, pref + EGRESS_PREF_OFFSET);
    attach_program(
        &mut bpf,
        BACKEND_RETURN_INGRESS_PROGRAM,
        &n.underlay_dev,
        TcAttachType::Ingress,
        pref + INGRESS_PREF_OFFSET,
    )?;
    attach_program(
        &mut bpf,
        BACKEND_RETURN_EGRESS_PROGRAM,
        &n.underlay_dev,
        TcAttachType::Egress,
        pref + EGRESS_PREF_OFFSET,
    )?;
    Ok(BackendRedirectAttachment {
        _bpf: Some(bpf),
        pin_dir,
        vxlan_dev: n.vxlan_dev.clone(),
        underlay_dev: n.underlay_dev.clone(),
        pref,
    })
}

fn return_contract(cfg: &Config, path: &GatewayReturnPath) -> Result<BackendReturnDscp> {
    let gateway_overlay = match path.gateway_overlay_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => bail!("backend Redirect only supports IPv4 gateway overlay {ip}"),
    };
    nudge_overlay_neighbor(gateway_overlay);
    let observed = crate::linux::redirect::observe_target_routes(&[gateway_overlay])?
        .into_iter()
        .next()
        .context("gateway overlay route observation missing")?;
    let n = cfg.network();
    ensure!(
        observed.device.as_deref() == Some(&n.vxlan_dev),
        "gateway overlay {} resolves through {:?}, expected {}",
        gateway_overlay,
        observed.device,
        n.vxlan_dev
    );
    let return_ifindex = observed
        .ifindex
        .context("gateway overlay route has no output ifindex")?;
    let source_mac = observed
        .source_mac
        .context("gateway overlay route has no source MAC")?;
    let destination_mac = observed
        .destination_mac
        .context("gateway overlay route has no destination MAC")?;
    Ok(BackendReturnDscp {
        flags: 1,
        return_ifindex,
        source_mac,
        destination_mac,
        _pad: [0; 4],
    })
}

fn nudge_overlay_neighbor(gateway_overlay: Ipv4Addr) {
    let Ok(socket) = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)) else {
        return;
    };
    let _ = socket.set_write_timeout(Some(Duration::from_millis(200)));
    let _ = socket.connect(SocketAddrV4::new(gateway_overlay, 9));
    let _ = socket.send(&[0]);
    sleep(Duration::from_millis(100));
}

fn attach_program(
    bpf: &mut Ebpf,
    name: &str,
    dev: &str,
    attach_type: TcAttachType,
    priority: u16,
) -> Result<()> {
    let program: &mut SchedClassifier = bpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("{name} program missing"))?
        .try_into()
        .with_context(|| format!("{name} is not a TC classifier"))?;
    program
        .attach_with_options(
            dev,
            attach_type,
            TcAttachOptions::Netlink(NlOptions {
                priority,
                handle: TcHandle::from(1),
                classid: None,
            }),
        )
        .with_context(|| format!("attaching {name} to {dev} {attach_type:?} pref {priority}"))?;
    Ok(())
}

pub fn apply(cfg: &Config) -> Result<()> {
    let mut current = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(active) = current.as_ref()
        && active.matches_config(cfg)
        && maps_match_contract(cfg)
    {
        return Ok(());
    }
    let prepared = prepare_object()?;
    if let Some(old) = current.take() {
        drop(old);
    }
    *current = Some(attach_prepared(cfg, prepared)?);
    Ok(())
}

pub fn cleanup(cfg: &Config) {
    let mut current = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = current.take() {
        drop(old);
    }
    let n = cfg.network();
    crate::linux::tc::delete_ingress_pref_best_effort(
        &n.vxlan_dev,
        DEFAULT_PREF + INGRESS_PREF_OFFSET,
    );
    crate::linux::tc::delete_ingress_pref_best_effort(
        &n.underlay_dev,
        DEFAULT_PREF + INGRESS_PREF_OFFSET,
    );
    crate::linux::tc::delete_egress_pref_best_effort(
        &n.underlay_dev,
        DEFAULT_PREF + EGRESS_PREF_OFFSET,
    );
    for name in MAPS {
        let _ = fs::remove_file(pin_path(cfg, name));
    }
    let _ = fs::remove_dir(pin_dir(cfg));
}

fn maps_match_contract(cfg: &Config) -> bool {
    let Ok(map_data) = MapData::from_pin(pin_path(cfg, BACKEND_RETURN_DSCP_MAP)) else {
        return false;
    };
    let Ok(map) = aya::maps::Map::from_map_data(map_data) else {
        return false;
    };
    let Ok(map): Result<HashMap<MapData, u32, BackendReturnDscp>, _> = HashMap::try_from(map)
    else {
        return false;
    };
    let paths = cfg.backend_return_paths();
    let desired = paths.iter().map(|path| path.dscp).collect::<HashSet<_>>();
    let Ok(actual) = map.keys().collect::<Result<HashSet<_>, _>>() else {
        return false;
    };
    actual == desired
        && paths.iter().all(|path| match return_contract(cfg, path) {
            Ok(expected) => map.get(&path.dscp, 0).is_ok_and(|value| value == expected),
            Err(_) => false,
        })
}
