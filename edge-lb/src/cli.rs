//! Command-line surface: `edge-lb [gateway|backend] ...|ui|verify|config`.
//! With no command, the configured `node_role` runs its normal daemon mode.

use std::{net::IpAddr, path::PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::DEFAULT_CONFIG_PATH;

#[derive(Parser, Debug)]
#[command(
    name = "edge-lb",
    version,
    about = "Edge LB agent: VXLAN return-path load balancing with the native datapath",
    propagate_version = true
)]
pub struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    pub config: PathBuf,

    /// Override the state directory from the config file.
    #[arg(long, global = true)]
    pub state_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Manage the gateway node.
    #[command(hide = true)]
    Gateway(GatewayArgs),
    /// Manage the backend node.
    #[command(hide = true)]
    Backend(BackendArgs),
    /// Serve the management UI and HTTP API.
    Ui {
        #[command(subcommand)]
        command: UiCommand,
    },
    /// Run end-to-end verification against the deployed path.
    Verify(VerifyArgs),
    /// Configuration utilities.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Install edge-lb as a system service.
    Install(InstallArgs),
    /// Uninstall edge-lb system service.
    Uninstall {
        #[command(subcommand)]
        command: UninstallCommand,
    },
    /// Internal helper commands used by managed hooks.
    #[command(hide = true)]
    Internal {
        #[command(subcommand)]
        command: InternalCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum InternalCommand {
    /// Send a managed HA hook event to the local gateway daemon.
    KaHookSend {
        /// Unix socket path exposed by the gateway daemon.
        #[arg(long)]
        socket: PathBuf,
        /// HA cluster instance name.
        #[arg(long)]
        instance: String,
        /// HA state, e.g. MASTER, BACKUP, STOP.
        #[arg(long)]
        state: String,
        /// VIP argument passed by the HA hook.
        #[arg(long)]
        vip: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum UiCommand {
    /// Start the HTTP API and static UI server.
    Serve {
        /// Listen address, e.g. 127.0.0.1:18080 or 0.0.0.0:18080.
        /// Non-loopback listeners require auth_token in the config.
        #[arg(long)]
        listen: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Validate the effective configuration (file + overrides) and exit.
    Validate {
        #[command(flatten)]
        overrides: Overrides,
    },
    /// Write the effective configuration to the config path (bootstrap aid).
    Init {
        #[command(flatten)]
        overrides: Overrides,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum UninstallCommand {
    /// Stop, disable and remove the systemd unit only.
    Service(UninstallServiceArgs),
}

#[derive(Args, Debug)]
pub struct InstallArgs {
    /// Optional role, for example `install gateway`.
    #[arg(value_enum)]
    pub role: Option<InstallRole>,

    /// Optional node identity and discovery overrides written to config.
    #[arg(long)]
    pub node_name: Option<String>,
    #[arg(long)]
    pub public_ip: Option<IpAddr>,
    #[arg(long)]
    pub underlay_ip: Option<IpAddr>,
    #[arg(long)]
    pub underlay_dev: Option<String>,
    #[arg(long)]
    pub vni: Option<u32>,
    #[arg(long)]
    pub vxlan_port: Option<u16>,
    #[arg(long)]
    pub dscp: Option<u32>,

    /// Install prefix for the binary.
    #[arg(long, default_value = "/usr/local")]
    pub prefix: PathBuf,

    /// systemd unit name.
    #[arg(long, default_value = "edge-lb")]
    pub service_name: String,

    /// Overwrite an existing config file.
    #[arg(long)]
    pub force: bool,

    /// Do not start the service after installing it.
    #[arg(long)]
    pub no_start: bool,
}

#[derive(Args, Debug)]
pub struct UninstallServiceArgs {
    /// systemd unit name.
    #[arg(long, default_value = "edge-lb")]
    pub service_name: String,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum InstallRole {
    Gateway,
    Backend,
}

impl InstallRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Backend => "backend",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_command_uses_configured_role_at_runtime() {
        let cli = Cli::try_parse_from(["edge-lb", "--config", "/etc/edge-lb/config.toml"])
            .expect("CLI should accept no subcommand");
        assert!(cli.command.is_none());
    }

    #[test]
    fn install_role_has_one_explicit_parameter_form() {
        let cli = Cli::try_parse_from([
            "edge-lb",
            "install",
            "gateway",
            "--node-name",
            "gateway-a",
            "--underlay-ip",
            "192.0.2.10",
        ])
        .expect("install role arguments should parse");
        let Some(Commands::Install(args)) = cli.command else {
            panic!("expected install command");
        };
        assert!(matches!(args.role, Some(InstallRole::Gateway)));
        assert_eq!(args.node_name.as_deref(), Some("gateway-a"));
        assert_eq!(args.underlay_ip, Some("192.0.2.10".parse().unwrap()));
    }

    #[test]
    fn install_role_accepts_positional_form() {
        let cli = Cli::try_parse_from(["edge-lb", "install", "backend"])
            .expect("positional install role should parse");
        let Some(Commands::Install(args)) = cli.command else {
            panic!("expected install command");
        };
        assert!(matches!(args.role, Some(InstallRole::Backend)));
    }
}

#[derive(Args, Debug)]
pub struct GatewayArgs {
    #[command(subcommand)]
    pub command: GatewayCommand,

    #[command(flatten)]
    pub overrides: Overrides,
}

#[derive(Subcommand, Debug)]
pub enum GatewayCommand {
    /// Converge the gateway: VXLAN, native datapath rules and DSCP eBPF.
    Apply {
        /// eBPF object to load when attaching the DSCP marker.
        #[arg(long)]
        object: Option<PathBuf>,
        /// Native datapath program id, when auto-detection is ambiguous.
        #[arg(long)]
        native_prog_id: Option<u32>,
    },
    /// Watch for drift (TC loss, ifindex change) and heal.
    Run,
    /// Print VXLAN, TC filters and native datapath state.
    Show,
    /// Remove only the objects this agent created on the gateway.
    Cleanup {
        /// Also delete agent-managed native listener state.
        #[arg(long, default_value_t = true)]
        rules: bool,
        /// Also remove the agent-managed native datapath.
        #[arg(long, default_value_t = false)]
        datapath: bool,
    },
}

#[derive(Args, Debug)]
pub struct BackendArgs {
    #[command(subcommand)]
    pub command: BackendCommand,

    #[command(flatten)]
    pub overrides: Overrides,
}

#[derive(Subcommand, Debug)]
pub enum BackendCommand {
    /// Converge the backend: VXLAN and Redirect-only return path.
    Apply,
    /// Watch the active gateway and switch the return path on change.
    Run,
    /// Print VXLAN, Redirect return path, and legacy return-path state.
    Show,
    /// Remove only the objects this agent created on the backend.
    Cleanup,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Skip the VIP path check.
    #[arg(long)]
    pub skip_vip: bool,
    /// Skip the backend direct path check.
    #[arg(long)]
    pub skip_backend: bool,
    /// curl connect timeout in seconds.
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,

    #[command(flatten)]
    pub overrides: Overrides,
}

/// CLI overrides for bootstrap parameters. Business resources are configured
/// through `/api/v1/listener-configs` and `/api/v1/target-groups`.
#[derive(Args, Debug, Default)]
pub struct Overrides {
    /// Node role, mainly for `config init` (backend | gateway).
    #[arg(long)]
    pub node_role: Option<String>,
    /// Node name, mainly for `config init`.
    #[arg(long)]
    pub node_name: Option<String>,
    /// Gateway public IP.
    #[arg(long)]
    pub gateway_public_ip: Option<IpAddr>,
    /// Backend public IP.
    #[arg(long)]
    pub backend_public_ip: Option<IpAddr>,
    /// Active gateway underlay IP.
    #[arg(long)]
    pub gateway_ip: Option<IpAddr>,
    /// Standby gateway underlay IP.
    #[arg(long)]
    pub standby_gateway_ip: Option<IpAddr>,
    /// Backend underlay IP.
    #[arg(long)]
    pub backend_ip: Option<IpAddr>,
    /// VXLAN VNI.
    #[arg(long)]
    pub vni: Option<u32>,
    /// VXLAN UDP port.
    #[arg(long)]
    pub vxlan_port: Option<u16>,
    /// DSCP value (0..63, 46 = EF).
    #[arg(long)]
    pub dscp: Option<u32>,
}
