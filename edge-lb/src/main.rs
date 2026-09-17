//! edge-lb: unified agent for the Edge LB VXLAN return-path scheme.
//!
//! Gateway side: native default-mode listener rules, DSCP marking, xDS control
//! plane, HTTP API, and UI. Backend side: xDS subscription, Redirect-only
//! return steering, and VXLAN return tunnel switching.

mod api;
mod automation;
mod cli;
mod config;
mod control;
mod events;
mod install;
mod linux;
mod metrics;
mod notify;
mod provider;
mod role;
mod runtime;
mod storage;
mod verify;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::Path;

use crate::{
    cli::{
        BackendCommand, Cli, Commands, ConfigCommand, GatewayCommand, InternalCommand, Overrides,
        UiCommand,
    },
    config::{Config, FileConfig},
    role::{backend, gateway},
    runtime::discovery,
};

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    if matches!(&cli.command, Some(Commands::Internal { .. })) {
        let Some(Commands::Internal { command }) = cli.command else {
            unreachable!();
        };
        return run_internal(command);
    }
    let overrides = match cli.command.as_ref() {
        Some(Commands::Gateway(args)) => Some(&args.overrides),
        Some(Commands::Backend(args)) => Some(&args.overrides),
        Some(Commands::Verify(args)) => Some(&args.overrides),
        Some(Commands::Config { command }) => match command {
            ConfigCommand::Validate { overrides } => Some(overrides),
            ConfigCommand::Init { overrides, .. } => Some(overrides),
        },
        Some(Commands::Ui { .. }) => None,
        Some(Commands::Install(_))
        | Some(Commands::Uninstall { .. })
        | Some(Commands::Internal { .. })
        | None => None,
    };
    let file = FileConfig::load_file(&cli.config)?;
    let mut file = file.unwrap_or_default();
    if let Some(state_dir) = &cli.state_dir {
        file.state_dir = state_dir.clone();
    }
    if let Some(overrides) = overrides {
        apply_overrides(&mut file, overrides)?;
    }
    let command = cli.command.unwrap_or_else(|| match file.node_role {
        crate::config::NodeRole::Gateway => Commands::Gateway(cli::GatewayArgs {
            command: GatewayCommand::Run,
            overrides: Overrides::default(),
        }),
        crate::config::NodeRole::Backend => Commands::Backend(cli::BackendArgs {
            command: BackendCommand::Run,
            overrides: Overrides::default(),
        }),
    });
    crate::runtime::logging::init(&file.log_level);
    discovery::resolve_auto_ips(&mut file)?;
    if command_needs_runtime_storage(&command, &file) {
        crate::storage::initialize(Path::new(&*file.state_dir))?;
    }
    crate::runtime::ha::merge_gateway_peers_best_effort(&mut file);
    let mut cfg = Config {
        path: cli.config.clone(),
        file,
    };
    if matches!(
        command,
        Commands::Gateway(_) | Commands::Verify(_) | Commands::Ui { .. }
    ) {
        crate::control::merge_active_backend_subscriptions(&mut cfg)?;
    }
    cfg.file.validate().context("invalid configuration")?;

    match command {
        Commands::Gateway(args) => match args.command {
            GatewayCommand::Apply {
                object,
                native_prog_id,
            } => gateway::apply(
                &cfg,
                &gateway::ApplyOptions {
                    object,
                    native_prog_id,
                },
            ),
            GatewayCommand::Run => gateway::run(&cfg),
            GatewayCommand::Show => gateway::show(&cfg),
            GatewayCommand::Cleanup { rules, datapath } => {
                gateway::cleanup(&cfg, &gateway::CleanupOptions { rules, datapath })
            }
        },
        Commands::Backend(args) => match args.command {
            BackendCommand::Apply => backend::apply(&cfg),
            BackendCommand::Run => backend::run(&cfg),
            BackendCommand::Show => backend::show(&cfg),
            BackendCommand::Cleanup => backend::cleanup(&cfg),
        },
        Commands::Ui { command } => match command {
            UiCommand::Serve { listen } => {
                if cfg.node_role == crate::config::NodeRole::Gateway {
                    crate::runtime::proxy_replication::spawn(&cfg)?;
                }
                api::serve(&cfg, listen)
            }
        },
        Commands::Verify(args) => {
            let outcome = verify::run_checks(&cfg, &args)?;
            if (!args.skip_vip && !outcome.vip_ok) || (!args.skip_backend && !outcome.backend_ok) {
                std::process::exit(1);
            }
            Ok(())
        }
        Commands::Config { command } => match command {
            ConfigCommand::Validate { .. } => {
                println!("configuration OK ({})", cfg.path.display());
                println!(
                    "role={:?} node={} listeners={} target_groups={} gateways={}",
                    cfg.node_role,
                    cfg.node_name,
                    cfg.listeners.len(),
                    cfg.target_groups.len(),
                    cfg.gateway_nodes.len(),
                );
                Ok(())
            }
            ConfigCommand::Init { force, .. } => {
                if cfg.path.exists() && !force {
                    anyhow::bail!(
                        "{} already exists; use --force to overwrite",
                        cfg.path.display()
                    );
                }
                cfg.file.save_atomic(&cfg.path)?;
                println!("wrote {}", cfg.path.display());
                Ok(())
            }
        },
        Commands::Install(args) => install::install_service(&cfg, &args),
        Commands::Uninstall { command } => match command {
            cli::UninstallCommand::Service(args) => install::uninstall_service(&args),
        },
        Commands::Internal { .. } => unreachable!("internal commands return before config loading"),
    }
}

fn command_needs_runtime_storage(command: &Commands, file: &FileConfig) -> bool {
    match command {
        Commands::Gateway(args) => {
            file.node_role == crate::config::NodeRole::Gateway
                && !matches!(args.command, GatewayCommand::Show)
        }
        Commands::Backend(args) => {
            file.node_role == crate::config::NodeRole::Backend
                && !matches!(args.command, BackendCommand::Show)
        }
        Commands::Ui { .. } | Commands::Verify(_) => true,
        Commands::Config { .. }
        | Commands::Install(_)
        | Commands::Uninstall { .. }
        | Commands::Internal { .. } => false,
    }
}

fn run_internal(command: InternalCommand) -> Result<()> {
    match command {
        InternalCommand::KaHookSend {
            socket,
            instance,
            state,
            vip,
        } => runtime::ka_hook::send(&socket, &instance, &state, &vip),
    }
}

/// Layer CLI overrides onto the local bootstrap config. Listener and target
/// group resources are intentionally not configurable through these flags.
fn apply_overrides(file: &mut FileConfig, ov: &Overrides) -> Result<()> {
    if let Some(role) = &ov.node_role {
        file.node_role = match role.as_str() {
            "backend" => crate::config::NodeRole::Backend,
            "gateway" => crate::config::NodeRole::Gateway,
            other => anyhow::bail!("node_role must be backend or gateway, got {other:?}"),
        };
    }
    if let Some(name) = &ov.node_name {
        file.node_name = name.clone();
    }
    let n = &mut file.network;
    if let Some(v) = ov.gateway_public_ip {
        n.gateway_public_ip = v;
    }
    if let Some(v) = ov.backend_public_ip {
        n.backend_public_ip = Some(v);
        if let Some(backend) = file.backend_nodes.first_mut() {
            backend.public_ip = v;
        }
    }
    if let Some(v) = ov.gateway_ip {
        let old = n.gateway_ip;
        n.gateway_ip = v;
        // Keep gateway_nodes consistent so active-gateway resolution honors
        // the override instead of silently falling back.
        if !file.gateway_nodes.iter().any(|g| g.underlay_ip == v) {
            let nodes = &mut file.gateway_nodes;
            let idx = nodes.iter().position(|g| g.underlay_ip == old).unwrap_or(0);
            if let Some(g) = nodes.get_mut(idx) {
                g.underlay_ip = v;
            }
        }
    }
    if let Some(v) = ov.standby_gateway_ip {
        n.standby_gateway_ip = Some(v);
    }
    if let Some(v) = ov.backend_ip {
        n.backend_ip = Some(v);
        if let Some(backend) = file.backend_nodes.first_mut() {
            backend.underlay_ip = v;
        }
    }
    if let Some(v) = ov.vni {
        n.vni = v;
    }
    if let Some(v) = ov.vxlan_port {
        n.vxlan_port = v;
    }
    if let Some(v) = ov.dscp {
        n.dscp = v;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_runtime_commands_initialize_storage_before_ha_merge() {
        let file = FileConfig {
            node_role: crate::config::NodeRole::Gateway,
            ..FileConfig::default()
        };
        assert!(command_needs_runtime_storage(
            &Commands::Gateway(cli::GatewayArgs {
                command: GatewayCommand::Run,
                overrides: Overrides::default(),
            }),
            &file
        ));
        assert!(command_needs_runtime_storage(
            &Commands::Ui {
                command: UiCommand::Serve { listen: None },
            },
            &file
        ));
        assert!(command_needs_runtime_storage(
            &Commands::Verify(cli::VerifyArgs {
                skip_vip: false,
                skip_backend: false,
                timeout: 5,
                overrides: Overrides::default(),
            }),
            &file
        ));
    }

    #[test]
    fn backend_mutating_commands_initialize_storage_but_show_and_config_do_not() {
        let backend_file = FileConfig {
            node_role: crate::config::NodeRole::Backend,
            ..FileConfig::default()
        };
        let gateway_file = FileConfig {
            node_role: crate::config::NodeRole::Gateway,
            ..FileConfig::default()
        };

        for command in [
            BackendCommand::Run,
            BackendCommand::Apply,
            BackendCommand::Cleanup,
        ] {
            assert!(command_needs_runtime_storage(
                &Commands::Backend(cli::BackendArgs {
                    command,
                    overrides: Overrides::default()
                }),
                &backend_file
            ));
        }
        assert!(!command_needs_runtime_storage(
            &Commands::Backend(cli::BackendArgs {
                command: BackendCommand::Show,
                overrides: Overrides::default(),
            }),
            &backend_file
        ));
        assert!(!command_needs_runtime_storage(
            &Commands::Gateway(cli::GatewayArgs {
                command: GatewayCommand::Show,
                overrides: Overrides::default(),
            }),
            &gateway_file
        ));
        assert!(!command_needs_runtime_storage(
            &Commands::Config {
                command: ConfigCommand::Validate {
                    overrides: Overrides::default(),
                },
            },
            &gateway_file
        ));
    }
}
