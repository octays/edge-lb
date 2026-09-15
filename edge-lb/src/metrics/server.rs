use std::{
    net::{IpAddr, SocketAddr},
    thread::JoinHandle,
};

use anyhow::{Context, Result};
use tiny_http::{Header, Response, Server};

use crate::{config::Config, runtime::access};

pub fn spawn_gateway(cfg: &Config) -> Result<Option<JoinHandle<()>>> {
    let Some(metrics) = cfg.gateway.metrics.as_ref() else {
        return Ok(None);
    };
    if !metrics.enabled {
        return Ok(None);
    }
    let listen: SocketAddr = metrics
        .listen
        .parse()
        .with_context(|| format!("bad gateway.metrics.listen {}", metrics.listen))?;
    let trusted_cidrs = access::metrics_trusted_source_cidrs(cfg)
        .context("building metrics trusted source CIDRs")?;
    let server =
        Server::http(listen).map_err(|e| anyhow::anyhow!("binding metrics {listen}: {e}"))?;
    let cfg = cfg.clone();
    let handle = std::thread::Builder::new()
        .name("edge-lb-metrics".to_string())
        .stack_size(512 * 1024)
        .spawn(move || {
            tracing::info!(
                "[gateway] metrics listening on http://{listen}/metrics trusted_sources={trusted_cidrs:?}"
            );
            for request in server.incoming_requests() {
                if let Err(error) = handle_request(request, &cfg, &trusted_cidrs) {
                    tracing::warn!("[metrics] {error:#}");
                }
            }
        })
        .context("spawning metrics server")?;
    Ok(Some(handle))
}

fn handle_request(
    request: tiny_http::Request,
    cfg: &Config,
    trusted_cidrs: &[String],
) -> Result<()> {
    let method = request.method().clone();
    let path = request.url().split('?').next().unwrap_or("").to_string();
    if path != "/metrics" {
        return respond_text(request, 404, "not found\n");
    }
    if method != tiny_http::Method::Get {
        return respond_text(request, 405, "method not allowed\n");
    }
    match request.remote_addr().map(SocketAddr::ip) {
        Some(ip) if allowed(ip, trusted_cidrs) => {}
        Some(ip) => return respond_text(request, 403, &format!("untrusted source {ip}\n")),
        None => return respond_text(request, 403, "missing remote address\n"),
    }
    let body = super::render::render_gateway(cfg);
    respond_metrics(request, body)
}

fn allowed(ip: IpAddr, trusted_cidrs: &[String]) -> bool {
    access::source_allowed(ip, trusted_cidrs).unwrap_or(false)
}

fn respond_metrics(request: tiny_http::Request, body: String) -> Result<()> {
    let header = Header::from_bytes("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .map_err(|e| anyhow::anyhow!("building metrics header: {e:?}"))?;
    request
        .respond(
            Response::from_string(body)
                .with_status_code(200)
                .with_header(header),
        )
        .map_err(|e| anyhow::anyhow!("responding metrics: {e}"))?;
    Ok(())
}

fn respond_text(request: tiny_http::Request, status: u16, body: &str) -> Result<()> {
    let header = Header::from_bytes("Content-Type", "text/plain; charset=utf-8")
        .map_err(|e| anyhow::anyhow!("building text header: {e:?}"))?;
    request
        .respond(
            Response::from_string(body)
                .with_status_code(status)
                .with_header(header),
        )
        .map_err(|e| anyhow::anyhow!("responding metrics error: {e}"))?;
    Ok(())
}
