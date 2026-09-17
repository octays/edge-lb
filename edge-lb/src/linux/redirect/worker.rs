//! Route-cache lifecycle. Never invokes business reconcile or HA transitions.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};

use super::{
    events::RouteEvents,
    maps::invalidate_routes,
    reconcile::{self, RedirectContext},
    status,
};

pub struct InvalidationWorker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    context: RedirectContext,
}

impl Drop for InvalidationWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn spawn(context: RedirectContext) -> Result<InvalidationWorker> {
    invalidate_routes(&context.route_pin)
        .context("invalidating redirect cache at monitor startup")?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let worker_context = context.clone();
    let thread = std::thread::Builder::new()
        .name("edge-lb-route-watch".into())
        .spawn(move || run(&worker_context, &worker_stop))
        .context("spawning redirect invalidation worker")?;
    Ok(InvalidationWorker {
        stop,
        thread: Some(thread),
        context,
    })
}

impl InvalidationWorker {
    pub fn matches(&self, context: &RedirectContext) -> bool {
        &self.context == context
    }
}

fn run(context: &RedirectContext, stop: &AtomicBool) {
    let pin = &context.route_pin;
    let mut events = None;
    let mut previous_error = None;
    let mut last_refresh = Instant::now() - Duration::from_secs(1);
    while !stop.load(Ordering::Acquire) && !crate::runtime::shutdown::requested() {
        let result = (|| -> Result<Option<u64>> {
            if events.is_none() {
                // No trust survives a receive failure or reconnect attempt.
                invalidate_routes(pin)?;
                events = Some(RouteEvents::open()?);
                invalidate_routes(pin)?;
            }
            if events.as_ref().expect("monitor initialized").changed()? {
                invalidate_routes(pin)?;
            }
            if last_refresh.elapsed() >= Duration::from_millis(500) {
                last_refresh = Instant::now();
                return reconcile::refresh(context, events.as_ref().expect("monitor initialized"));
            }
            Ok(None)
        })();
        match result {
            Ok(publication) => {
                if let Some(digest) = publication {
                    status::record_published(digest);
                }
                if publication.is_some() && previous_error.take().is_some() {
                    tracing::info!("[redirect] route invalidation monitor recovered");
                }
            }
            Err(error) => {
                events = None;
                status::record_blocked(&format!("{error:#}"));
                let invalidation = invalidate_routes(pin);
                let error = match invalidation {
                    Ok(_) => format!("{error:#}; redirect cache invalidated"),
                    Err(clear) => format!("{error:#}; cache invalidation ALSO failed: {clear:#}"),
                };
                if previous_error.as_ref() != Some(&error) {
                    tracing::warn!("[redirect] {error}");
                    previous_error = Some(error);
                }
                for _ in 0..5 {
                    if stop.load(Ordering::Acquire) || crate::runtime::shutdown::requested() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }
    if let Err(error) = reconcile::invalidate(pin) {
        tracing::error!("[redirect] invalidating cache on monitor exit failed: {error:#}");
    }
}
