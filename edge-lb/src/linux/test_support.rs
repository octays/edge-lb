//! Disposable network namespaces for privileged kernel integration tests.

use std::{
    sync::mpsc,
    thread::{self, JoinHandle},
};

mod network;
pub(super) use network::*;
pub(super) mod packet;
pub(super) mod tc_packet;
pub(super) mod xfrm;

pub(super) fn private_namespace(mounts: bool) {
    let flags = libc::CLONE_NEWNET | if mounts { libc::CLONE_NEWNS } else { 0 };
    // SAFETY: only a disposable test thread calls this; no caller thread is moved.
    assert_eq!(
        unsafe { libc::unshare(flags) },
        0,
        "unshare: {}",
        std::io::Error::last_os_error()
    );
    if mounts {
        // SAFETY: static NUL-terminated mount path; no source/data needed for propagation.
        assert_eq!(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            },
            0
        );
    }
    set_link(link("lo").up());
}

type Job = Box<dyn FnOnce() + Send>;

pub(super) struct Namespace {
    jobs: Option<mpsc::Sender<Job>>,
    thread: Option<JoinHandle<()>>,
    pub tid: u32,
}

impl Namespace {
    pub fn new() -> Self {
        let (jobs, receive) = mpsc::channel::<Job>();
        let (ready, tid) = mpsc::sync_channel(0);
        let thread = thread::spawn(move || {
            private_namespace(false);
            // SAFETY: gettid identifies this live namespace worker thread.
            ready
                .send(unsafe { libc::syscall(libc::SYS_gettid) } as u32)
                .unwrap();
            for job in receive {
                job();
            }
        });
        Self {
            jobs: Some(jobs),
            thread: Some(thread),
            tid: tid.recv().unwrap(),
        }
    }

    pub fn run<T: Send + 'static>(&self, action: impl FnOnce() -> T + Send + 'static) -> T {
        let (send, result) = mpsc::sync_channel(0);
        self.jobs
            .as_ref()
            .unwrap()
            .send(Box::new(move || {
                let _ = send.send(action());
            }))
            .unwrap();
        result.recv().expect("namespace operation failed")
    }
}

impl Drop for Namespace {
    fn drop(&mut self) {
        self.jobs.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
