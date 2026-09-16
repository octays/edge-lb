//! Privileged fixtures: callers must already own a disposable OS thread.

use std::path::{Path, PathBuf};

use aya::{
    Ebpf,
    programs::{
        SchedClassifier, TcAttachType,
        tc::{NlOptions, TcAttachOptions, TcHandle},
    },
};

pub(super) use crate::linux::test_support::private_namespace;

pub(super) struct PrivateBpffs(pub(super) PathBuf);

impl PrivateBpffs {
    pub(super) fn new() -> Self {
        // SAFETY: gettid has no pointer arguments or process side effects.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        let path = std::env::temp_dir().join(format!(
            "edge-lb-redirect-test-{}-{tid}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        let guard = Self(path);
        let path = std::ffi::CString::new(guard.0.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: live NUL-terminated paths and static filesystem type.
        assert_eq!(
            unsafe {
                libc::mount(
                    c"bpf".as_ptr(),
                    path.as_ptr(),
                    c"bpf".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            },
            0
        );
        guard
    }
}

impl Drop for PrivateBpffs {
    fn drop(&mut self) {
        let path = std::ffi::CString::new(self.0.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: this guard owns the mount at the live NUL-terminated path.
        let _ = unsafe { libc::umount2(path.as_ptr(), 0) };
        let _ = std::fs::remove_dir(&self.0);
    }
}

pub(super) fn load_bpf() -> Ebpf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/bpfel-unknown-none/release/edge-lb-ebpf");
    Ebpf::load(&std::fs::read(path).expect("run make ebpf first")).unwrap()
}

pub(super) fn attach_test_program(bpf: &mut Ebpf, name: &str, dev: &str, priority: u16) {
    let program: &mut SchedClassifier = bpf.program_mut(name).unwrap().try_into().unwrap();
    program.load().unwrap();
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
        .unwrap();
}
