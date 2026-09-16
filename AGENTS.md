# Repository Guidelines

## Project Structure & Module Organization

This repository implements `edge-lb`, the native DNAT/SNAT load balancer for the verified VXLAN return-path scheme (see `docs/architecture.md` and `docs/vxlan-dscp-verified.md`). The Rust workspace at the root has three crates: `edge-lb/` (user-space CLI/daemon/HTTP API), `edge-lb-common/` (shared types), `edge-lb-ebpf/` (Rust/Aya eBPF datapath programs). `ui/` holds the Vue 3 + TypeScript + Vite (rolldown) + shadcn-vue style management panel, built with bun and embedded into the binary at compile time. `deploy/` has systemd units, package templates, compose examples, and installation helpers. `tools/` contains validation utilities such as `ha-bench` and `backend-server`.

## Build, Test, and Development Commands

- `make check`: cargo check via a Linux container (aya needs Linux libc).
- `make clippy` / `make test`: lint and tests (`test` builds the current eBPF object first and needs `--privileged` for map creation and isolated network-namespace tests).
- `make ebpf`: build the DSCP marker object; requires `nightly-2025-12-01` (LLVM 21 must match bpf-linker) and `cargo install bpf-linker --locked`.
- `make release`: x86_64 Linux release build via an amd64 container.
- `make ui`: bun install + vite (rolldown) build into `ui/dist`.
- `make fmt`: `cargo fmt --all`.
- `make deb`: build role-specific gateway/backend Debian packages.
- `make container-image-push`: build and push the multi-platform GHCR image.

## Coding Style & Naming Conventions

Use standard Rust 2024 formatting and keep crate names in kebab case. Rust modules, functions, and variables use `snake_case`; types use `PascalCase`. Keep eBPF code compact and kernel-friendly; prefer explicit fixed-width integer types. Shell scripts should use clear variable names for interface, port, and IP settings.

## Frontend UI Constraints

Use shadcn-vue components for interactive form controls in `ui/`. Do not hand-style native selects, checkboxes, dialogs, or similar controls when a shadcn-vue/Reka UI primitive is available. For dropdowns, use the shared shadcn-vue Select wrapper under `ui/src/components/ui/select/` so trigger, content, item, focus, disabled, and popover states stay consistent across pages.

## Native Datapath Constraints

Keep management models centered on listener configurations and target groups. Do not reintroduce external load balancer provider models, standalone backend-target APIs, or external container dependencies. Gateway datapath changes should reconcile the native eBPF maps and VXLAN return path directly from the SQLite-backed configuration model.

## Layering and Structured Design

- Separate configuration/domain models, kernel observation I/O, pure resolution and validation, desired-state planning, map/resource reconciliation, and eBPF packet execution. Keep role/CLI/API entry points thin: orchestrate calls and present results rather than implementing these layers inline.
- Keep each module focused on one responsibility. Expose a small facade and keep implementation modules private. Do not accumulate new redirect functionality in `native_dnat.rs`, role handlers, or one large utility module. Split by ownership and behavior, not arbitrary line counts; avoid speculative frameworks or traits.
- Kernel observers must be read-only. Pure decision functions must not perform netlink, filesystem, subprocess, or BPF-map I/O. Reconciliation alone owns resource mutations, ordering, invalidation, and failure handling. The orchestration layer composes these capabilities without circular dependencies.
- Use typed structures and explicit result/reason enums at layer boundaries. Parse structured netlink/API data rather than CLI display strings. A successful observation must not implicitly authorize forwarding or bypass policy.
- Use native Rust APIs, netlink, procfs, or syscalls for network observation, mutation, and test topology setup. Do not spawn `ip`, `bridge`, `tc`, `nft`, `mount`, or shell wrappers from these modules, including test fixtures. Do not hide command syntax behind a string-dispatch adapter. Documented manual diagnostics and build/deployment tools are separate from runtime dependencies; the explicitly configured HA hook remains a process boundary by contract.
- Keep shared userspace/eBPF ABI definitions in `edge-lb-common`; keep kernel parsing and packet mutation in `edge-lb-ebpf`. Flow lifecycle, health selection, and return-path contracts must have one authoritative implementation/meaning, reused across fast and fallback paths.
- Test pure rules independently from kernel integration. Keep representative kernel, verifier, topology, and end-to-end tests at their corresponding boundaries. Document module responsibilities and dependency direction before adding cross-layer behavior; update `docs/implementation-contracts.md` when those boundaries change.
- Develop the current forwarding optimization on `patch`, without configuration, environment, API, or build-feature switches between old and new paths. Preserve automatic eligibility-based fallback. Merge into `master` only after the agreed scope is implemented and functional, failure, HA, and performance validation is complete.

## Testing Guidelines

Use `cargo fmt --all --check`, `make check`, and `make test` as baseline validation. For network behavior changes, include the exact route, nftables, curl, nc, or `ha-bench` commands used to verify the topology.

## Commit & Pull Request Guidelines

No local Git history is available, so no repository-specific commit pattern can be inferred. Use short imperative subjects, for example `Fix target group reconcile`, and keep related topology, config, and documentation updates together. Pull requests should describe the tested environment, changed IP/ASN assumptions, commands run, and observed packet or BGP evidence.

## Security & Configuration Tips

Do not commit real credentials, private keys, or cloud-specific secrets. Keep example IPs, ASNs, and hostnames clearly marked, and update both compose files and BGP configs together when changing topology.
