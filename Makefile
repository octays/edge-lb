# edge-lb workspace tasks.
#
# Host requirements:
#   - rust stable + nightly-2025-12-01 (LLVM 21 must match bpf-linker)
#   - cargo-bpf-linker: cargo install bpf-linker --locked
#   - protoc is provided by protoc-bin-vendored in build.rs
#   - cargo-zigbuild + zig (macOS: cargo install cargo-zigbuild --locked; brew install zig)
#   - the user-space crate needs Linux: `make check` runs it via Docker.

EBPF_TOOLCHAIN := nightly-2025-12-01
EBPF_TARGET    := bpfel-unknown-none
VERSION        := $(shell awk -F '"' '/^version[[:space:]]*=/ { print $$2; exit }' Cargo.toml)
DIST_DIR       := dist
ZIG_TARGETS    := x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
BUILD_IMAGE    := edge-lb-build:bookworm
IMAGE_NAME     ?= ghcr.io/octays/edge-lb
IMAGE_TAG      ?= v$(VERSION)
IMAGE_REF      ?= $(IMAGE_NAME):$(IMAGE_TAG)
LOCAL_PLATFORM ?= linux/amd64
IMAGE_PLATFORMS ?= linux/amd64,linux/arm64
IMAGE_OCI      ?= $(DIST_DIR)/edge-lb-image-$(IMAGE_TAG).oci.tar
DOCKER         ?= docker run --rm -v $(PWD):/src -v edge-lb-cargo:/usr/local/cargo/registry -w /src $(BUILD_IMAGE)
DOCKER_RUSTUP  ?= docker run --rm -v $(PWD):/src -v edge-lb-cargo:/usr/local/cargo/registry -v edge-lb-rustup:/usr/local/rustup -w /src $(BUILD_IMAGE)
DOCKER_PRIVILEGED ?= docker run --rm --privileged -v $(PWD):/src -v edge-lb-cargo:/usr/local/cargo/registry -w /src $(BUILD_IMAGE)
TEST_ARGS      ?=
DEB_DOCKER     ?= docker run --rm -u $$(id -u):$$(id -g) -v $(PWD):/src -w /src debian:bookworm-slim
UPX            ?= upx

.PHONY: help build-image check-host-tools fmt check clippy test ebpf build release zigbuild ha-bench backend-server package deb compress container-stage image image-push container-image container-image-oci container-image-push install-local ui clean

help:
	@echo "make build-image - build the Linux Rust image with protoc"
	@echo "make check-host-tools - verify cargo-zigbuild and zig"
	@echo "make fmt      - cargo fmt (all crates)"
	@echo "make check    - cargo check via Linux container (aya needs Linux)"
	@echo "make clippy   - cargo clippy via Linux container"
	@echo "make test     - cargo test via privileged Linux container"
	@echo "make ebpf     - build the DSCP eBPF object (needs bpf-linker + pinned nightly)"
	@echo "make build    - debug build via Linux container"
	@echo "make release  - release build for x86_64 Linux via cargo-zigbuild"
	@echo "make zigbuild - cross-build edge-lb for Linux amd64/arm64 with cargo-zigbuild"
	@echo "make ha-bench - release build Linux amd64 HA pressure client"
	@echo "make backend-server - release build Linux amd64 TCP/UDP test backend service"
	@echo "make package  - build UI/binary and create dist tarballs"
	@echo "make deb      - build gateway/backend Linux amd64/arm64 .deb packages"
	@echo "make compress - create optional UPX-compressed Linux binaries in dist/compressed"
	@echo "make container-image - build local $(LOCAL_PLATFORM) image $(IMAGE_REF)"
	@echo "make container-image-oci - build multi-platform OCI archive $(IMAGE_OCI)"
	@echo "make container-image-push - build and push multi-platform image $(IMAGE_REF)"
	@echo "make image    - alias for make container-image"
	@echo "make image-push - alias for make container-image-push"
	@echo "make install-local ROLE=backend|gateway - install local release as systemd service"
	@echo "make ui       - build the Vue UI into ui/dist"
	@echo "make clean    - remove target/"

fmt:
	cargo fmt --all

build-image:
	docker build -f deploy/build.Dockerfile -t $(BUILD_IMAGE) .

check-host-tools:
	@cargo zigbuild --help >/dev/null || { echo "missing cargo-zigbuild (cargo install cargo-zigbuild --locked)"; exit 1; }
	@command -v zig >/dev/null || { echo "missing zig (macOS: brew install zig)"; exit 1; }

check: build-image
	$(DOCKER) cargo check --workspace --exclude edge-lb-ebpf

clippy: build-image
	$(DOCKER_RUSTUP) bash -c "rustup component add clippy >/dev/null 2>&1; cargo clippy --workspace --exclude edge-lb-ebpf -- -D warnings"

test: build-image ebpf
	$(DOCKER_PRIVILEGED) env RUST_TEST_THREADS=1 cargo test -p edge-lb $(TEST_ARGS)

ebpf:
	cargo +$(EBPF_TOOLCHAIN) build -Z build-std=core --target $(EBPF_TARGET) -p edge-lb-ebpf --release

build: build-image ebpf
	$(DOCKER) cargo build -p edge-lb

release: check-host-tools ui ebpf
	cargo zigbuild --release -p edge-lb --target x86_64-unknown-linux-gnu

zigbuild: check-host-tools ui ebpf
	cargo zigbuild --release -p edge-lb --target x86_64-unknown-linux-gnu
	cargo zigbuild --release -p edge-lb --target aarch64-unknown-linux-gnu

ha-bench: check-host-tools
	cargo zigbuild --release -p ha-bench --target x86_64-unknown-linux-gnu

backend-server: check-host-tools
	cargo zigbuild --release -p backend-server --target x86_64-unknown-linux-gnu

package: zigbuild
	./scripts/package.sh x86_64-unknown-linux-gnu $(VERSION)
	./scripts/package.sh aarch64-unknown-linux-gnu $(VERSION)

deb: compress
	$(DEB_DOCKER) bash ./scripts/deb.sh x86_64-unknown-linux-gnu $(VERSION)
	$(DEB_DOCKER) bash ./scripts/deb.sh aarch64-unknown-linux-gnu $(VERSION)

compress: zigbuild
	@command -v $(UPX) >/dev/null || { echo "missing $(UPX) (Debian: apt install upx-ucl; macOS: brew install upx)" >&2; exit 1; }
	rm -rf $(DIST_DIR)/compressed
	mkdir -p $(DIST_DIR)/compressed
	cp target/x86_64-unknown-linux-gnu/release/edge-lb $(DIST_DIR)/compressed/edge-lb-$(VERSION)-amd64-upx
	cp target/aarch64-unknown-linux-gnu/release/edge-lb $(DIST_DIR)/compressed/edge-lb-$(VERSION)-arm64-upx
	$(UPX) --best --lzma $(DIST_DIR)/compressed/edge-lb-$(VERSION)-amd64-upx $(DIST_DIR)/compressed/edge-lb-$(VERSION)-arm64-upx
	chmod 0755 $(DIST_DIR)/compressed/edge-lb-$(VERSION)-*-upx

container-stage: compress
	rm -rf $(DIST_DIR)/docker
	mkdir -p $(DIST_DIR)/docker/amd64 $(DIST_DIR)/docker/arm64
	cp $(DIST_DIR)/compressed/edge-lb-$(VERSION)-amd64-upx $(DIST_DIR)/docker/amd64/edge-lb
	cp $(DIST_DIR)/compressed/edge-lb-$(VERSION)-arm64-upx $(DIST_DIR)/docker/arm64/edge-lb
	chmod 0755 $(DIST_DIR)/docker/amd64/edge-lb $(DIST_DIR)/docker/arm64/edge-lb

image: container-image

image-push: container-image-push

container-image: container-stage
	@command -v docker >/dev/null || { echo "missing docker" >&2; exit 1; }
	@docker buildx version >/dev/null || { echo "missing docker buildx" >&2; exit 1; }
	docker buildx build --platform $(LOCAL_PLATFORM) --load -f deploy/container.ci.Dockerfile -t $(IMAGE_REF) .
	@echo "built $(IMAGE_REF) for $(LOCAL_PLATFORM)"

container-image-oci: container-stage
	@command -v docker >/dev/null || { echo "missing docker" >&2; exit 1; }
	@docker buildx version >/dev/null || { echo "missing docker buildx" >&2; exit 1; }
	docker buildx build --platform $(IMAGE_PLATFORMS) -f deploy/container.ci.Dockerfile -t $(IMAGE_REF) --output=type=oci,dest=$(IMAGE_OCI) .
	@echo "built OCI archive $(IMAGE_OCI) for $(IMAGE_PLATFORMS)"

container-image-push: container-stage
	@command -v docker >/dev/null || { echo "missing docker" >&2; exit 1; }
	@docker buildx version >/dev/null || { echo "missing docker buildx" >&2; exit 1; }
	docker buildx build --platform $(IMAGE_PLATFORMS) --push -f deploy/container.ci.Dockerfile -t $(IMAGE_REF) .
	@echo "pushed $(IMAGE_REF) for $(IMAGE_PLATFORMS)"

install-local: release
	sudo target/x86_64-unknown-linux-gnu/release/edge-lb install $${ROLE:-backend}

ui:
	cd ui && bun install && bun run build

clean:
	rm -rf target $(DIST_DIR)
