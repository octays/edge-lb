#!/usr/bin/env bash
set -euo pipefail

ROLE=""
UNDERLAY_DEV="${UNDERLAY_DEV:-eth0}"
GATEWAY_VXLAN_DEV="${GATEWAY_VXLAN_DEV:-edge-hub}"
BACKEND_VXLAN_DEV="${BACKEND_VXLAN_DEV:-edge-return}"
NFT_TABLE="${NFT_TABLE:-edge_lb_return}"
APPLY=0
FORCE_ACTIVE=0
SKIP_SERVICE_CHECK=0

usage() {
  cat <<'EOF'
Usage:
  cleanup-legacy-datapath.sh --role gateway|backend|all [options]

Options:
  --underlay-dev DEV          Underlay device, default: eth0
  --gateway-vxlan-dev DEV     Gateway VXLAN device, default: edge-hub
  --backend-vxlan-dev DEV     Backend VXLAN device, default: edge-return
  --nft-table NAME            Legacy backend nft table, default: edge_lb_return
  --apply                     Execute changes. Without this, only print commands.
  --force-active              Allow cleanup while edge-lb.service is active.
  --skip-service-check        Do not check edge-lb.service state.
  -h, --help                  Show this help.

Environment variables with the same names as the long options can also set
device/table defaults: UNDERLAY_DEV, GATEWAY_VXLAN_DEV, BACKEND_VXLAN_DEV,
NFT_TABLE.

This script is a manual migration tool. The edge-lb daemon intentionally does
not delete old nftables tables or old TC filters during normal reconciliation.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)
      ROLE="${2:-}"
      shift 2
      ;;
    --underlay-dev)
      UNDERLAY_DEV="${2:-}"
      shift 2
      ;;
    --gateway-vxlan-dev)
      GATEWAY_VXLAN_DEV="${2:-}"
      shift 2
      ;;
    --backend-vxlan-dev)
      BACKEND_VXLAN_DEV="${2:-}"
      shift 2
      ;;
    --nft-table)
      NFT_TABLE="${2:-}"
      shift 2
      ;;
    --apply)
      APPLY=1
      shift
      ;;
    --force-active)
      FORCE_ACTIVE=1
      shift
      ;;
    --skip-service-check)
      SKIP_SERVICE_CHECK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$ROLE" in
  gateway|backend|all) ;;
  *)
    echo "--role must be gateway, backend, or all" >&2
    usage >&2
    exit 2
    ;;
esac

if [[ "$(id -u)" -ne 0 ]]; then
  echo "this script must run as root" >&2
  exit 1
fi

run_cmd() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if [[ "$APPLY" -eq 1 ]]; then
    "$@"
  fi
}

have_dev() {
  [[ -n "$1" && -e "/sys/class/net/$1" ]]
}

check_service() {
  if [[ "$SKIP_SERVICE_CHECK" -eq 1 || "$FORCE_ACTIVE" -eq 1 ]]; then
    return
  fi
  if command -v systemctl >/dev/null 2>&1 \
    && systemctl is-active --quiet edge-lb.service; then
    cat >&2 <<'EOF'
edge-lb.service is active. Stop the service first, or pass --force-active if
you intentionally want to remove datapath objects while the daemon is running.
EOF
    exit 1
  fi
}

delete_tc_by_program_names() {
  local dev="$1"
  local direction="$2"
  shift 2
  local names=("$@")
  local output line name pref

  if ! have_dev "$dev"; then
    echo "# skip missing device $dev"
    return
  fi
  output="$(tc filter show dev "$dev" "$direction" 2>/dev/null || true)"
  for name in "${names[@]}"; do
    while IFS= read -r line; do
      [[ "$line" == *"$name"* ]] || continue
      pref="$(awk '{for (i=1; i<=NF; i++) if ($i == "pref") {print $(i+1); exit}}' <<<"$line")"
      [[ -n "$pref" ]] || continue
      run_cmd tc filter del dev "$dev" "$direction" pref "$pref"
    done <<<"$output"
  done
}

delete_tc_pref() {
  local dev="$1"
  local direction="$2"
  local pref="$3"
  if have_dev "$dev" && tc filter show dev "$dev" "$direction" 2>/dev/null | grep -q "pref $pref "; then
    run_cmd tc filter del dev "$dev" "$direction" pref "$pref"
  fi
}

cleanup_gateway_tc() {
  echo "# gateway legacy/current edge-lb-owned TC filters"
  delete_tc_by_program_names "$UNDERLAY_DEV" ingress \
    dscp_mark native_dnat_ingress native_dnat_return
  delete_tc_by_program_names "$GATEWAY_VXLAN_DEV" ingress native_dnat_return

  # Known historical preferences. Kept after name matching so stale filters
  # without program names can still be removed during migration.
  delete_tc_pref "$UNDERLAY_DEV" ingress 1
  delete_tc_pref "$UNDERLAY_DEV" ingress 11
  delete_tc_pref "$UNDERLAY_DEV" ingress 12
  delete_tc_pref "$GATEWAY_VXLAN_DEV" ingress 12
}

cleanup_backend_tc() {
  echo "# backend legacy/current edge-lb-owned TC filters"
  delete_tc_by_program_names "$UNDERLAY_DEV" ingress backend_return_ingress
  delete_tc_by_program_names "$UNDERLAY_DEV" egress backend_return_egress
  delete_tc_by_program_names "$BACKEND_VXLAN_DEV" ingress backend_return_ingress

  # Current and early patch preferences.
  delete_tc_pref "$UNDERLAY_DEV" ingress 21
  delete_tc_pref "$UNDERLAY_DEV" egress 22
  delete_tc_pref "$BACKEND_VXLAN_DEV" ingress 21
}

cleanup_backend_nft() {
  echo "# backend legacy nftables return-path table"
  if command -v nft >/dev/null 2>&1 \
    && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
    run_cmd nft delete table inet "$NFT_TABLE"
  else
    echo "# nft table inet $NFT_TABLE not present"
  fi
}

check_service

if [[ "$APPLY" -eq 0 ]]; then
  echo "# dry-run mode; pass --apply to execute"
fi

case "$ROLE" in
  gateway)
    cleanup_gateway_tc
    ;;
  backend)
    cleanup_backend_tc
    cleanup_backend_nft
    ;;
  all)
    cleanup_gateway_tc
    cleanup_backend_tc
    cleanup_backend_nft
    ;;
esac
