#!/usr/bin/env bash
set -euo pipefail

DURATION="${1:-90}"
OUT="${2:-/tmp/edge-lb-resource.tsv}"
INTERVAL="${INTERVAL:-1}"

if ! [[ "$DURATION" =~ ^[0-9]+$ ]] || [[ "$DURATION" -lt 1 ]]; then
  echo "duration must be a positive integer" >&2
  exit 2
fi

pid="$(pidof edge-lb 2>/dev/null | awk '{print $1}' || true)"

read_cpu() {
  awk '/^cpu / {
    idle=$5+$6
    total=0
    for (i=2; i<=NF; i++) total += $i
    print total, idle
  }' /proc/stat
}

read_proc_ticks() {
  if [[ -n "${pid}" && -r "/proc/${pid}/stat" ]]; then
    awk '{print $14+$15}' "/proc/${pid}/stat"
  else
    echo 0
  fi
}

read_edge_rss_kb() {
  if [[ -n "${pid}" && -r "/proc/${pid}/status" ]]; then
    awk '/^VmRSS:/ {print $2}' "/proc/${pid}/status"
  else
    echo 0
  fi
}

printf 'ts\thost\ttotal_cpu_pct\tedge_lb_cpu_pct\tmem_used_mb\tmem_avail_mb\tedge_rss_mb\tload1\n' >"${OUT}"

read -r total idle < <(read_cpu)
proc_ticks="$(read_proc_ticks)"

for _ in $(seq 1 "${DURATION}"); do
  sleep "${INTERVAL}"
  read -r total_next idle_next < <(read_cpu)
  proc_ticks_next="$(read_proc_ticks)"

  delta_total=$((total_next - total))
  delta_idle=$((idle_next - idle))
  delta_proc=$((proc_ticks_next - proc_ticks))

  total_cpu_pct="$(awk -v dt="${delta_total}" -v di="${delta_idle}" 'BEGIN {
    if (dt > 0) printf "%.2f", (dt - di) * 100 / dt; else printf "0.00"
  }')"
  edge_lb_cpu_pct="$(awk -v dt="${delta_total}" -v dp="${delta_proc}" 'BEGIN {
    if (dt > 0) printf "%.2f", dp * 100 / dt; else printf "0.00"
  }')"
  read -r mem_total mem_available < <(awk '
    /^MemTotal:/ {total=$2}
    /^MemAvailable:/ {available=$2}
    END {print total, available}
  ' /proc/meminfo)
  edge_rss_kb="$(read_edge_rss_kb)"
  load1="$(cut -d' ' -f1 /proc/loadavg)"

  awk \
    -v ts="$(date +%s)" \
    -v host="$(hostname -s)" \
    -v total_cpu="${total_cpu_pct}" \
    -v edge_cpu="${edge_lb_cpu_pct}" \
    -v mem_total="${mem_total}" \
    -v mem_available="${mem_available}" \
    -v edge_rss="${edge_rss_kb}" \
    -v load1="${load1}" \
    'BEGIN {
      printf "%s\t%s\t%s\t%s\t%.1f\t%.1f\t%.1f\t%s\n",
        ts, host, total_cpu, edge_cpu,
        (mem_total - mem_available) / 1024,
        mem_available / 1024,
        edge_rss / 1024,
        load1
    }' >>"${OUT}"

  total="${total_next}"
  idle="${idle_next}"
  proc_ticks="${proc_ticks_next}"
done

echo "${OUT}"
