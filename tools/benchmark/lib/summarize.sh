#!/usr/bin/env bash
#
# summarize.sh - aggregate the raw iperf3 JSON and metadata of a benchmark
# session into a machine-readable summary.json and a human-readable
# report.txt.
#
# Usage: summarize.sh <session-dir> <summary.json> <report.txt>
#
# Layout consumed (produced by run-benchmark.sh):
#   <session-dir>/
#     run-<seq>-<proto>-<mode>-<point>/
#       meta.json                  run metadata
#       iperf3-forward.json        raw iperf3 --json output (client)
#       iperf3-reverse.json        raw iperf3 --json output when reverse run
#       curtsy-config.yaml         config used by the proxied run (when any)
#     env-before/<node>/           session-level environment snapshots
#     env-after/<node>/

set -eu -o pipefail

usage() {
    cat <<'EOF'
Usage: summarize.sh <session-dir> <summary.json> <report.txt>

Aggregates run metadata and raw iperf3 JSON files under <session-dir> into:
  - <summary.json>  machine-readable array of per-test results (for
                    regression comparison)
  - <report.txt>    human-readable aligned table
EOF
}

if [ "$#" -ne 3 ]; then
    usage >&2
    exit 2
fi
case "$1" in
    --help | -h | help)
        usage
        exit 0
        ;;
esac

session_dir="$1"
summary_file="$2"
report_file="$3"

# --- jq metric expressions (with explicit fallbacks) -----------------------
# TCP: aggregate sender throughput plus retransmits and mean RTT across the
# sender streams. UDP: aggregate throughput, jitter, loss and packet counts.
tcp_bits=".end.sum_sent.bits_per_second // 0"
tcp_retrans=".end.sum_sent.retransmits // 0"
tcp_rtt="(([.end.streams[].sender.mean_rtt | select(. != null)] | add / (length + 1e-9)) // 0)"
udp_bits=".end.sum.bits_per_second // 0"
udp_jitter=".end.sum.jitter_ms // 0"
udp_lost_pct=".end.sum.lost_percent // 0"
udp_packets=".end.sum.packets // 0"

extract_metrics() { # protocol json_file -> "bits|retrans|rtt|jitter|lost_pct|packets"
    local proto="$1" file="$2"
    if [ ! -f "$file" ]; then
        echo "0|0|0|0|0|0"
        return 0
    fi
    if [ "$proto" = "udp" ]; then
        bits=$(jq_value "$file" "$udp_bits")
        jitter=$(jq_value "$file" "$udp_jitter")
        lost=$(jq_value "$file" "$udp_lost_pct")
        packets=$(jq_value "$file" "$udp_packets")
        printf '%s|0|0|%s|%s|%s\n' "$bits" "$jitter" "$lost" "$packets"
    else
        bits=$(jq_value "$file" "$tcp_bits")
        retrans=$(jq_value "$file" "$tcp_retrans")
        rtt=$(jq_value "$file" "$tcp_rtt")
        printf '%s|%s|%s|0|0|0\n' "$bits" "$retrans" "$rtt"
    fi
}

# jq_value lives in common.sh; define a local copy so this script is
# standalone when invoked directly.
if ! declare -F jq_value >/dev/null 2>&1; then
    jq_value() { # file expr
        jq -r "$2" "$1" 2>/dev/null || printf '0\n'
    }
fi

tmpdir=$(mktemp -d /tmp/curtsy-summarize.XXXXXX)
trap 'rm -rf "$tmpdir"' EXIT
tests_jsonl="$tmpdir/tests.jsonl"
: >"$tests_jsonl"

report_rows="$tmpdir/report.txt"
: >"$report_rows"

session=$(basename "$session_dir")

run_dirs=()
for d in "$session_dir"/run-*/; do
    [ -d "$d" ] || continue
    run_dirs+=("$d")
done

for d in "${run_dirs[@]}"; do
    meta="$d/meta.json"
    [ -f "$meta" ] || continue
    run_id=$(jq_value "$meta" '.run_id // ""')
    proto=$(jq_value "$meta" '.protocol // ""')
    mode=$(jq_value "$meta" '.mode // ""')
    point=$(jq_value "$meta" '.point // ""')
    point_value=$(jq_value "$meta" '.point_value // 0')
    label=$(jq_value "$meta" '.label // ""')
    cpu_seconds=$(jq_value "$meta" '.cpu_seconds // 0')
    test_seconds=$(jq_value "$meta" '.test_seconds // 0')
    [ -n "$run_id" ] || continue

    for dir in forward reverse; do
        json_file="$d/iperf3-$dir.json"
        [ -f "$json_file" ] || continue
        IFS='|' read -r bits retrans rtt jitter lost packets < <(extract_metrics "$proto" "$json_file")
        rel="${d##*/}/iperf3-$dir.json"
        obj=$(jq -cn \
            --arg run_id "$run_id" \
            --arg protocol "$proto" \
            --arg mode "$mode" \
            --arg point "$point" \
            --argjson point_value "$point_value" \
            --arg direction "$dir" \
            --arg label "$label" \
            --argjson bits "$bits" \
            --argjson retrans "$retrans" \
            --argjson rtt "$rtt" \
            --argjson jitter "$jitter" \
            --argjson lost "$lost" \
            --argjson packets "$packets" \
            --argjson cpu_seconds "$cpu_seconds" \
            --argjson test_seconds "$test_seconds" \
            --arg source "$rel" \
            '{run_id: $run_id, protocol: $protocol, mode: $mode, point: $point,
              point_value: $point_value, direction: $direction, label: $label,
              bits_per_second: $bits, retransmits: $retrans, mean_rtt_us: $rtt,
              jitter_ms: $jitter, lost_percent: $lost, packets: $packets,
              cpu_seconds: $cpu_seconds, test_seconds: $test_seconds,
              cpu_per_gbit:
                (if $mode == "curtsy" and $cpu_seconds > 0 and $test_seconds > 0 and $bits > 0
                 then (($cpu_seconds / $test_seconds) * 100) / ($bits / 1e9)
                 else null end),
              source: $source}')
        printf '%s\n' "$obj" >>"$tests_jsonl"

        cpu_per_gbit=""
        if [ "$mode" = "curtsy" ] && [ "${cpu_seconds:-0}" != "0" ] && [ "${test_seconds:-0}" != "0" ] && [ "${bits:-0}" != "0" ]; then
            cpu_per_gbit=$(awk -v c="$cpu_seconds" -v t="$test_seconds" -v b="$bits" \
                'BEGIN{ if (t > 0 && b > 0) printf "%.3f", (c / t * 100) / (b / 1e9) }')
        fi
        [ -n "$cpu_per_gbit" ] || cpu_per_gbit="-"

        if [ "$proto" = "udp" ]; then
            printf '%-24s %-5s %-6s %-8s %-7s %14.0f  jitter=%5.3fms  loss=%6.2f%%  pkts=%s  cpu=%s%%/G\n' \
                "$run_id" "$proto" "$mode" "$point" "$dir" "$bits" "$jitter" "$lost" "$packets" "$cpu_per_gbit" >>"$report_rows"
        else
            printf '%-24s %-5s %-6s %-8s %-7s %14.0f  retrans=%-4s  rtt=%sus  cpu=%s%%/G\n' \
                "$run_id" "$proto" "$mode" "$point" "$dir" "$bits" "$retrans" "$rtt" "$cpu_per_gbit" >>"$report_rows"
        fi
    done
done

# --- summary.json ----------------------------------------------------------
jq -n \
    --arg session "$session" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --slurpfile runs "$tests_jsonl" \
    '{session: $session, generated_at: $generated_at, runs: $runs}' >"$summary_file"

# --- report.txt ------------------------------------------------------------
{
    echo "Curtsy benchmark session: $session"
    echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "Session-level environment snapshots: env-before/ and env-after/"
    echo
    for d in "$session_dir"/env-before/*/; do
        [ -d "$d" ] || continue
        if [ -f "$d/link_speed.txt" ]; then
            echo "Environment snapshot '$(basename "$d")' NICs (env-before):"
            awk '{printf "  %-12s %s\n", $1, ($2=="unknown" ? "unknown" : $2 " Mb/s")}' "$d/link_speed.txt"
            echo
        fi
    done
    printf '%-24s %-5s %-6s %-8s %-7s %14s\n' \
        run protocol mode point direction bits_per_second
    printf '%s\n' '------------------------ ----- ------ -------- ------- ---------------'
    cat "$report_rows"
} >"$report_file"

count=$(wc -l <"$tests_jsonl")
echo "summarized $count test results from ${#run_dirs[@]} run(s)"
