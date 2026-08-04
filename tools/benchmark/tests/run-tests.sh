#!/usr/bin/env bash
#
# run-tests.sh - fixture-based dry-run tests for the Curtsy benchmark harness
# (tools/benchmark). Exercises compare.sh (pass / fail / missing metrics) and
# recommend-system.sh (against a fake /sys + /proc tree with read-only fake
# ethtool/ip, proving the tool never invokes mutating verbs).
#
# Usage: tests/run-tests.sh [--verbose]
# Exit codes: 0 all tests passed, 1 one or more tests failed.

set -u -o pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
FIXTURES="$HERE/tests/fixtures"
COMPARE="$HERE/compare.sh"
RECOMMEND="$HERE/lib/recommend-system.sh"
SUMMARIZE="$HERE/lib/summarize.sh"

TMP=$(mktemp -d /tmp/curtsy-tests.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

passed=0
failed=0

ok() { passed=$((passed + 1)); printf 'PASS %s\n' "$1"; }
bad() { failed=$((failed + 1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

check() { # name expected actual
    if [ "$2" = "$3" ]; then
        ok "$1"
    else
        bad "$1" "expected '$2', got '$3'"
    fi
}

report_expect() { # name json jqexpr ; passes when jqexpr yields true
    local name="$1" json="$2" expr="$3" got
    got=$(jq -r "$expr" "$json" 2>/dev/null || echo "__JQ_ERR__")
    if [ "$got" = "true" ]; then
        ok "$name"
    else
        bad "$name" "expected jq expr to be true, got '$got'"
    fi
}

# --- shell syntax / help checks ---------------------------------------------
for f in \
    run-benchmark.sh \
    compare.sh \
    lib/common.sh \
    lib/collect-env.sh \
    lib/summarize.sh \
    lib/recommend-system.sh; do
    if bash -n "$HERE/$f" 2>"$TMP/bash-n.err"; then
        ok "bash -n $f"
    else
        bad "bash -n $f" "$(cat "$TMP/bash-n.err")"
    fi
done

if "$COMPARE" --help >/dev/null 2>&1; then ok "compare.sh --help exits 0"; else bad "compare.sh --help exits 0" "non-zero"; fi
if "$RECOMMEND" --help >/dev/null 2>&1; then ok "recommend-system.sh --help exits 0"; else bad "recommend-system.sh --help exits 0" "non-zero"; fi

"$COMPARE" >/dev/null 2>&1
check "compare.sh with no args exits 2" 2 "$?"

if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -s bash "$COMPARE" "$RECOMMEND" >/dev/null 2>&1; then
        ok "shellcheck clean"
    else
        bad "shellcheck" "warnings emitted (run shellcheck manually for details)"
    fi
else
    printf 'SKIP shellcheck not installed (reported missing)\n'
fi

# --- compare.sh: pass / fail / missing metrics ------------------------------
compare_run() { # name baseline candidate expected_exit [extra args...]
    local name="$1" base="$2" cand="$3" want="$4"
    shift 4
    local json="$TMP/$name.json"
    if "$COMPARE" "$FIXTURES/compare/$base" "$FIXTURES/compare/$cand" "$@" \
        --json "$json" >"$TMP/$name.txt" 2>&1; then
        local got=$?
        check "$name (exit)" "$want" "0"
    else
        local got=$?
        check "$name (exit)" "$want" "$got"
    fi
    printf '%s' "$json"
}

run_compare_case() { # name baseline candidate expected_exit [extra args...]
    local name="$1" base="$2" cand="$3" want="$4"
    shift 4
    local json="$TMP/$name.json"
    "$COMPARE" "$FIXTURES/compare/$base" "$FIXTURES/compare/$cand" "$@" \
        --json "$json" >"$TMP/$name.txt" 2>&1
    local got=$?
    check "$name (exit)" "$want" "$got"
}

run_compare_case pass baseline.json pass.json 0
report_expect "pass verdict" "$TMP/pass.json" '.verdict == "pass"'
report_expect "pass no failures" "$TMP/pass.json" '(.failures | length) == 0'
report_expect "pass matched all" "$TMP/pass.json" '.matched == 4'

run_compare_case cpu-pass cpu-pass-base.json cpu-pass.json 0
report_expect "cpu-pass verdict" "$TMP/cpu-pass.json" '.verdict == "pass"'
report_expect "cpu-pass cpu status pass" "$TMP/cpu-pass.json" '([.results[] | select(.key == "tcp|curtsy|conn1|forward") | .cpu_status] | index("pass")) != null'
report_expect "cpu-pass no incomparable warning" "$TMP/cpu-pass.json" '([.warnings[] | contains("cpu_per_gbit")] | any) | not'

run_compare_case fail-throughput baseline.json fail-throughput.json 1
report_expect "fail-throughput verdict" "$TMP/fail-throughput.json" '.verdict == "fail"'
report_expect "fail-throughput failure recorded" "$TMP/fail-throughput.json" '(.failures | map(select(.key == "tcp|curtsy|conn1|forward")) | length) == 1'
report_expect "fail-throughput message mentions throughput" "$TMP/fail-throughput.json" '([.failures[].messages[] | contains("throughput")] | any)'

run_compare_case fail-cpu fail-cpu.json fail-cpu-candidate.json 1
report_expect "fail-cpu verdict" "$TMP/fail-cpu.json" '.verdict == "fail"'
report_expect "fail-cpu message mentions cpu-per-gbit" "$TMP/fail-cpu.json" '([.failures[].messages[] | contains("cpu-per-gbit")] | any)'

run_compare_case fail-loss baseline.json fail-loss.json 1
report_expect "fail-loss verdict" "$TMP/fail-loss.json" '.verdict == "fail"'
report_expect "fail-loss message mentions lost_percent" "$TMP/fail-loss.json" '([.failures[].messages[] | contains("lost_percent")] | any)'

run_compare_case fail-retrans baseline.json fail-retrans.json 1
report_expect "fail-retrans verdict" "$TMP/fail-retrans.json" '.verdict == "fail"'
report_expect "fail-retrans message mentions retransmits" "$TMP/fail-retrans.json" '([.failures[].messages[] | contains("retransmits")] | any)'

run_compare_case missing baseline.json missing.json 0
report_expect "missing default verdict pass" "$TMP/missing.json" '.verdict == "pass"'
report_expect "missing reported" "$TMP/missing.json" '(.missing_in_candidate | length) == 1'
report_expect "missing warning listed" "$TMP/missing.json" '([.warnings[] | contains("run missing in candidate")] | any)'

run_compare_case missing-fail baseline.json missing.json 1 --fail-on-missing
report_expect "missing --fail-on-missing verdict" "$TMP/missing-fail.json" '.verdict == "fail"'

run_compare_case metrics-missing baseline.json metrics-missing.json 0
report_expect "metrics-missing verdict pass" "$TMP/metrics-missing.json" '.verdict == "pass"'
report_expect "metrics-missing cpu skip + warning" "$TMP/metrics-missing.json" '([.results[] | select(.key == "tcp|curtsy|conn1|forward") | .cpu_status] | index("skip")) != null'
report_expect "metrics-missing warning text" "$TMP/metrics-missing.json" '([.warnings[] | contains("cpu_per_gbit present only on candidate")] | any)'

run_compare_case no-overlap baseline.json no-overlap.json 3
report_expect "no-overlap verdict" "$TMP/no-overlap.json" '.verdict == "cannot_compare"'

run_compare_case invalid baseline.json invalid.json 3
run_compare_case empty-summary baseline.json empty.json 3

run_compare_case threshold-override baseline.json fail-throughput.json 0 --max-throughput-regression 20
run_compare_case cpu-threshold-override fail-cpu.json fail-cpu-candidate.json 0 --max-cpu-regression 50

# --- recommend-system.sh: fixture-based dry run -----------------------------
rec_run() { # name [extra args...]
    local name="$1"
    shift
    local json="$TMP/$name.json" txt="$TMP/$name.txt"
    CURTSY_RECOMMEND_SYS_ROOT="$FIXTURES/sys" \
    PATH="$FIXTURES/bin:$PATH" \
    "$RECOMMEND" --cpus 8 --target-speed 25 --target-mtu 9000 --host testnode \
        --json "$json" --text "$txt" "$@" >"$TMP/$name.out" 2>&1
    local got=$?
    check "$name (exit)" 0 "$got"
}

rec_run recommend
report_expect "recommend produces findings" "$TMP/recommend.json" '(.findings | length) > 0'
report_expect "recommend governor warning" "$TMP/recommend.json" '([.findings[] | select(.category == "governor" and .severity == "warn")] | length) == 1'
report_expect "recommend rps warning" "$TMP/recommend.json" '([.findings[] | select(.category == "rps" and .severity == "warn")] | length) >= 1'
report_expect "recommend mtu warning" "$TMP/recommend.json" '([.findings[] | select(.category == "mtu" and .severity == "warn")] | length) == 1'
report_expect "recommend irq warning" "$TMP/recommend.json" '([.findings[] | select(.category == "irq" and .severity == "warn")] | length) == 1'
report_expect "recommend socket backlog warning" "$TMP/recommend.json" '([.findings[] | select(.detail | contains("netdev_max_backlog"))] | length) == 1'
report_expect "recommend numa info + numactl command" "$TMP/recommend.json" '([.findings[] | select(.category == "numa" and (.command | contains("numactl"))) ] | length) >= 1'
report_expect "recommend reads NIC speed" "$TMP/recommend.json" '.nics[0].speed_mbps == 25000'
report_expect "recommend reads driver" "$TMP/recommend.json" '.nics[0].driver == "mlx5_core"'
report_expect "recommend reads NUMA node" "$TMP/recommend.json" '.nics[0].numa_node == 1'
report_expect "recommend records cpus" "$TMP/recommend.json" '.cpus == 8'

# Prove read-only behaviour: fake ethtool/ip exit 127 on any mutating verb.
report_expect "recommend never suggests a mutating command" "$TMP/recommend.json" '([.commands[] | contains("MUTATION")] | any) | not'
if ! grep -q "MUTATION" "$TMP/recommend.out"; then
    ok "recommend never invoked a mutating ethtool/ip verb"
else
    bad "recommend never invoked a mutating ethtool/ip verb" "saw MUTATION in output"
fi

# Graceful degradation when ethtool is missing.
CURTSY_RECOMMEND_SYS_ROOT="$FIXTURES/sys" \
CURTSY_RECOMMEND_ETHTOOL=/nonexistent-ethtool \
"$RECOMMEND" --cpus 8 --host testnode --json "$TMP/recommend-noeth.json" --text "$TMP/recommend-noeth.txt" >/dev/null 2>&1
check "recommend without ethtool (exit)" 0 "$?"
report_expect "recommend without ethtool degrades" "$TMP/recommend-noeth.json" '([.findings[] | select(.detail | contains("ethtool unavailable"))] | length) == 1'

# --filter-iface limits inspection.
rec_run recommend-filter --filter-iface enp1s0
report_expect "recommend filter keeps iface" "$TMP/recommend-filter.json" '.nics[0].iface == "enp1s0"'

# --- summarize.sh: CPU-per-Gbit emission ------------------------------------
# Fixture session drives the full meta.json + iperf3 JSON -> summary.json path:
# a curtsy TCP run (2.0 CPU-seconds over 10s at 25 Gbps -> 0.8 %/G), a curtsy
# UDP run (2.4s over 10s at 24 Gbps -> 1.0 %/G) and a direct run (no Curtsy
# process -> cpu_per_gbit null).
"$SUMMARIZE" "$FIXTURES/session/summarize" "$TMP/summarize.json" "$TMP/summarize-report.txt" >"$TMP/summarize.out" 2>&1
check "summarize runs clean" 0 "$?"
report_expect "summarize tcp cpu_per_gbit" "$TMP/summarize.json" '([.runs[] | select(.run_id == "run-001-tcp-curtsy-conn1") | .cpu_per_gbit] | .[0]) == 0.8'
report_expect "summarize udp cpu_per_gbit" "$TMP/summarize.json" '([.runs[] | select(.run_id == "run-002-udp-curtsy-pkt1400") | .cpu_per_gbit] | .[0]) == 1.0'
report_expect "summarize direct cpu_per_gbit null" "$TMP/summarize.json" '([.runs[] | select(.run_id == "run-003-tcp-direct-conn1") | .cpu_per_gbit] | .[0]) == null'
report_expect "summarize cpu_seconds recorded" "$TMP/summarize.json" '([.runs[] | select(.run_id == "run-001-tcp-curtsy-conn1") | .cpu_seconds] | .[0]) == 2.0'
report_expect "summarize test_seconds recorded" "$TMP/summarize.json" '([.runs[] | select(.run_id == "run-001-tcp-curtsy-conn1") | .test_seconds] | .[0]) == 10'

# --- summary ---------------------------------------------------------------
echo
echo "Results: $passed passed, $failed failed"
if [ "$failed" -gt 0 ]; then
    exit 1
fi
exit 0
