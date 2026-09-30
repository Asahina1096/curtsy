#!/usr/bin/env bash
#
# common.sh - shared helpers for the Curtsy benchmark harness
# (tools/benchmark). This file is sourced by run-benchmark.sh; it is never
# executed directly. Requires bash >= 4 and the tools checked by the harness
# itself (ip, ss, jq, iperf3).

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    echo "common.sh is a library and must be sourced, not executed" >&2
    exit 2
fi

set -u

# --- repository layout ----------------------------------------------------
BENCH_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$BENCH_DIR/../.." && pwd)
LIB_DIR="$BENCH_DIR/lib"
PROFILES_DIR="$BENCH_DIR/profiles"
TEMPLATES_DIR="$BENCH_DIR/templates"
COLLECT_ENV_SCRIPT="$LIB_DIR/collect-env.sh"
SUMMARIZE_SCRIPT="$LIB_DIR/summarize.sh"
RECOMMEND_SCRIPT="$LIB_DIR/recommend-system.sh"

TCP_PROFILE_FILE="$PROFILES_DIR/tcp-connections.default"
UDP_PROFILE_FILE="$PROFILES_DIR/udp-packet-sizes.default"
CONFIG_TEMPLATE="$TEMPLATES_DIR/curtsy-config.yaml"

# --- exit codes -----------------------------------------------------------
#  0  check or run completed
#  1  runtime failure during a benchmark run
#  2  usage / argument error
#  3  missing required tool
#  4  environment error (no NIC at link speed, busy port, broken curtsy)
EXIT_OK=0
EXIT_RUNTIME=1
EXIT_USAGE=2
EXIT_TOOL_MISSING=3
EXIT_ENV=4

# --- logging --------------------------------------------------------------
BENCH_LOG_LEVEL="${BENCH_LOG_LEVEL:-info}"
BENCH_VERBOSE="${BENCH_VERBOSE:-0}"

log_line() { # level message...
    local level="$1"
    shift
    printf '[%s] %-5s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$level" "$*" >&2
}

debug() {
    if [ "${BENCH_VERBOSE:-0}" = "1" ]; then
        log_line DEBUG "$@"
    fi
}
info()  { log_line INFO "$@"; }
warn()  { log_line WARN "$@"; }
error() { log_line ERROR "$@"; }

die() { # exit_code message...
    local code="$1"
    shift
    error "$*"
    exit "$code"
}

usage_die() {
    error "$* (see --help)"
    exit "$EXIT_USAGE"
}

# --- identifiers ----------------------------------------------------------
# A session groups all runs produced by one invocation. A run is one
# (protocol, mode, profile-point) test directory under the session.
generate_session_id() {
    printf 'session-%s-%s%s\n' "$(date -u +%Y%m%dT%H%M%SZ)" "$$" "$RANDOM"
}

generate_run_id() { # seq protocol mode point_slug
    printf 'run-%03d-%s-%s-%s' "$1" "$2" "$3" "$4"
}

# --- tool checks ----------------------------------------------------------
require_cmd() { # command
    command -v "$1" >/dev/null 2>&1 || die "$EXIT_TOOL_MISSING" "missing required tool: $1"
}

# --- node abstraction -----------------------------------------------------
# A node spec is either `local` (commands run on this host) or a
# `[user@]host` reachable with passwordless ssh. All node access goes through
# node_run, so remote and local behaviour stays identical.

node_is_remote() { # spec
    case "$1" in
        local | "") return 1 ;;
        *) return 0 ;;
    esac
}

node_run() { # spec shell_command_string
    local node="$1" cmd="$2"
    if node_is_remote "$node"; then
        debug "ssh $node: $cmd"
        ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$node" "$cmd"
    else
        debug "local: $cmd"
        bash -c "$cmd"
    fi
}

node_fetch() { # spec remote_path local_path
    local node="$1" remote_path="$2" local_path="$3"
    if node_is_remote "$node"; then
        scp -q -o BatchMode=yes -o ConnectTimeout=10 "$node:$remote_path" "$local_path"
    else
        cp "$remote_path" "$local_path"
    fi
}

node_hostname() { # spec
    node_run "$1" "hostname" 2>/dev/null || echo "unknown"
}

node_start_background() { # spec pidfile logfile command...
    local node="$1" pidfile="$2" logfile="$3"
    shift 3
    local cmd
    cmd="nohup "
    for a in "$@"; do
        cmd="$cmd '$(printf '%s' "$a" | sed "s/'/'\\\\''/g")'"
    done
    cmd="$cmd >>'$logfile' 2>&1 </dev/null & echo \$! >'$pidfile'"
    node_run "$node" "$cmd"
}

node_stop_background() { # spec pidfile
    local node="$1" pidfile="$2"
    node_run "$node" "if [ -f '$pidfile' ]; then kill \$(cat '$pidfile') 2>/dev/null || true; fi"
}

node_kill_force() { # spec pidfile
    local node="$1" pidfile="$2"
    node_run "$node" "[ -f '$pidfile' ] && kill -9 \$(cat '$pidfile') 2>/dev/null || true; rm -f '$pidfile'"
}

node_wait_stopped() { # spec pidfile timeout_seconds ; returns 0 when gone
    local node="$1" pidfile="$2" timeout="${3:-20}"
    local i=0
    while [ "$i" -lt "$timeout" ]; do
        if ! node_run "$node" "[ -f '$pidfile' ] && kill -0 \"\$(cat '$pidfile')\" 2>/dev/null" >/dev/null 2>&1; then
            node_run "$node" "rm -f '$pidfile'" 2>/dev/null || true
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

wait_for_port() { # spec port timeout_seconds ; returns 0 when listening
    local node="$1" port="$2" timeout="${3:-15}"
    local i=0
    while [ "$i" -lt "$timeout" ]; do
        if node_run "$node" "ss -H -ltn 'sport = :$port' 2>/dev/null | grep -q ." >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

port_in_use() { # spec port ; returns 0 when busy
    local node="$1" port="$2"
    node_run "$node" "ss -H -ltn 'sport = :$port' 2>/dev/null | grep -q ." >/dev/null 2>&1
}

node_require_cmd() { # spec command
    local node="$1" cmd="$2"
    if node_is_remote "$node"; then
        node_run "$node" "command -v '$cmd'" >/dev/null 2>&1 ||
            die "$EXIT_TOOL_MISSING" "missing required tool: $cmd (on node $node)"
    else
        require_cmd "$cmd"
    fi
}

# --- addresses ------------------------------------------------------------
# Resolve the primary IPv4 address used to reach a node from elsewhere. Falls
# back to 127.0.0.1 when nothing usable is found (e.g. container hosts).
resolve_primary_ipv4() { # spec
    local node="$1" out
    out=$(node_run "$node" "hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\\.' | grep -v '^127\\.' | head -n 1" 2>/dev/null || true)
    if [ -z "${out:-}" ]; then
        out=$(node_run "$node" "hostname -I 2>/dev/null | awk '{print \$1}'" 2>/dev/null || true)
    fi
    if [ -z "${out:-}" ]; then
        out="127.0.0.1"
    fi
    printf '%s\n' "$out"
}

# --- configuration generation ----------------------------------------------
# The curtsy config used by the proxied tests is produced from the template
# under tools/benchmark/templates. Only placeholders are substituted; nothing
# outside tools/benchmark is written.
generate_curtsy_config() { # listen_host listen_port upstream_host upstream_port \
    #   protocols tcp_sockmap udp_sockmap udp_sockbuf workers output
    local listen_host="$1" listen_port="$2" upstream_host="$3" upstream_port="$4"
    local protocols="$5" tcp_sockmap="$6" udp_sockmap="$7" udp_sockbuf="$8"
    local workers="$9" output="${10}"
    sed -e "s|__LISTEN_HOST__|$listen_host|g" \
        -e "s|__LISTEN_PORT__|$listen_port|g" \
        -e "s|__UPSTREAM_HOST__|$upstream_host|g" \
        -e "s|__UPSTREAM_PORT__|$upstream_port|g" \
        -e "s|__PROTOCOLS__|$protocols|g" \
        -e "s|__TCP_SOCKMAP__|$tcp_sockmap|g" \
        -e "s|__UDP_SOCKMAP__|$udp_sockmap|g" \
        -e "s|__UDP_SOCK_BUF__|$udp_sockbuf|g" \
        -e "s|__WORKER_THREADS__|$workers|g" \
        "$CONFIG_TEMPLATE" > "$output"
}

# --- small helpers ---------------------------------------------------------
point_slug() { # protocol point_value
    case "$1" in
        tcp) printf 'conn%s' "$2" ;;
        udp) printf 'pkt%s' "$2" ;;
    esac
}

is_numeric() {
    case "$1" in
        '' | *[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

# Parse a profile file: numbers separated by whitespace/commas, '#' comments.
load_profile_list() { # file
    local file="$1"
    sed -e 's/[[:space:],]\+/\n/g' "$file" | grep -E '^[0-9]+$' || true
}

parse_csv_numbers() { # "1,4,16,64"
    printf '%s' "$1" | sed -e 's/[[:space:],]\+/\n/g' | grep -E '^[0-9]+$' || true
}

# jq_value file 'expr with // fallback' -> raw value (or fallback text)
jq_value() { # file expr
    local file="$1" expr="$2"
    jq -r "$expr" "$file" 2>/dev/null || printf '0\n'
}
