#!/usr/bin/env bash
#
# run-benchmark.sh - Curtsy 25 Gbps benchmark harness.
#
# Orchestrates iperf3 throughput benchmarks comparing a direct client->server
# baseline against the same traffic proxied through Curtsy. Results are stored
# as raw iperf3 JSON plus environment/NIC/softirq snapshots under the session
# output directory, and aggregated into summary.json / report.txt.
#
# Only tools/benchmark/ and docs/performance.md are owned by this harness.
# It never modifies system settings; it only prints recommended commands.
#
# Modes:
#   --check | --dry-run   Validate the environment, print the execution plan
#                         and any recommended commands, then exit (default).
#   --run                 Execute the benchmark session.
#
# Usage: run-benchmark.sh [options]
# Run `run-benchmark.sh --help` for the full option list.

set -eu -o pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

# --- defaults --------------------------------------------------------------
mode=check
client=local
proxy=local
server=local
client_addr=""
proxy_addr=""
upstream_addr=""
listen_host=""
protocols=both
duration=10
bandwidth=25G
direction=both
tcp_connections=""
udp_packet_sizes=""
link_speed=25
mtu=1500
udp_sockbuf=4194304
acceleration=auto
# runtime.workerThreads has no auto mode: default to one thread per CPU,
# capped at 32 as host-derived selection used to do.
worker_threads=$(nproc 2>/dev/null || echo 1)
case "$worker_threads" in '' | *[!0-9]*) worker_threads=1 ;; esac
if [ "$worker_threads" -gt 32 ]; then worker_threads=32; fi
curtsy_binary="$REPO_ROOT/zig-out/bin/curtsy"
listen_port=9000
upstream_port=9001
user_config=""
output_dir="/tmp/curtsy-benchmark"
session_name=""
label=""
force=0
keep_artifacts=0
verbose=0

usage() {
    cat <<'EOF'
Usage: run-benchmark.sh [options]

Curtsy 25 Gbps benchmark harness: iperf3 direct-vs-Curtsy TCP/UDP throughput
profiling with environment/NIC/softirq collection.

Modes:
  --check, --dry-run   Validate environment, print the execution plan and any
                       recommended system settings, then exit (default).
  --run                Execute the benchmark session.
  --recommend          Read-only per-node system tuning recommendations
                       (NIC/IRQ/NUMA/RPS/RSS/sysctl). Never modifies anything.
  -h, --help           Print this help and exit.

Endpoints (each is `local` or a `[user@]host` reachable via passwordless ssh):
  --client <spec>      Node running the iperf3 client.        [local]
  --proxy <spec>       Node running Curtsy.                   [local]
  --server <spec>      Node running the iperf3 upstream.      [local]
  --client-addr <ip>   Address the client uses for the direct baseline.
  --proxy-addr <ip>    Address the client uses for the proxied target.
  --upstream-addr <ip> Address Curtsy uses for the upstream server.
  --listen-host <ip>   Curtsy listen.host; default 127.0.0.1 for local
                       loops, else the proxy's primary IPv4.

Benchmark:
  --protocols <p>      tcp | udp | both                          [both]
  --duration <s>       Per-test duration (integer).              [10]
  --bandwidth <rate>   UDP target rate, e.g. 25G.                [25G]
  --direction <d>      forward | reverse | both                  [both]
  --tcp-connections <l>  Comma list overriding the TCP profile.
  --udp-packet-sizes <l> Comma list overriding the UDP profile.
  --link-speed <g>     Minimum NIC speed gate, Gbps.             [25]
  --mtu <bytes>        MTU under test; validated/reported, never set. [1500]
  --udp-socket-buffer <b> iperf3 -w for UDP tests (bytes).       [4194304]
  --acceleration <a>   auto | enabled | disabled (sockmap).      [auto]

Curtsy:
  --curtsy-binary <p>  Path to the curtsy binary.               [repo/zig-out/bin/curtsy]
  --listen-port <p>    Curtsy listen port.                      [9000]
  --upstream-port <p>  iperf3 server port.                      [9001]
  --config <path>      Reuse an existing curtsy config instead of the
                       generated one; ports above must match it.
  --worker-threads <n> runtime.workerThreads (positive int).  [nproc, max 32]

Session:
  --output-dir <dir>   Parent directory for results.            [/tmp/curtsy-benchmark]
  --session <name>     Session id (timestamp-based otherwise).
  --label <text>       Free-form label recorded in every result.
  --force              Bypass the link-speed gate (loopback smoke tests).
  --keep-artifacts     Keep temporary files.
  --verbose            Debug logging.

Result layout (output-dir/session):
  session-meta.json      session metadata and full command line
  plan.json              planned tests + warnings + recommended commands
  env-before/, env-after/  per-node environment/NIC/softirq snapshots
  run-<seq>-<proto>-<mode>-<point>/
    meta.json            run metadata (mode is direct or curtsy)
    iperf3-forward.json  raw iperf3 --json (client)
    iperf3-reverse.json  raw iperf3 --json when reverse direction ran
    curtsy-config.yaml   config used by the proxied run
  summary.json           machine-readable aggregated results (regression)
  report.txt             human-readable summary table

Exit codes: 0 ok, 1 runtime failure, 2 usage error, 3 missing required tool,
4 environment error (no NIC at link speed / busy port / broken curtsy).
EOF
}

# --- argument parsing ------------------------------------------------------
parse_args() {
    local args=()
    local a
    for a in "$@"; do
        case "$a" in
            --*=*) args+=("${a%%=*}" "${a#*=}") ;;
            *) args+=("$a") ;;
        esac
    done
    set -- "${args[@]}"
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --help | -h) usage && exit 0 ;;
            --check | --dry-run) mode=check; shift ;;
            --run) mode=run; shift ;;
            --recommend) mode=recommend; shift ;;
            --force) force=1; shift ;;
            --verbose) verbose=1; BENCH_VERBOSE=1; shift ;;
            --keep-artifacts) keep_artifacts=1; shift ;;
            --client) client=${2:?missing value for --client}; shift 2 ;;
            --proxy) proxy=${2:?missing value for --proxy}; shift 2 ;;
            --server) server=${2:?missing value for --server}; shift 2 ;;
            --client-addr) client_addr=${2:?missing value for --client-addr}; shift 2 ;;
            --proxy-addr) proxy_addr=${2:?missing value for --proxy-addr}; shift 2 ;;
            --upstream-addr) upstream_addr=${2:?missing value for --upstream-addr}; shift 2 ;;
            --listen-host) listen_host=${2:?missing value for --listen-host}; shift 2 ;;
            --protocols) protocols=${2:?missing value for --protocols}; shift 2 ;;
            --duration) duration=${2:?missing value for --duration}; shift 2 ;;
            --bandwidth) bandwidth=${2:?missing value for --bandwidth}; shift 2 ;;
            --direction) direction=${2:?missing value for --direction}; shift 2 ;;
            --tcp-connections) tcp_connections=${2:?missing value for --tcp-connections}; shift 2 ;;
            --udp-packet-sizes) udp_packet_sizes=${2:?missing value for --udp-packet-sizes}; shift 2 ;;
            --link-speed) link_speed=${2:?missing value for --link-speed}; shift 2 ;;
            --mtu) mtu=${2:?missing value for --mtu}; shift 2 ;;
            --udp-socket-buffer) udp_sockbuf=${2:?missing value for --udp-socket-buffer}; shift 2 ;;
            --acceleration) acceleration=${2:?missing value for --acceleration}; shift 2 ;;
            --curtsy-binary) curtsy_binary=${2:?missing value for --curtsy-binary}; shift 2 ;;
            --listen-port) listen_port=${2:?missing value for --listen-port}; shift 2 ;;
            --upstream-port) upstream_port=${2:?missing value for --upstream-port}; shift 2 ;;
            --config) user_config=${2:?missing value for --config}; shift 2 ;;
            --output-dir) output_dir=${2:?missing value for --output-dir}; shift 2 ;;
            --session) session_name=${2:?missing value for --session}; shift 2 ;;
            --label) label=${2:?missing value for --label}; shift 2 ;;
            --worker-threads) worker_threads=${2:?missing value for --worker-threads}; shift 2 ;;
            *)
                usage_die "unexpected argument: $1"
                ;;
        esac
    done
}

# --- validation ------------------------------------------------------------
validate_args() {
    case "$protocols" in tcp | udp | both) ;; *) usage_die "--protocols must be tcp, udp or both (got '$protocols')" ;; esac
    case "$direction" in forward | reverse | both) ;; *) usage_die "--direction must be forward, reverse or both" ;; esac
    case "$acceleration" in auto | enabled | disabled) ;; *) usage_die "--acceleration must be auto, enabled or disabled" ;; esac
    is_numeric "$duration" || usage_die "--duration must be a positive integer (got '$duration')"
    is_numeric "$link_speed" || usage_die "--link-speed must be a number of Gbps"
    is_numeric "$mtu" || usage_die "--mtu must be a number of bytes"
    is_numeric "$udp_sockbuf" || usage_die "--udp-socket-buffer must be a number of bytes"
    is_numeric "$listen_port" && [ "$listen_port" -ge 1 ] && [ "$listen_port" -le 65535 ] ||
        usage_die "--listen-port must be 1..65535 (got '$listen_port')"
    is_numeric "$upstream_port" && [ "$upstream_port" -ge 1 ] && [ "$upstream_port" -le 65535 ] ||
        usage_die "--upstream-port must be 1..65535 (got '$upstream_port')"
    [ "$listen_port" -ne "$upstream_port" ] || usage_die "--listen-port and --upstream-port must differ"
    [ -n "$bandwidth" ] || usage_die "--bandwidth must be non-empty"
    case "$worker_threads" in '' | *[!0-9]*) usage_die "--worker-threads must be a positive integer" ;; esac
    [ "$worker_threads" -ge 1 ] || usage_die "--worker-threads must be at least 1"
    if [ -n "$user_config" ]; then
        [ -f "$user_config" ] || die "$EXIT_USAGE" "--config file not found: $user_config"
        warn "--config in use: ensure --listen-port/--upstream-port match its values"
    fi
}

load_profiles() {
    if [ -n "$tcp_connections" ]; then
        mapfile -t tcp_profile < <(parse_csv_numbers "$tcp_connections")
    else
        mapfile -t tcp_profile < <(load_profile_list "$TCP_PROFILE_FILE")
    fi
    if [ -n "$udp_packet_sizes" ]; then
        mapfile -t udp_profile < <(parse_csv_numbers "$udp_packet_sizes")
    else
        mapfile -t udp_profile < <(load_profile_list "$UDP_PROFILE_FILE")
    fi
    [ "${#tcp_profile[@]}" -gt 0 ] || usage_die "TCP profile is empty"
    [ "${#udp_profile[@]}" -gt 0 ] || usage_die "UDP profile is empty"

    local filtered=() sz
    for sz in "${udp_profile[@]}"; do
        if [ "$sz" -ge 8500 ] && [ "$mtu" -lt 8500 ]; then
            warn "dropping UDP size $sz (jumbo) because --mtu $mtu < 8500"
            continue
        fi
        filtered+=("$sz")
    done
    udp_profile=("${filtered[@]}")
    [ "${#udp_profile[@]}" -gt 0 ] || usage_die "UDP profile is empty after the MTU filter"

    case "$protocols" in
        tcp) protos=(tcp) ;;
        udp) protos=(udp) ;;
        both) protos=(tcp udp) ;;
    esac
    case "$direction" in
        forward) directions=(forward) ;;
        reverse) directions=(reverse) ;;
        both) directions=(forward reverse) ;;
    esac
}

config_protocols_string() {
    # iperf3 UDP tests still open a TCP control channel to the same
    # target:port (test parameters and results travel over it), so whenever
    # UDP is profiled the Curtsy config must also listen for TCP, even when
    # the profile itself is UDP-only. TCP-only profiles stay TCP-only.
    local want_tcp=0 want_udp=0 p
    for p in "${protos[@]}"; do
        case "$p" in
            tcp) want_tcp=1 ;;
            udp) want_udp=1 ;;
        esac
    done
    [ "$want_udp" = 1 ] && want_tcp=1
    if [ "$want_tcp" = 1 ]; then printf 'tcp'; fi
    if [ "$want_udp" = 1 ]; then
        if [ "$want_tcp" = 1 ]; then printf ', '; fi
        printf 'udp'
    fi
}

# --- setup ----------------------------------------------------------------
session=""
session_dir=""
session_tmp=""
tmp_warns=""
tmp_cmds=""
session_pids_file=""
probe_config=""
tcp_profile=()
udp_profile=()
protos=()
directions=()
pts=()

cleanup_stale() {
    if [ -f "${session_pids_file:-}" ]; then
        local node pidfile
        while read -r node pidfile; do
            [ -n "${node:-}" ] || continue
            node_stop_background "$node" "$pidfile" 2>/dev/null || true
            node_kill_force "$node" "$pidfile" 2>/dev/null || true
        done <"$session_pids_file"
    fi
    if [ -n "${session_tmp:-}" ] && [ "${keep_artifacts:-0}" != "1" ]; then
        rm -rf "$session_tmp"
    fi
}

rec_warning() { printf '%s\n' "$1" >>"$tmp_warns"; }
rec_command() { printf '%s\n' "$1" >>"$tmp_cmds"; }

node_dirname() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }

setup() {
    session=${session_name:-$(generate_session_id)}
    session_dir="$output_dir/$session"
    mkdir -p "$session_dir"
    session_tmp=$(mktemp -d /tmp/curtsy-bench.XXXXXX)
    tmp_warns="$session_tmp/warnings.txt"
    tmp_cmds="$session_tmp/commands.txt"
    session_pids_file="$session_tmp/pids"
    : >"$tmp_warns"
    : >"$tmp_cmds"
    trap cleanup_stale EXIT

    resolve_addresses

    if [ "$mode" = recommend ]; then
        gate_tools check
        return 0
    fi

    if [ -n "$user_config" ]; then
        probe_config="$user_config"
    else
        probe_config="$session_dir/probe-curtsy-config.yaml"
        generate_curtsy_config \
            "$listen_host_val" "$listen_port" "$upstream_target" "$upstream_port" \
            "$(config_protocols_string)" "$acceleration" "$acceleration" "$udp_sockbuf" \
            "$worker_threads" "$probe_config"
    fi

    validate_curtsy
    gate_tools "$mode"

    CLIENT_HOST=$(node_hostname "$client")
    PROXY_HOST=$(node_hostname "$proxy")
    SERVER_HOST=$(node_hostname "$server")
    IPERF_VERSION=$(node_run "$client" "iperf3 --version 2>&1 | head -n 1" 2>/dev/null || echo "unknown")
}

resolve_addresses() {
    # Address the client uses to reach the iperf3 server (direct baseline).
    if [ -n "$client_addr" ]; then
        direct_target="$client_addr"
    elif node_is_remote "$client" || node_is_remote "$server"; then
        direct_target=$(resolve_primary_ipv4 "$server")
    else
        direct_target="127.0.0.1"
    fi
    # Address the client uses to reach Curtsy (proxied target).
    if [ -n "$proxy_addr" ]; then
        proxy_target="$proxy_addr"
    elif node_is_remote "$client" || node_is_remote "$proxy"; then
        proxy_target=$(resolve_primary_ipv4 "$proxy")
    else
        proxy_target="127.0.0.1"
    fi
    # Address Curtsy uses to reach the upstream iperf3 server.
    if [ -n "$upstream_addr" ]; then
        upstream_target="$upstream_addr"
    elif node_is_remote "$server"; then
        upstream_target=$(resolve_primary_ipv4 "$server")
    else
        upstream_target="127.0.0.1"
    fi
    # Curtsy listen host.
    if [ -n "$listen_host" ]; then
        listen_host_val="$listen_host"
    elif [ "$proxy" = "local" ] && [ "$client" = "local" ]; then
        listen_host_val="127.0.0.1"
    else
        listen_host_val=$(resolve_primary_ipv4 "$proxy")
    fi
}

# --- tool / env gates ------------------------------------------------------
tool_present() { # spec cmd
    local spec="$1" cmd="$2"
    if node_is_remote "$spec"; then
        node_run "$spec" "command -v '$cmd'" >/dev/null 2>&1
    else
        command -v "$cmd" >/dev/null 2>&1
    fi
}

gate_tools() { # mode
    local mode="$1" hard=0
    [ "$mode" = run ] && hard=1
    if node_is_remote "$client" || node_is_remote "$proxy" || node_is_remote "$server"; then
        require_cmd ssh
        require_cmd scp
    fi

    local spec cmd
    check_one() { # spec cmd hard
        if tool_present "$1" "$2"; then
            return 0
        fi
        if [ "$3" = 1 ]; then
            die "$EXIT_TOOL_MISSING" "missing required tool: $2 (on node $1)"
        fi
        warn "missing tool: $2 (on node $1) - benchmarks blocked until installed"
        rec_warning "missing tool $2 on node $1"
        rec_command "install $2 on $1"
        return 0
    }

    # Foundational tools are required in every mode: the harness cannot
    # produce plan.json/summary.json (jq) or manage ports/processes (ip, ss)
    # without them. iperf3 is only hard-required for --run; check mode reports
    # it as a warning so validation works on machines without iperf3.
    check_one local jq 1
    check_one local ip 1
    check_one local ss 1
    check_one "$client" bash 1
    check_one "$client" iperf3 "$hard"
    check_one "$proxy" bash 1
    check_one "$proxy" ip 1
    check_one "$proxy" ss 1
    check_one "$server" bash 1
    check_one "$server" iperf3 "$hard"
    check_one "$server" ss 1
    if ! command -v ethtool >/dev/null 2>&1; then
        warn "ethtool missing locally: NIC link speeds will be reported as unknown"
    fi
}

validate_curtsy() {
    local ver
    if node_is_remote "$proxy"; then
        ver=$(node_run "$proxy" "'$curtsy_binary' --version" 2>&1) ||
            die "$EXIT_ENV" "curtsy binary not runnable on $proxy: $curtsy_binary"
        local remote_cfg
        remote_cfg=$(node_run "$proxy" "mktemp /tmp/curtsy-bench.XXXXXX.yaml")
        scp -q -o BatchMode=yes "$probe_config" "$proxy:$remote_cfg"
        if ! node_run "$proxy" "'$curtsy_binary' --config '$remote_cfg' --check-config" >/dev/null 2>&1; then
            node_run "$proxy" "rm -f '$remote_cfg'"
            die "$EXIT_ENV" "curtsy rejected the generated config on $proxy"
        fi
        node_run "$proxy" "rm -f '$remote_cfg'"
    else
        ver=$("$curtsy_binary" --version 2>&1) ||
            die "$EXIT_ENV" "curtsy binary not runnable: $curtsy_binary (use --curtsy-binary)"
        if ! "$curtsy_binary" --config "$probe_config" --check-config >/dev/null 2>&1; then
            die "$EXIT_ENV" "curtsy rejected the generated config: $probe_config"
        fi
    fi
    info "curtsy OK: $(printf '%s' "$ver" | head -n 1) ($curtsy_binary)"
}

# --- environment collection -------------------------------------------------
collect_env_on_node() { # spec dest
    local node="$1" dest="$2" remote_tmp
    mkdir -p "$dest"
    if node_is_remote "$node"; then
        remote_tmp=$(node_run "$node" "mktemp -d /tmp/curtsy-env.XXXXXX")
        scp -q -o BatchMode=yes "$COLLECT_ENV_SCRIPT" "$node:$remote_tmp/collect-env.sh"
        node_run "$node" "bash '$remote_tmp/collect-env.sh' '$remote_tmp/out'"
        mkdir -p "$dest"
        scp -q -r -o BatchMode=yes "$node:$remote_tmp/out/." "$dest/"
        node_run "$node" "rm -rf '$remote_tmp'"
    else
        bash "$COLLECT_ENV_SCRIPT" "$dest"
    fi
}

collect_env_session() { # before|after
    local phase="$1" node
    local -A seen=()
    for node in "$client" "$proxy" "$server"; do
        if [ -n "${seen[$node]:-}" ]; then
            continue
        fi
        seen[$node]=1
        info "collecting environment ($phase) on $node"
        collect_env_on_node "$node" "$session_dir/env-$phase/$(node_dirname "$node")" ||
            warn "environment collection on $node ($phase) failed"
    done
}

node_has_link_speed() { # spec ; returns 0 when a NIC is at/above link_speed
    local node="$1"
    local f="$session_dir/env-before/$(node_dirname "$node")/link_speed.txt"
    [ -f "$f" ] || return 1
    local iface speed
    while read -r iface speed; do
        [ -n "${iface:-}" ] || continue
        [ "$speed" = unknown ] && continue
        if is_numeric "$speed" && [ "$speed" -ge "$((link_speed * 1000))" ]; then
            return 0
        fi
    done <"$f"
    return 1
}

check_link_speed() { # mode check|run
    local mode="$1" node
    for node in "$client" "$proxy" "$server"; do
        if node_has_link_speed "$node"; then
            info "node $node has a NIC at >= ${link_speed}Gbps"
        elif [ "$mode" = check ]; then
            warn "node $node: no NIC detected at >= ${link_speed}Gbps (link speed unknown or below target)"
            rec_warning "node $node: no NIC at >= ${link_speed}Gbps detected"
            rec_command "use a ${link_speed}Gbps NIC on $node, or pass --force to bypass this gate"
        else
            if [ "$force" = 1 ]; then
                warn "node $node: no NIC at >= ${link_speed}Gbps, continuing due to --force"
            else
                die "$EXIT_ENV" "no NIC at >= ${link_speed}Gbps on $node; use --force to run anyway (e.g. loopback smoke test)"
            fi
        fi
    done
}

check_ports() { # mode check|run
    local mode="$1"
    if port_in_use "$proxy" "$listen_port"; then
        if [ "$mode" = check ]; then
            warn "listen port $listen_port already in use on $proxy"
            rec_warning "listen port $listen_port in use on $proxy"
            rec_command "free port $listen_port on $proxy or change --listen-port"
        else
            die "$EXIT_ENV" "listen port $listen_port already in use on $proxy"
        fi
    fi
    if port_in_use "$server" "$upstream_port"; then
        if [ "$mode" = check ]; then
            warn "upstream port $upstream_port already in use on $server"
            rec_warning "upstream port $upstream_port in use on $server"
            rec_command "free port $upstream_port on $server or change --upstream-port"
        else
            die "$EXIT_ENV" "upstream port $upstream_port already in use on $server"
        fi
    fi
}

check_sysctl_recommendations() {
    local node f
    for node in "$client" "$proxy" "$server"; do
        f="$session_dir/env-before/$(node_dirname "$node")/sysctl.txt"
        [ -f "$f" ] || continue
        local rmem wmem
        rmem=$(awk '/^net.core.rmem_max/{print $3}' "$f" 2>/dev/null || true)
        wmem=$(awk '/^net.core.wmem_max/{print $3}' "$f" 2>/dev/null || true)
        if [ -n "$rmem" ] && [ "$rmem" -lt 8388608 ]; then
            warn "net.core.rmem_max=$rmem < 8MiB on $node"
            rec_warning "net.core.rmem_max=$rmem < 8MiB on $node"
            rec_command "sudo sysctl -w net.core.rmem_max=8388608   # on $node"
        fi
        if [ -n "$wmem" ] && [ "$wmem" -lt 8388608 ]; then
            warn "net.core.wmem_max=$wmem < 8MiB on $node"
            rec_warning "net.core.wmem_max=$wmem < 8MiB on $node"
            rec_command "sudo sysctl -w net.core.wmem_max=8388608   # on $node"
        fi
    done
    if [ "$link_speed" -ge 25 ]; then
        rec_command "For ${link_speed}Gbps TCP consider: sudo sysctl -w net.ipv4.tcp_rmem='4096 262144 16777216' net.ipv4.tcp_wmem='4096 262144 16777216' net.core.rmem_max=16777216 net.core.wmem_max=16777216 (persist via /etc/sysctl.d)"
    fi
}

check_mtu() {
    local node f iface cur
    for node in "$client" "$proxy" "$server"; do
        f="$session_dir/env-before/$(node_dirname "$node")/nics.txt"
        [ -f "$f" ] || continue
        if grep -q "mtu $mtu " "$f" 2>/dev/null; then
            continue
        fi
        iface=$(grep -E '^[0-9]+: .*mtu ' "$f" | head -n 1 | sed -E 's/^[0-9]+: ([^:]+):.*/\1/' 2>/dev/null || true)
        cur=$(grep -E '^[0-9]+: .*mtu ' "$f" | head -n 1 | sed -E 's/.*mtu ([0-9]+).*/\1/' 2>/dev/null || true)
        if [ -n "$iface" ] && [ -n "$cur" ] && [ "$cur" != "$mtu" ]; then
            warn "interface $iface on $node has MTU $cur, requested $mtu"
            rec_warning "interface $iface on $node MTU $cur != requested $mtu"
            rec_command "sudo ip link set $iface mtu $mtu   # on $node"
        fi
    done
}

# --- plan ------------------------------------------------------------------
build_tests_plan() { # writes tests JSONL into session_tmp
    : >"$session_tmp/tests.jsonl"
    local seq=0 proto pt mode dir target
    for proto in "${protos[@]}"; do
        if [ "$proto" = tcp ]; then pts=("${tcp_profile[@]}"); else pts=("${udp_profile[@]}"); fi
        for pt in "${pts[@]}"; do
            for mode in direct curtsy; do
                seq=$((seq + 1))
                if [ "$mode" = direct ]; then target="$direct_target"; else target="$proxy_target"; fi
                local run_id
                run_id=$(generate_run_id "$seq" "$proto" "$mode" "$(point_slug "$proto" "$pt")")
                for dir in "${directions[@]}"; do
                    jq -cn \
                        --arg run_id "$run_id" \
                        --arg protocol "$proto" \
                        --arg mode "$mode" \
                        --arg point "$(point_slug "$proto" "$pt")" \
                        --argjson point_value "$pt" \
                        --arg direction "$dir" \
                        --arg target "$target" \
                        '{run_id:$run_id, protocol:$protocol, mode:$mode, point:$point,
                          point_value:$point_value, direction:$direction, target:$target}' \
                        >>"$session_tmp/tests.jsonl"
                done
            done
        done
    done
}

json_array_from_lines() { # file
    if [ -s "$1" ]; then
        jq -R -s 'split("\n") | map(select(length > 0))' "$1"
    else
        printf '[]\n'
    fi
}

write_plan() { # mode
    local mode="$1"
    local warnings_json commands_json
    warnings_json=$(json_array_from_lines "$tmp_warns")
    commands_json=$(json_array_from_lines "$tmp_cmds")
    jq -n \
        --arg session "$session" \
        --arg mode "$mode" \
        --arg label "$label" \
        --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg hostname "$(hostname)" \
        --arg client "$client" --arg proxy "$proxy" --arg server "$server" \
        --arg direct_target "$direct_target" --arg proxy_target "$proxy_target" --arg upstream_target "$upstream_target" \
        --argjson duration "$duration" --arg bandwidth "$bandwidth" --arg direction "$direction" \
        --arg link_speed "${link_speed}G" --argjson mtu "$mtu" \
        --argjson listen_port "$listen_port" --argjson upstream_port "$upstream_port" \
        --arg acceleration "$acceleration" --arg worker_threads "$worker_threads" \
        --arg curtsy_binary "$curtsy_binary" \
        --arg curtsy_version "$("$curtsy_binary" --version 2>/dev/null || echo unknown)" \
        --slurpfile tests "$session_tmp/tests.jsonl" \
        --argjson warnings "$warnings_json" \
        --argjson recommended_commands "$commands_json" \
        '{session:$session, mode:$mode, label:$label, generated_at:$generated_at, hostname:$hostname,
          endpoints:{client:$client, proxy:$proxy, server:$server},
          targets:{direct:$direct_target, proxy:$proxy_target, upstream:$upstream_target},
          parameters:{duration:$duration, bandwidth:$bandwidth, direction:$direction,
                      link_speed:$link_speed, mtu:$mtu, listen_port:$listen_port,
                      upstream_port:$upstream_port, acceleration:$acceleration,
                      worker_threads:$worker_threads, curtsy_binary:$curtsy_binary,
                      curtsy_version:$curtsy_version},
          tests:$tests, warnings:$warnings, recommended_commands:$recommended_commands}' \
        >"$session_dir/plan.json"
}

print_check_report() {
    {
        echo "========================================================================="
        echo "Curtsy benchmark harness - environment check"
        echo "Session: $session   Mode: check (no benchmarks executed)"
        echo "Nodes: client=$client  proxy=$proxy  server=$server"
        echo "Targets: direct=$direct_target  proxy=$proxy_target  upstream=$upstream_target"
        echo "Parameters: protocols=$protocols duration=${duration}s bandwidth=$bandwidth"
        echo "            direction=$direction link-speed=${link_speed}G mtu=$mtu accel=$acceleration"
        echo "            listen=:$listen_port upstream=:$upstream_port"
        echo
        echo "Detected NICs (local node, env-before):"
        while read -r iface speed; do
            [ -n "${iface:-}" ] || continue
            if [ "$speed" = unknown ]; then
                printf '  %-12s %s\n' "$iface" "unknown (cannot confirm link speed)"
            else
                printf '  %-12s %s\n' "$iface" "$speed Mb/s"
            fi
        done <"$session_dir/env-before/$(node_dirname "$client")/link_speed.txt" 2>/dev/null || true
        echo
        if [ -s "$tmp_cmds" ]; then
            echo "Recommended commands (NOT applied automatically):"
            sed 's/^/  \$ /' "$tmp_cmds"
            echo
        fi
        if [ -s "$tmp_warns" ]; then
            echo "Warnings:"
            sed 's/^/  - /' "$tmp_warns"
            echo
        fi
        echo "Planned iperf3 invocations: $(wc -l <"$session_tmp/tests.jsonl" | tr -d ' ')"
        echo "Plan written to: $session_dir/plan.json"
        echo "Environment snapshots: $session_dir/env-before/"
        echo "========================================================================="
    }
}

# --- process lifecycle -----------------------------------------------------
track_process() { echo "$1 $2" >>"$session_pids_file"; }

iperf_pidfile=""
iperf_logfile=""
curtsy_pidfile=""
curtsy_logfile=""
RUN_DIR=""

start_iperf_server() {
    iperf_pidfile=$(node_run "$server" "mktemp /tmp/iperf3-pid.XXXXXX")
    iperf_logfile=$(node_run "$server" "mktemp /tmp/iperf3-log.XXXXXX")
    node_start_background "$server" "$iperf_pidfile" "$iperf_logfile" iperf3 -s -p "$upstream_port"
    track_process "$server" "$iperf_pidfile"
    if wait_for_port "$server" "$upstream_port" 15; then
        return 0
    fi
    error "iperf3 server did not start listening on :$upstream_port ($server)"
    return 1
}

stop_iperf_server() {
    [ -n "${iperf_pidfile:-}" ] || return 0
    node_stop_background "$server" "$iperf_pidfile" || true
    node_wait_stopped "$server" "$iperf_pidfile" 10 || node_kill_force "$server" "$iperf_pidfile" || true
    node_fetch "$server" "$iperf_logfile" "$RUN_DIR/iperf3-server.log" 2>/dev/null || true
}

start_curtsy() {
    local cfg="$probe_config"
    if node_is_remote "$proxy"; then
        curtsy_cfg_remote=$(node_run "$proxy" "mktemp /tmp/curtsy-bench.XXXXXX.yaml")
        scp -q -o BatchMode=yes "$cfg" "$proxy:$curtsy_cfg_remote"
        cfg="$curtsy_cfg_remote"
    fi
    curtsy_pidfile=$(node_run "$proxy" "mktemp /tmp/curtsy-pid.XXXXXX")
    curtsy_logfile=$(node_run "$proxy" "mktemp /tmp/curtsy-log.XXXXXX")
    node_start_background "$proxy" "$curtsy_pidfile" "$curtsy_logfile" "$curtsy_binary" --config "$cfg"
    track_process "$proxy" "$curtsy_pidfile"
    if wait_for_port "$proxy" "$listen_port" 20; then
        return 0
    fi
    error "curtsy did not start listening on :$listen_port ($proxy); see $curtsy_logfile"
    return 1
}

stop_curtsy() {
    [ -n "${curtsy_pidfile:-}" ] || return 0
    node_stop_background "$proxy" "$curtsy_pidfile" || true
    node_wait_stopped "$proxy" "$curtsy_pidfile" 30 || {
        warn "curtsy did not exit within 30s; sending SIGKILL"
        node_kill_force "$proxy" "$curtsy_pidfile" || true
    }
    node_fetch "$proxy" "$curtsy_logfile" "$RUN_DIR/curtsy.stderr.log" 2>/dev/null || true
}

run_one_iperf() { # proto point direction target run_dir
    local proto="$1" pt="$2" dir="$3" target="$4" run_dir="$5"
    local tmpdir a args=()
    tmpdir=$(node_run "$client" "mktemp -d /tmp/iperf3-cli.XXXXXX")
    args=(-c "$target" -p "$upstream_port")
    if [ "$proto" = udp ]; then
        args+=(-u -b "$bandwidth" -l "$pt" -t "$duration" -w "$udp_sockbuf")
    else
        args+=(-t "$duration" -P "$pt")
    fi
    [ "$dir" = reverse ] && args+=(-R)
    args+=(--json)
    local cmd="iperf3"
    for a in "${args[@]}"; do
        cmd="$cmd '$(printf '%s' "$a" | sed "s/'/'\\\\''/g")'"
    done
    cmd="$cmd >'$tmpdir/out.json' 2>'$tmpdir/err.log'; echo \$? >'$tmpdir/rc'"
    debug "iperf3 client: $cmd"
    node_run "$client" "$cmd" || true
    local rc
    rc=$(node_run "$client" "cat '$tmpdir/rc' 2>/dev/null | tr -d '[:space:]'" 2>/dev/null || true)
    [ -n "$rc" ] || rc=unknown
    node_fetch "$client" "$tmpdir/out.json" "$run_dir/iperf3-$dir.json" 2>/dev/null || true
    node_fetch "$client" "$tmpdir/err.log" "$run_dir/iperf3-$dir.stderr.log" 2>/dev/null || true
    node_run "$client" "rm -rf '$tmpdir'" || true
    if [ "$rc" != "0" ]; then
        warn "iperf3 client rc=$rc for $proto/$dir point=$pt (see $(basename "$run_dir")/iperf3-$dir.stderr.log)"
    fi
}

# --- Curtsy CPU accounting --------------------------------------------------
# Curtsy's process-wide CPU time (all threads) is read from /proc/<pid>/stat
# on the proxy node just after start and just before stop of a proxied run.
# The delta in clock ticks is converted to seconds via CLK_TCK and recorded in
# the run's meta.json; summarize.sh turns it into cpu_per_gbit. Direct runs
# have no Curtsy process and leave the fields at 0.

clk_tck=""

node_clock_ticks() { # echoes CLK_TCK (default 100)
    if [ -z "$clk_tck" ]; then
        clk_tck=$(node_run "$proxy" "getconf CLK_TCK 2>/dev/null || echo 100" 2>/dev/null || echo 100)
    fi
    printf '%s\n' "$clk_tck"
}

curtsy_cpu_total_ticks() { # echoes process-wide utime+stime ticks, or 0
    node_run "$proxy" "pid=\$(cat '$curtsy_pidfile' 2>/dev/null || true); [ -n \"\$pid\" ] && awk '{print \$14+\$15}' /proc/\$pid/stat 2>/dev/null || true" 2>/dev/null || echo 0
}

curtsy_cpu_seconds() { # start_ticks end_ticks ; echoes elapsed CPU seconds
    local start="${1:-0}" end="${2:-0}" tck
    tck=$(node_clock_ticks)
    [ -n "$start" ] || start=0
    [ -n "$end" ] || end=0
    awk -v a="$start" -v b="$end" -v c="$tck" 'BEGIN{ if (c > 0) printf "%.6f", (b - a) / c; else printf "0" }'
}

write_run_meta() { # run_dir run_id proto mode pt target
    local run_dir="$1" run_id="$2" proto="$3" mode="$4" pt="$5" target="$6"
    local cfg_line=""
    [ "$mode" = curtsy ] && cfg_line="$probe_config"
    jq -n \
        --arg run_id "$run_id" \
        --arg session "$session" \
        --arg protocol "$proto" \
        --arg mode "$mode" \
        --arg point "$(point_slug "$proto" "$pt")" \
        --argjson point_value "$pt" \
        --arg label "$label" \
        --arg target "$target" \
        --arg client "$client" --arg proxy "$proxy" --arg server "$server" \
        --arg client_host "$CLIENT_HOST" --arg proxy_host "$PROXY_HOST" --arg server_host "$SERVER_HOST" \
        --arg config "$cfg_line" \
        --arg iperf_version "$IPERF_VERSION" \
        --arg mtu "$mtu" --arg bandwidth "$bandwidth" --arg acceleration "$acceleration" \
        --arg started_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{run_id:$run_id, session:$session, protocol:$protocol, mode:$mode, point:$point,
          point_value:$point_value, label:$label, target:$target,
          client:{spec:$client, host:$client_host}, proxy:{spec:$proxy, host:$proxy_host},
          server:{spec:$server, host:$server_host}, config:$config,
          iperf_version:$iperf_version, mtu:$mtu, bandwidth:$bandwidth,
          acceleration:$acceleration, started_at:$started_at}' >"$run_dir/meta.json"
}

execute_run() { # run_id proto mode pt target
    local run_id="$1" proto="$2" mode="$3" pt="$4" target="$5"
    local run_dir="$session_dir/$run_id"
    RUN_DIR="$run_dir"
    mkdir -p "$run_dir/env/before" "$run_dir/env/after"

    write_run_meta "$run_dir" "$run_id" "$proto" "$mode" "$pt" "$target"
    if [ "$mode" = curtsy ]; then
        cp "$probe_config" "$run_dir/curtsy-config.yaml"
    fi
    collect_env_on_node "$proxy" "$run_dir/env/before" ||
        warn "per-run environment collection on $proxy failed"

    if [ "$mode" = direct ]; then
        start_iperf_server || die "$EXIT_RUNTIME" "failed to start iperf3 server on $server"
    else
        start_iperf_server || die "$EXIT_RUNTIME" "failed to start iperf3 server on $server"
        start_curtsy || die "$EXIT_RUNTIME" "failed to start curtsy on $proxy"
    fi

    local cpu_start="" cpu_end="" cpu_seconds=0 test_seconds
    test_seconds=$((duration * ${#directions[@]}))
    if [ "$mode" = curtsy ]; then
        cpu_start=$(curtsy_cpu_total_ticks)
    fi

    local dir
    for dir in "${directions[@]}"; do
        info "  running $mode $proto point=$(point_slug "$proto" "$pt") direction=$dir"
        run_one_iperf "$proto" "$pt" "$dir" "$target" "$run_dir"
    done

    if [ "$mode" = curtsy ]; then
        cpu_end=$(curtsy_cpu_total_ticks)
        cpu_seconds=$(curtsy_cpu_seconds "$cpu_start" "$cpu_end")
    fi

    collect_env_on_node "$proxy" "$run_dir/env/after" ||
        warn "per-run environment collection on $proxy failed"

    if [ "$mode" = direct ]; then
        stop_iperf_server
    else
        stop_curtsy
        stop_iperf_server
    fi
    jq --argjson cpu_seconds "$cpu_seconds" --argjson test_seconds "$test_seconds" \
        --arg finished_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '. + {finished_at: $finished_at, cpu_seconds: $cpu_seconds, test_seconds: $test_seconds}' \
        "$run_dir/meta.json" \
        >"$run_dir/meta.json.tmp" && mv "$run_dir/meta.json.tmp" "$run_dir/meta.json"
}

run_all_tests() {
    local seq=0 proto pt mode dir target run_id
    for proto in "${protos[@]}"; do
        if [ "$proto" = tcp ]; then pts=("${tcp_profile[@]}"); else pts=("${udp_profile[@]}"); fi
        for pt in "${pts[@]}"; do
            for mode in direct curtsy; do
                seq=$((seq + 1))
                if [ "$mode" = direct ]; then target="$direct_target"; else target="$proxy_target"; fi
                run_id=$(generate_run_id "$seq" "$proto" "$mode" "$(point_slug "$proto" "$pt")")
                info "run $run_id: $proto/$mode point=$(point_slug "$proto" "$pt") target=$target"
                execute_run "$run_id" "$proto" "$mode" "$pt" "$target"
            done
        done
    done
}

write_session_meta() {
    local cmdline
    cmdline=$(printf '%q ' "${argv[@]}")
    jq -n \
        --arg session "$session" \
        --arg mode "$mode" \
        --arg label "$label" \
        --arg started_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg hostname "$(hostname)" \
        --arg kernel "$(uname -r)" \
        --arg cmdline "$cmdline" \
        --arg output_dir "$output_dir" \
        '{session:$session, mode:$mode, label:$label, started_at:$started_at,
          hostname:$hostname, kernel:$kernel, cmdline:$cmdline, output_dir:$output_dir}' \
        >"$session_dir/session-meta.json"
}

do_check() {
    info "check mode: validating environment and writing the plan (no benchmarks executed)"
    collect_env_session before
    check_ports check
    check_link_speed check
    check_sysctl_recommendations
    check_mtu
    build_tests_plan
    write_plan check
    print_check_report
}

do_run() {
    info "run mode: starting benchmark session $session"
    collect_env_session before
    check_ports run
    check_link_speed run
    build_tests_plan
    write_plan run
    run_all_tests
    collect_env_session after
    info "aggregating results"
    "$SUMMARIZE_SCRIPT" "$session_dir" "$session_dir/summary.json" "$session_dir/report.txt"
    info "session complete: $session_dir"
    cat "$session_dir/report.txt"
}

do_recommend() {
    info "recommend mode: read-only system tuning recommendations (nothing is modified)"
    local node dest remote_tmp
    local -A seen=()
    for node in "$client" "$proxy" "$server"; do
        if [ -n "${seen[$node]:-}" ]; then
            continue
        fi
        seen[$node]=1
        dest="$session_dir/recommend-$(node_dirname "$node")"
        mkdir -p "$dest"
        info "collecting system recommendations on $node"
        if node_is_remote "$node"; then
            remote_tmp=$(node_run "$node" "mktemp -d /tmp/curtsy-rec.XXXXXX")
            scp -q -o BatchMode=yes "$RECOMMEND_SCRIPT" "$node:$remote_tmp/recommend-system.sh"
            if node_run "$node" "bash '$remote_tmp/recommend-system.sh' --json '$remote_tmp/findings.json' --text '$remote_tmp/findings.txt' --host '$node' --target-speed '$link_speed' --target-mtu '$mtu'"; then
                scp -q -o BatchMode=yes "$node:$remote_tmp/findings.json" "$dest/findings.json"
                scp -q -o BatchMode=yes "$node:$remote_tmp/findings.txt" "$dest/findings.txt"
                cat "$dest/findings.txt"
            else
                warn "recommendation run failed on $node (is jq installed there?)"
            fi
            node_run "$node" "rm -rf '$remote_tmp'" 2>/dev/null || true
        else
            if bash "$RECOMMEND_SCRIPT" --json "$dest/findings.json" --text "$dest/findings.txt" --host "$node" --target-speed "$link_speed" --target-mtu "$mtu"; then
                cat "$dest/findings.txt"
            else
                warn "recommendation run failed locally (is jq installed?)"
            fi
        fi
    done
    info "recommendations written under $session_dir (recommend-<node>/findings.json); nothing was modified"
}

main() {
    argv=("$@")
    parse_args "$@"
    validate_args
    load_profiles
    setup
    write_session_meta
    if [ "$mode" = check ]; then
        do_check
    elif [ "$mode" = recommend ]; then
        do_recommend
    else
        do_run
    fi
}

main "$@"
