#!/usr/bin/env bash
#
# recommend-system.sh - read-only system recommendation tool for the
# Curtsy 25 Gbps benchmark harness (tools/benchmark).
#
# Inspects NIC speed/driver/queues, MTU/offloads, NUMA locality, RSS/RPS/XPS,
# IRQ affinities, CPU governor and socket/ring limits, then emits a
# machine-readable findings report (JSON) plus explicit suggested commands.
#
# This tool NEVER modifies system state. Every recommended command is printed
# for the operator to run manually; nothing is executed, piped to a privileged
# shell, or written outside the report files given on the command line. It uses
# only read-only queries: ethtool (info, -i, -l, -g, -k), ip link show and
# reads under /proc and /sys.
#
# Usage:
#   recommend-system.sh [--json <file>] [--text <file>] \
#       [--target-speed <g>] [--target-mtu <bytes>] [--cpus <n>] \
#       [--host <label>] [--filter-iface <name>]
#   recommend-system.sh --help
#
# Exit codes: 0 ok (findings are advisory), 2 usage error, 3 jq missing.
#
# Test hooks (never set in production):
#   CURTSY_RECOMMEND_SYS_ROOT  base directory for a fake /sys + /proc tree
#   CURTSY_RECOMMEND_ETHTOOL   ethtool binary (default: ethtool)
#   CURTSY_RECOMMEND_IP        ip binary (default: ip)

set -eu -o pipefail

TOOL_VERSION="1.0.0"

# --- configuration ----------------------------------------------------------
SYS_ROOT="${CURTSY_RECOMMEND_SYS_ROOT:-/}"
ETHTOOL_CMD="${CURTSY_RECOMMEND_ETHTOOL:-ethtool}"
IP_CMD="${CURTSY_RECOMMEND_IP:-ip}"

json_file=""
text_file=""
target_speed_g=25
target_mtu=""
cpus=""
host_label=""
filter_iface=""

usage() {
    cat <<'EOF'
Usage: recommend-system.sh [options]

Read-only system recommendation tool. Inspects NIC speed/driver/queues,
MTU/offloads, NUMA locality, RSS/RPS/XPS, IRQ affinities, CPU governor and
socket/ring limits, then emits machine-readable findings plus explicit
suggested commands. It NEVER executes any mutating command.

Options:
  --json <file>        Write the machine-readable findings report (JSON).
  --text <file>        Write the human-readable report (default: stdout).
  --target-speed <g>   Link speed to plan for, Gbps.        [25]
  --target-mtu <bytes> Target MTU; mismatches are flagged.  [none]
  --cpus <n>           CPU count (default: nproc).
  --host <label>       Node label recorded in the report.   [hostname]
  --filter-iface <n>   Inspect only this interface.
  -h, --help           Print this help and exit.

Exit codes: 0 ok (findings are advisory), 2 usage error, 3 jq missing.
EOF
}

# --- argument parsing -------------------------------------------------------
while [ "$#" -gt 0 ]; do
    case "$1" in
        --help | -h) usage; exit 0 ;;
        --json) json_file=${2:?missing value for --json}; shift 2 ;;
        --text) text_file=${2:?missing value for --text}; shift 2 ;;
        --target-speed) target_speed_g=${2:?missing value for --target-speed}; shift 2 ;;
        --target-mtu) target_mtu=${2:?missing value for --target-mtu}; shift 2 ;;
        --cpus) cpus=${2:?missing value for --cpus}; shift 2 ;;
        --host) host_label=${2:?missing value for --host}; shift 2 ;;
        --filter-iface) filter_iface=${2:?missing value for --filter-iface}; shift 2 ;;
        *) echo "recommend-system: unexpected argument: $1 (see --help)" >&2; exit 2 ;;
    esac
done

is_num() { case "$1" in '' | *[!0-9]*) return 1 ;; *) return 0 ;; esac; }

is_num "$target_speed_g" || { echo "recommend-system: --target-speed must be an integer" >&2; exit 2; }
if [ -n "$target_mtu" ]; then is_num "$target_mtu" || { echo "recommend-system: --target-mtu must be an integer" >&2; exit 2; }; fi
if [ -n "$cpus" ]; then is_num "$cpus" || { echo "recommend-system: --cpus must be an integer" >&2; exit 2; }; fi

command -v jq >/dev/null 2>&1 || { echo "recommend-system: jq is required" >&2; exit 3; }

if [ -z "$host_label" ]; then host_label=$(hostname 2>/dev/null || echo unknown); fi
if [ -z "$cpus" ]; then cpus=$(nproc 2>/dev/null || echo 1); fi
target_mbps=$((target_speed_g * 1000))

# --- helpers ----------------------------------------------------------------
sys_path() { printf '%s/%s\n' "${SYS_ROOT%/}" "$1"; }

read_sys() {
    local p
    p=$(sys_path "$1")
    if [ -r "$p" ]; then cat "$p" 2>/dev/null || true; fi
}

sysctl_val() { # dotted.name
    local key="$1"
    read_sys "proc/sys/${key//./\/}" | head -n1
}

hex_popcount() { # "mask" possibly "aa,bb" -> number of set bits
    local all="$1" digits d n=0
    digits=$(printf '%s' "$all" | tr -cd '0-9a-fA-F')
    while [ -n "$digits" ]; do
        d=${digits:0:1}
        case "$d" in
            1 | 2 | 4 | 8) n=$((n + 1)) ;;
            3 | 5 | 6 | 9 | a | A) n=$((n + 2)) ;;
            7 | b | B | d | D | e | E) n=$((n + 3)) ;;
            f | F) n=$((n + 4)) ;;
        esac
        digits=${digits:1}
    done
    printf '%d' "$n"
}

full_cpu_mask() { # ncpus -> hex mask covering all cpus
    local ncpus="$1" nibbles s=""
    nibbles=$(((ncpus + 3) / 4))
    while [ "$nibbles" -gt 0 ]; do s="f$s"; nibbles=$((nibbles - 1)); done
    printf '%s' "$s"
}

# --- finding / report plumbing ----------------------------------------------
tmpdir=$(mktemp -d /tmp/curtsy-recommend.XXXXXX)
trap 'rm -rf "$tmpdir"' EXIT
findings_jsonl="$tmpdir/findings.jsonl"
nics_jsonl="$tmpdir/nics.jsonl"
: >"$findings_jsonl"
: >"$nics_jsonl"

rec_finding() { # severity category detail [command]
    local severity="$1" category="$2" detail="$3" command="${4:-}"
    jq -cn \
        --arg severity "$severity" --arg category "$category" \
        --arg node "$host_label" --arg detail "$detail" --arg command "$command" \
        '{severity: $severity, category: $category, node: $node,
          detail: $detail, command: $command}' >>"$findings_jsonl"
}

# --- global checks ----------------------------------------------------------
governor=""
rmem_max=""
wmem_max=""
somaxconn=""
backlog=""

governor=$(read_sys "sys/devices/system/cpu/cpu0/cpufreq/scaling_governor" | head -n1)
if [ -n "$governor" ]; then
    if [ "$governor" != "performance" ]; then
        rec_finding warn governor "CPU governor is '$governor' (not performance)" \
            "sudo cpupower frequency-set -g performance   # or: echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"
    else
        rec_finding ok governor "CPU governor is performance"
    fi
else
    rec_finding info governor "CPU governor not readable (no cpufreq / virtual CPU)"
fi

rmem_max=$(sysctl_val net.core.rmem_max)
wmem_max=$(sysctl_val net.core.wmem_max)
somaxconn=$(sysctl_val net.core.somaxconn)
backlog=$(sysctl_val net.core.netdev_max_backlog)

if is_num "$rmem_max"; then
    if [ "$rmem_max" -lt 8388608 ]; then
        rec_finding warn socket "net.core.rmem_max=$rmem_max < 8MiB" \
            "sudo sysctl -w net.core.rmem_max=8388608"
    else
        rec_finding ok socket "net.core.rmem_max=$rmem_max"
    fi
else
    rec_finding info socket "net.core.rmem_max not readable"
fi

if is_num "$wmem_max"; then
    if [ "$wmem_max" -lt 8388608 ]; then
        rec_finding warn socket "net.core.wmem_max=$wmem_max < 8MiB" \
            "sudo sysctl -w net.core.wmem_max=8388608"
    else
        rec_finding ok socket "net.core.wmem_max=$wmem_max"
    fi
else
    rec_finding info socket "net.core.wmem_max not readable"
fi

if is_num "$somaxconn"; then
    if [ "$somaxconn" -lt 4096 ]; then
        rec_finding warn socket "net.core.somaxconn=$somaxconn < 4096" \
            "sudo sysctl -w net.core.somaxconn=4096"
    else
        rec_finding ok socket "net.core.somaxconn=$somaxconn"
    fi
else
    rec_finding info socket "net.core.somaxconn not readable"
fi

if is_num "$backlog"; then
    if [ "$backlog" -lt 4096 ]; then
        rec_finding warn socket "net.core.netdev_max_backlog=$backlog < 4096 (high pps)" \
            "sudo sysctl -w net.core.netdev_max_backlog=65536"
    else
        rec_finding ok socket "net.core.netdev_max_backlog=$backlog"
    fi
else
    rec_finding info socket "net.core.netdev_max_backlog not readable"
fi

# --- ethtool helpers --------------------------------------------------------
ethtool_available=0
if command -v "$ETHTOOL_CMD" >/dev/null 2>&1; then
    ethtool_available=1
else
    rec_finding info nic "ethtool unavailable: link speed/driver/rings/offloads not inspected" ""
fi

ethtool_speed() { # iface ; echoes Mbps or "unknown"
    local out speed
    out=$("$ETHTOOL_CMD" "$1" 2>/dev/null) || { echo unknown; return; }
    speed=$(printf '%s\n' "$out" | awk -F: '/Speed:/{gsub(/[^0-9]/, "", $2); print $2; exit}')
    if [ -n "${speed:-}" ]; then echo "$speed"; else echo unknown; fi
}

ethtool_driver() { # iface ; echoes driver or "unknown"
    local out d
    out=$("$ETHTOOL_CMD" -i "$1" 2>/dev/null) || { echo unknown; return; }
    d=$(printf '%s\n' "$out" | awk -F: '/driver:/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}')
    echo "${d:-unknown}"
}

ethtool_combined() { # iface ; echoes Combined queue count from ethtool -l or 0
    local out c
    out=$("$ETHTOOL_CMD" -l "$1" 2>/dev/null) || { echo 0; return; }
    c=$(printf '%s\n' "$out" | awk '/^Combined:/{c=$2} END{print c+0}')
    echo "$c"
}

ethtool_ring() { # iface ; echoes "rx tx" or "0 0"
    local out r t
    out=$("$ETHTOOL_CMD" -g "$1" 2>/dev/null) || { echo "0 0"; return; }
    r=$(printf '%s\n' "$out" | awk '/^RX:/{r=$2} END{print r+0}')
    t=$(printf '%s\n' "$out" | awk '/^TX:/{t=$2} END{print t+0}')
    echo "$r $t"
}

ethtool_feature() { # iface feature ; echoes on/off or "unknown"
    local v
    v=$("$ETHTOOL_CMD" -k "$1" 2>/dev/null | awk -v f="$2" -F: '$1 ~ ("^[ \t]*" f "$"){gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}')
    echo "${v:-unknown}"
}

nic_irqs() { # iface driver ; echoes "<irq> <affinity-mask>" per matching line
    local f
    f=$(sys_path proc/interrupts)
    [ -r "$f" ] || return 0
    local i d irq aff
    i="$1"; d="$2"
    while read -r irq; do
        irq=${irq%:}
        case "$irq" in '' | *[!0-9]*) continue ;; esac
        aff=$(read_sys "proc/irq/$irq/smp_affinity" | head -n1)
        printf '%s %s\n' "$irq" "${aff:-0}"
    done < <(awk -v i="$i" -v d="$d" 'NR>1 && ($NF ~ i || $NF ~ d) { print $1 }' "$f")
}

# --- per-interface inspection ----------------------------------------------
list_ifaces() {
    local devf
    devf=$(sys_path proc/net/dev)
    if [ -r "$devf" ]; then
        awk 'NR>2 { iface=$1; sub(":", "", iface); if (iface != "lo") print iface }' "$devf"
    else
        "$IP_CMD" -o link show 2>/dev/null | awk -F': ' '$1 !~ /^[[:space:]]*$/ && $2 != "lo" { print $2 }' || true
    fi
}

inspect_iface() {
    local iface="$1"
    local sdir qbase
    local mtu="" numa_node="" speed="unknown" driver="unknown" combined=0
    local rx_ring=0 tx_ring=0
    local rx_queues=0 tx_queues=0 rps_zero=0 xps_zero=0
    local rx_off="unknown" tx_off="unknown" tso_off="unknown" gro_off="unknown"
    local total=0 distinct=0 masks="" d
    local irq aff

    sdir="sys/class/net/$iface"
    qbase=$(sys_path "$sdir/queues")

    mtu=$(read_sys "$sdir/mtu" | head -n1)
    numa_node=$(read_sys "$sdir/device/numa_node" | head -n1)

    for d in "$qbase"/rx-*; do
        [ -d "$d" ] || continue
        rx_queues=$((rx_queues + 1))
        v=$(cat "$d/rps_cpus" 2>/dev/null | tr -d '[:space:]' || true)
        [ "$v" = "0" ] && rps_zero=$((rps_zero + 1))
    done
    for d in "$qbase"/tx-*; do
        [ -d "$d" ] || continue
        tx_queues=$((tx_queues + 1))
        v=$(cat "$d/xps_cpus" 2>/dev/null | tr -d '[:space:]' || true)
        [ "$v" = "0" ] && xps_zero=$((xps_zero + 1))
    done

    if [ "$ethtool_available" = 1 ]; then
        speed=$(ethtool_speed "$iface")
        driver=$(ethtool_driver "$iface")
        combined=$(ethtool_combined "$iface")
        read -r rx_ring tx_ring < <(ethtool_ring "$iface") || true
        rx_off=$(ethtool_feature "$iface" rx-checksumming)
        tx_off=$(ethtool_feature "$iface" tx-checksumming)
        tso_off=$(ethtool_feature "$iface" tcp-segmentation-offload)
        gro_off=$(ethtool_feature "$iface" generic-receive-offload)
    fi

    # --- findings ----------------------------------------------------------
    if is_num "$speed"; then
        if [ "$speed" -lt "$target_mbps" ]; then
            rec_finding warn nic "$iface link speed $speed Mb/s < target ${target_speed_g}Gbps" ""
        else
            rec_finding ok nic "$iface link speed $speed Mb/s >= target ${target_speed_g}Gbps"
        fi
    else
        rec_finding info nic "$iface link speed unknown"
    fi

    case "$driver" in
        unknown) : ;;
        vfio-pci | virtio | virtio_net | e1000 | e1000e | loopback)
            rec_finding warn nic "$iface driver '$driver' is not a high-performance 25G driver" "" ;;
        *) rec_finding info nic "$iface driver $driver" ;;
    esac

    if [ "$rx_queues" -gt 0 ]; then
        if [ "$rx_queues" -lt "$cpus" ] && [ "$cpus" -gt 1 ]; then
            rec_finding warn rss "$iface has $rx_queues RX queue(s) < $cpus CPU(s)" \
                "sudo ethtool -L $iface combined $cpus   # spread RX/TX queues across CPUs"
        else
            rec_finding ok rss "$iface $rx_queues RX queue(s)"
        fi
    fi

    if [ -n "$target_mtu" ] && [ -n "$mtu" ] && is_num "$mtu" && [ "$mtu" != "$target_mtu" ]; then
        rec_finding warn mtu "$iface MTU $mtu != target $target_mtu" \
            "sudo ip link set $iface mtu $target_mtu"
    elif [ -n "$mtu" ]; then
        rec_finding info mtu "$iface MTU $mtu"
    fi

    if [ -n "$numa_node" ] && is_num "$numa_node" && [ "$numa_node" -ge 0 ]; then
        rec_finding info numa "$iface NUMA node $numa_node" \
            "run Curtsy/iperf3 pinned to the same node: numactl --cpunodebind=$numa_node --membind=$numa_node <command>"
    else
        rec_finding info numa "$iface NUMA locality unknown"
    fi

    if [ "$rx_queues" -gt 0 ] && [ "$cpus" -gt 1 ]; then
        if [ "$rps_zero" -gt 0 ]; then
            mask=$(full_cpu_mask "$cpus")
            rec_finding warn rps "$iface: $rps_zero/$rx_queues RX queue(s) have RPS disabled (rps_cpus=0)" \
                "for q in /sys/class/net/$iface/queues/rx-*/rps_cpus; do echo $mask | sudo tee \$q; done"
        else
            rec_finding ok rps "$iface RPS configured on all RX queues"
        fi
    fi

    if [ "$tx_queues" -gt 0 ] && [ "$cpus" -gt 1 ]; then
        if [ "$xps_zero" -gt 0 ]; then
            mask=$(full_cpu_mask "$cpus")
            rec_finding warn xps "$iface: $xps_zero/$tx_queues TX queue(s) have XPS disabled (xps_cpus=0)" \
                "for q in /sys/class/net/$iface/queues/tx-*/xps_cpus; do echo $mask | sudo tee \$q; done"
        else
            rec_finding ok xps "$iface XPS configured on all TX queues"
        fi
    fi

    if [ "$ethtool_available" = 1 ]; then
        for pair in "rx-checksumming:$rx_off" "tx-checksumming:$tx_off" \
            "tcp-segmentation-offload:$tso_off" "generic-receive-offload:$gro_off"; do
            name=${pair%%:*}
            val=${pair#*:}
            if [ "$val" = "off" ]; then
                rec_finding warn offload "$iface $name is off" "sudo ethtool -K $iface $name on"
            fi
        done
        if is_num "$rx_ring" && [ "$rx_ring" -gt 0 ] && [ "$rx_ring" -lt 1024 ]; then
            rec_finding warn ring "$iface RX ring $rx_ring < 1024" "sudo ethtool -G $iface rx 4096 tx 4096"
        elif is_num "$rx_ring" && [ "$rx_ring" -gt 0 ]; then
            rec_finding ok ring "$iface RX ring $rx_ring"
        fi
        if is_num "$tx_ring" && [ "$tx_ring" -gt 0 ] && [ "$tx_ring" -lt 1024 ]; then
            rec_finding warn ring "$iface TX ring $tx_ring < 1024" "sudo ethtool -G $iface rx 4096 tx 4096"
        elif is_num "$tx_ring" && [ "$tx_ring" -gt 0 ]; then
            rec_finding ok ring "$iface TX ring $tx_ring"
        fi
    fi

    # IRQ affinity: warn when a NIC's interrupt lines are concentrated on a
    # single CPU mask while multiple CPUs are available.
    while read -r irq aff; do
        total=$((total + 1))
        masks="$masks $aff"
    done < <(nic_irqs "$iface" "$driver")
    if [ "$total" -gt 0 ]; then
        distinct=$(printf '%s\n' $masks | sed '/^[[:space:]]*$/d' | sort -u | wc -l)
        if [ "$total" -gt 1 ] && [ "$cpus" -gt 1 ] && [ "$distinct" -le 1 ]; then
            rec_finding warn irq "$iface: $total NIC IRQ(s) share a single affinity mask (concentrated on one CPU)" \
                "sudo systemctl enable --now irqbalance   # or spread manually, e.g. echo <mask> | sudo tee /proc/irq/<irq>/smp_affinity"
        else
            rec_finding ok irq "$iface IRQ affinity spread over $total IRQ(s), $distinct distinct mask(s)"
        fi
    fi

    # --- machine-readable NIC detail ----------------------------------------
    jq -cn \
        --arg iface "$iface" --arg mtu "${mtu:-}" --arg numa_node "${numa_node:-}" \
        --arg driver "$driver" --arg speed "$speed" \
        --argjson rx_queues "$rx_queues" --argjson tx_queues "$tx_queues" \
        --arg rx_ring "$rx_ring" --arg tx_ring "$tx_ring" \
        --argjson rps_zero "$rps_zero" --argjson xps_zero "$xps_zero" \
        --argjson total "$total" --argjson distinct "$distinct" \
        --arg rx_off "$rx_off" --arg tx_off "$tx_off" --arg tso_off "$tso_off" --arg gro_off "$gro_off" \
        '{iface: $iface,
          mtu: (if $mtu == "" then null else ($mtu | tonumber) end),
          numa_node: (if $numa_node == "" then null else ($numa_node | tonumber) end),
          driver: (if $driver == "unknown" then null else $driver end),
          speed_mbps: (if $speed == "unknown" then null else ($speed | tonumber) end),
          rx_queues: $rx_queues, tx_queues: $tx_queues,
          rx_ring: (if $rx_ring == "0" then null else ($rx_ring | tonumber) end),
          tx_ring: (if $tx_ring == "0" then null else ($tx_ring | tonumber) end),
          rps: {queues_with_zero_mask: $rps_zero, queues: $rx_queues},
          xps: {queues_with_zero_mask: $xps_zero, queues: $tx_queues},
          irq_affinity: {irqs: $total, distinct_masks: $distinct},
          offloads: {rx_checksumming: $rx_off, tx_checksumming: $tx_off,
                     tcp_segmentation_offload: $tso_off, generic_receive_offload: $gro_off}}' \
        >>"$nics_jsonl"
}

for iface in $(list_ifaces); do
    if [ -n "$filter_iface" ] && [ "$iface" != "$filter_iface" ]; then
        continue
    fi
    inspect_iface "$iface"
done

# --- output ----------------------------------------------------------------
render_text() {
    {
        echo "System recommendation report for $host_label"
        echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "cpus=$cpus  target_speed=${target_speed_g}Gbps  target_mtu=${target_mtu:-unset}"
        echo
        echo "Findings:"
        local line sev catg det cmd
        while read -r line; do
            [ -n "$line" ] || continue
            sev=$(printf '%s' "$line" | jq -r '.severity')
            catg=$(printf '%s' "$line" | jq -r '.category')
            det=$(printf '%s' "$line" | jq -r '.detail')
            cmd=$(printf '%s' "$line" | jq -r '.command')
            printf '  [%s] (%s) %s\n' "$sev" "$catg" "$det"
            if [ -n "$cmd" ]; then
                printf '      $ %s\n' "$cmd"
            fi
        done <"$findings_jsonl"
    }
}

if [ -n "$json_file" ]; then
    jq -n \
        --arg tool "recommend-system" \
        --arg version "$TOOL_VERSION" \
        --arg node "$host_label" \
        --arg hostname "$(hostname 2>/dev/null || echo unknown)" \
        --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson cpus "$cpus" \
        --argjson target_speed_g "$target_speed_g" \
        --argjson target_mtu "${target_mtu:-0}" \
        --arg governor "$governor" \
        --argjson rmem_max "${rmem_max:-0}" \
        --argjson wmem_max "${wmem_max:-0}" \
        --argjson somaxconn "${somaxconn:-0}" \
        --argjson backlog "${backlog:-0}" \
        --slurpfile nics "$nics_jsonl" \
        --slurpfile findings "$findings_jsonl" \
        '{tool: $tool, version: $version, node: $node, hostname: $hostname,
          generated_at: $generated_at, cpus: $cpus,
          target: {speed_gbps: $target_speed_g,
                   mtu: (if $target_mtu == 0 then null else $target_mtu end)},
          system: {cpu_governor: (if $governor == "" then null else $governor end),
                   socket_limits: {rmem_max: (if $rmem_max == 0 then null else $rmem_max end),
                                   wmem_max: (if $wmem_max == 0 then null else $wmem_max end),
                                   somaxconn: (if $somaxconn == 0 then null else $somaxconn end),
                                   netdev_max_backlog: (if $backlog == 0 then null else $backlog end)}},
          nics: $nics, findings: $findings,
          commands: ([$findings[].command | select(length > 0)] | unique)}' >"$json_file"
fi

if [ -n "$text_file" ]; then
    render_text >"$text_file"
else
    render_text
fi

warn_count=$(jq -s '[.[] | select(.severity == "warn")] | length' "$findings_jsonl" 2>/dev/null || echo 0)
total_count=$(jq -s 'length' "$findings_jsonl" 2>/dev/null || echo 0)
echo "recommend-system: $total_count finding(s), $warn_count actionable warning(s); nothing was modified"

exit 0
