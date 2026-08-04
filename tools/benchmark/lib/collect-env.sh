#!/usr/bin/env bash
#
# collect-env.sh - capture a snapshot of environment, NIC, interrupt/softirq
# and system counters into a directory. Run on the target node either directly
# or through the harness (which copies it to remote nodes).
#
# Usage: collect-env.sh <output-dir>
#        collect-env.sh --help
#
# Optional tools degrade to an "unavailable:" marker in the affected file;
# the harness never fails a run because of a missing optional tool.

set -eu -o pipefail

usage() {
    cat <<'EOF'
Usage: collect-env.sh <output-dir>

Captures a snapshot of environment, NIC, interrupt/softirq and system counters
into <output-dir> (created if missing). Only bash, ip and the /proc filesystem
are assumed; optional tools (lscpu, ethtool, numactl, ss, sysctl) degrade to
"unavailable:" markers when missing.

Files written:
  meta.txt        snapshot time, hostname, uname, os-release
  cpu.txt         lscpu output (when lscpu is present)
  meminfo.txt     /proc/meminfo
  nics.txt        `ip link show` / `ip addr show` text
  link_speed.txt  "<iface> <speed-mbps|unknown>" per NIC (from ethtool)
  ethtool.txt     per-NIC `ethtool`, `ethtool -i`, `ethtool -S` text
  interrupts.txt  /proc/interrupts
  softirqs.txt    /proc/softirqs
  netdev.txt      /proc/net/dev (per-interface rx/tx bytes, errors)
  netstat.txt     /proc/net/netstat (incl. listen queue overflow counters)
  snmp.txt        /proc/net/snmp
  sockstat.txt    `ss -s` (when ss is present)
  route.txt       `ip route show` (when ip is present)
  sysctl.txt      relevant net.* sysctls (when sysctl is present)
  numa.txt        `numactl --hardware` (when numactl is present)
  nproc.txt       CPU count and model
EOF
}

if [ "$#" -ne 1 ]; then
    usage >&2
    exit 2
fi
case "$1" in
    --help | -h | help)
        usage
        exit 0
        ;;
esac

dest="$1"
mkdir -p "$dest"

snap() { # file command...
    local file="$1"
    shift
    if "$@" >"$dest/$file" 2>/dev/null; then
        :
    else
        echo "unavailable: $*" >"$dest/$file"
    fi
}

snap_proc() { # file /proc/path
    local file="$1" src="$2"
    if [ -r "$src" ]; then
        # -f so a previously collected read-only copy (e.g. /proc files are
        # mode 400) can be overwritten on repeat collections.
        cp -f "$src" "$dest/$file"
    else
        echo "unavailable: $src" >"$dest/$file"
    fi
}

# --- meta ------------------------------------------------------------------
{
    echo "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "hostname=$(hostname 2>/dev/null || echo unknown)"
    uname -a 2>/dev/null || true
    if [ -r /etc/os-release ]; then
        grep -E '^(NAME|VERSION|ID)=' /etc/os-release || true
    fi
} >"$dest/meta.txt"

# --- cpu / memory ----------------------------------------------------------
if command -v lscpu >/dev/null 2>&1; then
    snap cpu.txt lscpu
else
    echo "unavailable: lscpu" >"$dest/cpu.txt"
fi
snap_proc meminfo.txt /proc/meminfo
{
    echo "nproc=$(nproc 2>/dev/null || echo unknown)"
    if [ -r /proc/cpuinfo ]; then
        grep -m 1 -E '^(model name|vendor_id|cpu family|model)\s*:' /proc/cpuinfo || true
    fi
} >"$dest/nproc.txt"

# --- nics ------------------------------------------------------------------
get_ifaces() {
    if command -v ip >/dev/null 2>&1; then
        ip -j link show 2>/dev/null | jq -r '.[].ifname' 2>/dev/null ||
            ip link show 2>/dev/null | awk '/^[0-9]+:/{n=$2; gsub(":","",n); print n}'
    fi
}

if command -v ip >/dev/null 2>&1; then
    snap nics.txt ip link show
    ip addr show >>"$dest/nics.txt" 2>/dev/null || true
else
    echo "unavailable: ip" >"$dest/nics.txt"
fi

# Per-NIC link speed, one line per interface: "<iface> <speed-mbps|unknown>".
: >"$dest/link_speed.txt"
if command -v ethtool >/dev/null 2>&1; then
    ifaces=$(get_ifaces)
    for iface in $ifaces; do
        speed=$(ethtool "$iface" 2>/dev/null | awk '/Speed:/{print $2}' | head -n 1)
        case "$speed" in
            *Mb/s) speed=${speed%Mb/s} ;;
            *) speed=unknown ;;
        esac
        echo "$iface ${speed:-unknown}" >>"$dest/link_speed.txt"
    done
fi
if [ ! -s "$dest/link_speed.txt" ]; then
    echo "unavailable: ethtool" >"$dest/link_speed.txt"
fi

# Full ethtool detail per NIC.
: >"$dest/ethtool.txt"
if command -v ethtool >/dev/null 2>&1; then
    ifaces=$(get_ifaces)
    for iface in $ifaces; do
        {
            echo "==== $iface ===="
            ethtool "$iface" 2>&1 || true
            echo "---- ethtool -i $iface ----"
            ethtool -i "$iface" 2>&1 || true
            echo "---- ethtool -S $iface ----"
            ethtool -S "$iface" 2>&1 || true
        } >>"$dest/ethtool.txt"
    done
fi

if command -v ip >/dev/null 2>&1; then
    snap route.txt ip route show
else
    echo "unavailable: ip" >"$dest/route.txt"
fi

# --- interrupts / softirqs / net counters ----------------------------------
snap_proc interrupts.txt /proc/interrupts
snap_proc softirqs.txt /proc/softirqs
snap_proc netdev.txt /proc/net/dev
snap_proc netstat.txt /proc/net/netstat
snap_proc snmp.txt /proc/net/snmp

if command -v ss >/dev/null 2>&1; then
    snap sockstat.txt ss -s
else
    echo "unavailable: ss" >"$dest/sockstat.txt"
fi

# --- sysctl ----------------------------------------------------------------
: >"$dest/sysctl.txt"
if command -v sysctl >/dev/null 2>&1; then
    sysctl -e \
        net.core.rmem_max net.core.wmem_max \
        net.core.rmem_default net.core.wmem_default \
        net.core.somaxconn net.core.netdev_max_backlog \
        net.core.busy_read net.core.busy_poll \
        net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.ipv4.tcp_mem \
        net.ipv4.udp_rmem_min net.ipv4.udp_wmem_min \
        net.ipv4.ip_local_port_range \
        >"$dest/sysctl.txt" 2>/dev/null || true
fi

if command -v numactl >/dev/null 2>&1; then
    snap numa.txt numactl --hardware
else
    echo "unavailable: numactl" >"$dest/numa.txt"
fi

exit 0
