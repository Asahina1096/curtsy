# Curtsy 性能基准测试（25 Gbps）

本文档描述 `tools/benchmark/` 基准测试工具的用法、结果布局、推荐做法与已知
限制。它用于回答两个问题：

1. Curtsy 在本机/跨机场景下的转发吞吐相比「客户端直连上游」损失多少；
2. 吞吐随 TCP 并发连接数、UDP 报文大小、方向、sockmap 配置如何变化。

除基准本身外，工具链还提供：只读系统推荐（`--recommend` / `lib/recommend-system.sh`，
盘点 NIC/IRQ/NUMA/RPS/RSS/sysctl 并给出建议命令，绝不改系统）与回归门禁
（`tools/benchmark/compare.sh`，对两份 `summary.json` 的吞吐/CPU-per-Gbit/丢包/
重传做阈值判定）。

基准工具只属于 `tools/benchmark/` 与本文档，不修改仓库其他路径，也绝不自动
改动系统设置（sysctl、MTU、IRQ 亲和等一律只打印建议命令）。

## 1. 拓扑模型

三种角色，各自独立可配置节点（`local` 或 `[user@]host`，免密 ssh）：

```
                    direct 基线
   client ────────────────► server (iperf3 -s)
   iperf3 -c                 ▲
                              │ proxied 路径
   client ───────► Curtsy ───┘  (proxy)
   iperf3 -c        listen     upstream
                     :listen   :upstream
```

- **direct**：客户端直接连 iperf3 server，作为基线；
- **curtsy**：客户端连 Curtsy 监听端口，Curtsy 转发到 iperf3 server（上游）。

两个方向都测（`--direction both` 默认）：

- **forward**：客户端发送到服务端（`iperf3` 不带 `-R`）；
- **reverse**：服务端发送到客户端（`iperf3 -R`），同样经过（或不经过）Curtsy。

默认各角色均为 `local`，即整条路径走回环接口，可用于无 25GbE 机器的冒烟/校验。

### 1.1 三节点 25GbE 实测流程

真实 25 Gbps 结论必须在独立节点上复测（回环不代表跨机性能）。推荐三节点：

```
    client               proxy                  server
 (iperf3 -c)          (curtsy 转发)         (iperf3 -s 上游)
     │   ── 25GbE ──► │   ── 25GbE ──► │
     │   ──── direct 基线 ────────────► │
```

前置要求（均需操作员手动完成，工具绝不代改系统）：

1. 三个节点各配置 ≥25Gbps 网卡，链路连通（`ip link` / `ethtool` 确认速率）；
2. 三个节点免密 ssh（`BatchMode`），client/server 装有 iperf3，proxy 有 curtsy 二进制；
3. 若要测 9000 字节 jumbo UDP，把三节点相关网卡的 MTU 手动设为 9000；
4. 先在三个节点分别跑只读推荐，按需手工应用 NIC/IRQ/NUMA/sysctl 建议（见 §6）。

完整流程：

```bash
# 0) 只读系统推荐（不修改任何设置；机器无关，可随时跑）
tools/benchmark/run-benchmark.sh --recommend \
    --client user@client-node --proxy user@proxy-node --server user@server-node

# 1) 环境校验 + 生成执行计划（不跑基准）
tools/benchmark/run-benchmark.sh --check \
    --client user@client-node --proxy user@proxy-node --server user@server-node \
    --link-speed 25 --mtu 9000 --duration 30 --session 20260804-3node

# 2) 正式三节点基准（计划通过后再 --run）
tools/benchmark/run-benchmark.sh --run \
    --client user@client-node --proxy user@proxy-node --server user@server-node \
    --link-speed 25 --mtu 9000 --duration 30 --label mlx5-3node --session 20260804-3node

# 3) 复测基线（例如改内核参数/sockmap 后），再与上一步对比
tools/benchmark/run-benchmark.sh --run \
    --client user@client-node --proxy user@proxy-node --server user@server-node \
    --link-speed 25 --mtu 9000 --duration 30 --label mlx5-3node-retune --session 20260804-3node-retune

# 4) 回归对比（默认吞吐回落 >3% 或 CPU-per-Gbit 上升 >5% 即失败）
tools/benchmark/compare.sh \
    /tmp/curtsy-benchmark/20260804-3node/summary.json \
    /tmp/curtsy-benchmark/20260804-3node-retune/summary.json \
    --json compare-3node.json
```

三节点下地址解析规则：direct 基线连 `server` 的主 IPv4，proxied 目标连 `proxy`
的主 IPv4，Curtsy 上游连 `server` 的主 IPv4。如需覆盖可用
`--client-addr` / `--proxy-addr` / `--upstream-addr`（例如网卡上有多个地址时）。

### 1.2 验收标准（三节点真实 25GbE）

只有当 1.1 的流程在三节点真实 25GbE 上跑完并通过以下门槛，才能宣称「25 Gbps
转发就绪」。**回环结果不是硬件证明**：回环路径（MTU 65536、零 RTT、无 NIC/IRQ/
NUMA 参与）只能验证工具链路，任何回环数字都不能替代 25GbE 实测。

| 指标 | 通过门槛 | 对应命令 |
| --- | --- | --- |
| TCP 8–64 并发连接 | 经 Curtsy ≥ 23.5 Gbps，持续 10 分钟 | `--tcp-connections 8,16,32,64 --duration 600` |
| UDP 1500 字节报文 | ≥ 23 Gbps，丢包 < 0.01% | `--udp-packet-sizes 1500 --duration 600` |
| UDP 9000 字节 jumbo 报文 | ≥ 24 Gbps，丢包 < 0.001% | `--udp-packet-sizes 9000 --mtu 9000 --duration 600` |
| direct-vs-Curtsy 比率 | Curtsy 吞吐 ≥ 直接基线的 95%（TCP）/ 93%（UDP） | `report.txt` 相邻 direct/curtsy 行读取 |

说明：

- 三条带宽门槛均指 **经 Curtsy 转发** 的 iperf3 吞吐（`run-*-curtsy-*` 结果），
  方向默认 forward+reverse 都测、分别记账；10 分钟即 `--duration 600`；
- UDP 丢包看 `lost_percent`，jumbo 报文要求整条路径（client↔proxy↔server）MTU
  都是 9000（1.1 前置第 3 条）；
- direct-vs-Curtsy 比率 = 同一 profile 点下 `curtsy` 与 `direct` 模式的
  `bits_per_second` 之比，在 `report.txt` 相邻两行即可读取；比率过低通常意味着
  转发路径（队列、IRQ 亲和、NUMA、sockmap）有瓶颈，参考 §6 排查；
- 上述数值在**执行 `--recommend` 并手工应用建议（§6）、跑 `--check` 通过后**测，
  全部通过后用 `compare.sh`（§7）做回归门禁。任何 AF_XDP/XDP 类方案在取得新的
  实测证据前不在本文档与工具链范围内。

验收流程（完整可复现）：

```bash
# 0) 三节点只读推荐 + 按需手工应用（不修改任何设置）
tools/benchmark/run-benchmark.sh --recommend \
    --client user@client-node --proxy user@proxy-node --server user@server-node

# 1) 环境校验 + 执行计划（不跑基准；--check 通过后再 --run）
tools/benchmark/run-benchmark.sh --check \
    --client user@client-node --proxy user@proxy-node --server user@server-node \
    --link-speed 25 --mtu 9000 --duration 600 --session accept-25g

# 2) 正式验收基准：一个会话同时产出 direct 与 curtsy 两种模式的结果
tools/benchmark/run-benchmark.sh --run \
    --client user@client-node --proxy user@proxy-node --server user@server-node \
    --link-speed 25 --mtu 9000 --duration 600 \
    --tcp-connections 8,16,32,64 --udp-packet-sizes 1500,9000 \
    --label 25g-accept --session accept-25g

# 3) 判定：在 report.txt / summary.json 里按 profile 点读取
#    - curtsy 模式的 bits_per_second / lost_percent，对照 §1.2 上表绝对门槛；
#    - 相邻 direct/curtsy 两行算出 direct-vs-Curtsy 比率。

# 4) 调优后再跑同一参数集（如 --session accept-25g-retune），
#    用 compare.sh 做回归门禁（吞吐回落 >3% / CPU-per-Gbit 上升 >5% / 丢包 / 重传即失败）
tools/benchmark/compare.sh \
    /tmp/curtsy-benchmark/accept-25g/summary.json \
    /tmp/curtsy-benchmark/accept-25g-retune/summary.json \
    --json /tmp/curtsy-benchmark/accept-25g-compare.json
```

`compare.sh` 按 `protocol|mode|point|direction` 对齐 run，因此只应用于**模式构成
一致**的两份 summary（如两次 curtsy 会话、或同一次会话的调优前后复测）；它输出
的 `verdict` 是回归一致性检查，**不替代**上表的绝对门槛。direct-vs-Curtsy 比率在
`report.txt` 的相邻两行（同一 profile 点、`mode=direct` 与 `mode=curtsy`）读取，
或在 `summary.json` 中按点手工计算。

## 2. 两种模式

### 2.1 `--check` / `--dry-run`（默认）

环境校验并生成执行计划，**不执行任何基准**：

- 校验必需工具（bash、ip、ss、iperf3、jq）在对应节点上是否存在；
- 检测各节点网卡及链路速率（`ethtool`），无法确认 ≥ `--link-speed` 时告警；
- 用生成的配置对 `curtsy --check-config` 做校验；
- 检查监听/上游端口占用、UDP 收发缓冲 sysctl、目标 MTU；
- 输出 `plan.json`（计划测试清单 + 警告 + 建议命令）与
  `env-before/` 环境快照，并打印人读摘要。

在缺 25GbE 或 iperf3 的机器上：缺 iperf3 会明确报错并标记测试被阻塞
（`--run` 时直接退出码 3）；可选工具（ethtool、numactl、lscpu）缺失时对应
采集项降级为 `unavailable:`。

### 2.2 `--run`

在 `--check` 的全部校验通过后执行基准。缺 25G 网卡且未传 `--force` 时以
退出码 4 拒绝运行（回环冒烟测试请加 `--force`）。执行过程：

1. 采集各节点会话级 `env-before/` 快照；
2. 逐 profile 点、逐模式（direct → curtsy）、逐方向执行测试：
   - 启动 iperf3 server（`iperf3 -s`），等待监听；
   - curtsy 模式额外启动 Curtsy（生成的配置），等待监听；
   - 采集本次 run 的 `env/before`（含 `/proc/softirqs`、`/proc/interrupts`）；
   - 运行 iperf3 客户端，保存 `--json` 原始输出；
   - 采集 `env/after`；停止 Curtsy（SIGTERM 优雅退出）与 iperf3 server；
3. 采集 `env-after/`；汇总出 `summary.json` 与 `report.txt`。

### 2.3 只读系统推荐（`--recommend`）

`run-benchmark.sh --recommend` 在 client / proxy / server 各节点运行
`lib/recommend-system.sh`，只做**只读**检查并输出机器可读 findings 与显式建议
命令，**绝不执行任何修改操作**（不使用 sysctl -w / ip link set / ethtool -K/-G/-L
/ IRQ 亲和写操作；工具与测试均验证了这一约束）。

检查项：

| 类别 | 检查内容 | 缺省告警阈值 |
| --- | --- | --- |
| `governor` | `scaling_governor` 是否为 `performance` | 非 `performance` |
| `socket` | `rmem_max` / `wmem_max` ≥ 8 MiB、`somaxconn` ≥ 4096、`netdev_max_backlog` ≥ 4096 | 低于阈值 |
| `nic` | `ethtool` 速率 ≥ 目标、驱动类型（`virtio`/`vfio-pci` 等非高性能驱动告警） | 速率低于 `--target-speed` |
| `rss` | RX 队列数与 CPU 数 | RX 队列 < CPU 数 |
| `mtu` | 网卡 MTU 与 `--target-mtu` 是否一致 | 不一致 |
| `numa` | 网卡所在 NUMA 节点，提示 `numactl` 绑定 | 仅提示 |
| `rps` / `xps` | 各队列 `rps_cpus` / `xps_cpus` 是否为 0 | 存在 0 掩码队列 |
| `irq` | `/proc/interrupts` 中该网卡中断的 `smp_affinity` 是否集中 | 多中断共用单一掩码 |
| `ring` | `ethtool -g` RX/TX ring | < 1024 |
| `offload` | checksum / TSO / GRO 是否开启 | 关闭 |

```bash
# 本机（或三节点）只读推荐
tools/benchmark/run-benchmark.sh --recommend \
    --client user@client-node --proxy user@proxy-node --server user@server-node

# 或直接在某个节点运行脚本本身
tools/benchmark/lib/recommend-system.sh --json findings.json --text findings.txt \
    --target-speed 25 --target-mtu 9000
```

输出：会话目录下 `recommend-<node>/findings.json`（机器可读）与 `findings.txt`
（人读），`findings.json` 内含 `findings[]`（`severity/category/node/detail/command`）
与 `commands[]`（去重后的建议命令清单，可直接给操作员审阅后手工执行）。
脚本退出码：0 正常（findings 仅供参考，`warn` 不改变退出码）、2 用法错误、3 缺 jq。

## 3. 参数与 Profile

### 3.1 参数（节选）

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--protocols tcp\|udp\|both` | `both` | 被测协议 |
| `--duration N` | `10` | 单次 iperf3 时长（秒），须为正整数 |
| `--bandwidth RATE` | `25G` | UDP 目标速率（iperf3 `-b`） |
| `--direction f\|r\|both` | `both` | 测试方向 |
| `--tcp-connections LIST` | 见 profile | 覆盖 TCP 并发数，如 `1,16,64` |
| `--udp-packet-sizes LIST` | 见 profile | 覆盖 UDP 报文大小，如 `64,512,1400` |
| `--link-speed G` | `25` | 最小网卡速率门禁（Gbps） |
| `--mtu BYTES` | `1500` | 目标 MTU，只校验/记录，不修改 |
| `--udp-socket-buffer B` | `4194304` | iperf3 UDP `-w`（字节） |
| `--acceleration auto\|enabled\|disabled` | `auto` | 写入生成的 Curtsy 配置的 sockmap 开关 |
| `--worker-threads auto\|N` | `auto` | 写入生成的配置的 `runtime.workerThreads` |
| `--listen-port` / `--upstream-port` | `9000` / `9001` | Curtsy 监听 / iperf3 server 端口 |
| `--config PATH` | 自动生成 | 复用已有 Curtsy 配置（端口须与上面两项一致） |

### 3.2 Profile 文件

- `profiles/tcp-connections.default`：默认 `1 4 16 64`（并行连接数 `-P`）；
- `profiles/udp-packet-sizes.default`：默认 `64 256 512 1400 9000`（`-l` 报文长）。

格式为空白/逗号分隔的整数，`#` 为注释。当 `--mtu < 8500` 时自动丢弃 ≥ 8500 的
jumbo 尺寸并记录告警（9000 字节报文在 1500 MTU 下无意义）。命令行覆盖优先。

### 3.3 生成的 Curtsy 配置

模板见 `templates/curtsy-config.yaml`。固定设置：

- `runtime.tuningDaemon: false`：关闭常驻调参 daemon，保证基准结果不被动态调参扰动；
- `performance.tcp/udpSockmapAcceleration` 跟随 `--acceleration`；
- `performance.udpSocketBufferBytes: 4194304`：UDP socket 缓冲 4 MiB。

如需 `enabled`/`disabled` 对比 sockmap 加速，分别以 `--acceleration enabled` 和
`--acceleration disabled` 跑两次，用相同 `--label` 区分。

## 4. 结果布局与运行标识

```
<output-dir>/<session>/
  session-meta.json      会话元数据、完整命令行
  plan.json              计划测试、警告、建议命令（check 与 run 都写）
  env-before/、env-after/  每节点一次的环境/NIC/软中断快照
  run-<seq>-<proto>-<mode>-<point>/
    meta.json            本 run 元数据（mode 取值 direct | curtsy）
    iperf3-forward.json   iperf3 客户端原始 JSON
    iperf3-reverse.json   反向原始 JSON（启用 reverse 时）
    iperf3-*.stderr.log   iperf3 客户端 stderr
    iperf3-server.log     iperf3 server stderr
    curtsy-config.yaml    curtsy 模式所用配置
    curtsy.stderr.log     curtsy 日志（curtsy 模式）
    env/before/、env/after/  本 run 前后快照（proxy 节点）
  summary.json           机器可读汇总（回归对比）
  report.txt             人读汇总表
```

**运行标识**：

- `session`：一次调用 = 一个会话，默认 `session-<UTC时间戳>-<pid><rand>`，
  可用 `--session` 指定（如 `--session 20260804-lnx1`）；
- `run_id`：`run-<seq>-<proto>-<mode>-<point>`，如 `run-004-tcp-curtsy-conn16`、
  `run-012-udp-direct-pkt1400`，`seq` 从 001 递增，保证目录唯一可排序。

每次测试的 `meta.json` 都带 `mode`、`label`、目标地址、节点 hostname、iperf3
版本、MTU、带宽、加速配置，可直接用于回归对比；curtsy 模式还记录 `cpu_seconds`
（本次 run 期间 Curtsy 进程全线程 CPU 时间，秒）与 `test_seconds`（本 run 测试
总时长 = `--duration` × 方向数），供汇总与 CPU-per-Gbit 计算。`summary.json` 的
每个元素含 `run_id / protocol / mode / point / point_value / direction /
bits_per_second / retransmits / mean_rtt_us / jitter_ms / lost_percent / packets /
cpu_seconds / test_seconds / cpu_per_gbit`。

## 5. 环境 / NIC / 软中断采集

`lib/collect-env.sh` 在目标节点采集（缺失的可选工具降级）：

| 文件 | 内容 |
| --- | --- |
| `meta.txt` | 采集时间、hostname、uname、os-release |
| `cpu.txt` / `nproc.txt` | lscpu / CPU 数、型号 |
| `meminfo.txt` | /proc/meminfo |
| `nics.txt` | `ip link show` + `ip addr show` |
| `link_speed.txt` | 每网卡速率（`<iface> <Mbps|unknown>`，供门禁解析） |
| `ethtool.txt` | 每网卡 `ethtool` / `ethtool -i` / `ethtool -S` |
| `interrupts.txt` | /proc/interrupts |
| `softirqs.txt` | /proc/softirqs |
| `netdev.txt` | /proc/net/dev（接口收发包与错误计数） |
| `netstat.txt` | /proc/net/netstat（含监听队列溢出） |
| `snmp.txt` / `sockstat.txt` / `route.txt` | TCP/UDP 统计、socket 统计、路由 |
| `sysctl.txt` | 相关 net.* 值 |
| `numa.txt` | `numactl --hardware` |

会话级 `env-before/`/`env-after/` 对比可评估系统基线漂移；每个 run 的
`env/before` 与 `env/after` 对比可得到该测试期间软中断/中断/NIC 计数增量。

## 6. 推荐做法与系统设置

工具**不会**自动修改系统设置，只打印 `$ sudo ...` 建议命令。上线前建议：

1. **25G 网卡门禁**：`--link-speed 25` 会检查各节点是否有 ≥ 25Gbps 网卡；
   无法确认速率（如虚拟网卡）或低于目标时，`--run` 会拒绝（除非 `--force`）。
2. **UDP 缓冲 sysctl**：`net.core.rmem_max` / `net.core.wmem_max` 建议 ≥ 8 MiB
   （Curtsy `udpSocketBufferBytes` 默认 4 MiB；无 `CAP_NET_ADMIN` 时内核会把
   请求静默收敛到这两个值）：
   ```bash
   sudo sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
   ```
3. **25G TCP 窗口**：高 RTT 链路需要足够窗口上限，建议：
   ```bash
   sudo sysctl -w net.ipv4.tcp_rmem='4096 262144 16777216' \
                net.ipv4.tcp_wmem='4096 262144 16777216' \
                net.core.rmem_max=16777216 net.core.wmem_max=16777216
   ```
   如需持久化，写入 `/etc/sysctl.d/`（重启保留，`sysctl -w` 不保留）。
4. **MTU**：`--mtu 9000`（或 1500）只做校验；与网卡实际 MTU 不一致时打印
   `sudo ip link set <iface> mtu <mtu>` 建议命令。注意 jumbo（9000 字节）UDP
   报文要求整条路径（client↔proxy↔server）的网卡 MTU 都是 9000，否则分片/丢包。
5. **RSS 队列**：多队列网卡建议开启与 CPU 数相当的 RX/TX 队列，避免单队列成为
   转发瓶颈。注意 `ethtool -L` 会重建队列、短暂中断该网卡流量：
   ```bash
   sudo ethtool -L <iface> combined <ncpus>
   ```
6. **RPS / XPS**：队列多于 CPU 或 RSS 不足时，可把接收/发送流均衡到多核
   （`sysfs` 写入，重启丢失，需用 udev/systemd 持久化）：
   ```bash
   # 全核掩码示例（8 核 => ff），可先 cat /sys/class/net/<iface>/queues/rx-0/rps_cpus 确认
   for q in /sys/class/net/<iface>/queues/rx-*/rps_cpus; do echo ff | sudo tee "$q"; done
   for q in /sys/class/net/<iface>/queues/tx-*/xps_cpus; do echo ff | sudo tee "$q"; done
   ```
7. **IRQ 亲和**：多中断集中在一个 CPU 上会形成瓶颈。优先用
   `sudo systemctl enable --now irqbalance`；需要手动分发时逐个写
   `/proc/irq/<n>/smp_affinity`（按位掩码，每核一个中断）。同样需持久化。
8. **CPU 绑定 / NUMA 就近**：NIC 在哪个 NUMA 节点，转发进程就应绑定到同节点，
   减少跨 NUMA 内存访问。先确认节点：
   ```bash
   cat /sys/class/net/<iface>/device/numa_node    # 0 或 1
   numactl --hardware
   ```
   然后用 `numactl` 包裹进程（**只在被测节点/测试进程上做，不修改系统全局**）：
   ```bash
   numactl --cpunodebind=<node> --membind=<node> <curtsy-binary> --config <config>
   numactl --cpunodebind=<node> --membind=<node> iperf3 -s -p 9001
   ```
   当前工具未内置绑定选项，可通过 `--curtsy-binary` 指向一个 `numactl ...` 包装
   脚本、或运行前手工用 `taskset` 启动 iperf3 server 的方式实现。
9. **CPU governor**：25G 转发建议 `performance`：
   ```bash
   sudo cpupower frequency-set -g performance
   ```
10. **一键生成建议**：以上各项用 `run-benchmark.sh --recommend`（或
   `lib/recommend-system.sh`）即可自动盘点本机差异，命令逐条由操作员审阅后
   手工执行；工具只读、不落盘到系统，重启后 sysfs/ethtool 类修改需自行持久化。

> 安全提醒：任何 `ethtool -L`、`sysfs` 写、IRQ 亲和改动都会影响在途流量并可能
> 在重启后失效；请在维护窗口、测试节点上操作，改动前保留原值。

## 7. 回归对比（compare.sh）

两次运行使用相同参数与 profile，得到各自 `summary.json`，用
`tools/benchmark/compare.sh` 做自动化回归门禁。

```bash
tools/benchmark/compare.sh <baseline-summary.json> <candidate-summary.json> [选项]
```

对比键为 `protocol|mode|point|direction`（如 `tcp|curtsy|conn16|forward`），
逐 run 对齐后按下列指标判定：

| 指标 | 默认门限 | 说明 |
| --- | --- | --- |
| 吞吐 `bits_per_second` | 下降 >3% 判 FAIL | `--max-throughput-regression <pct>` |
| CPU-per-Gbit `cpu_per_gbit` | 上升 >5% 判 FAIL | `--max-cpu-regression <pct>`；仅当两侧都存在该字段时生效，缺失则报「不可比」 |
| UDP 丢包 `lost_percent` | 上升 >5 个百分点判 FAIL | `--max-loss-increase <pct>` |
| TCP 重传 `retransmits` | 增加 >1000 判 FAIL | `--max-retransmit-increase <n>` |

- 只在一侧出现的 run 计为 `missing_in_candidate` / `missing_in_baseline`，
  默认按警告（WARN）报告、不改变退出码；加 `--fail-on-missing` 后转为失败。
- CPU-per-Gbit 等字段只出现在一侧时，对应指标标 `skip` 并在 `warnings` 中说明
  原因（「不可比」）。`summarize.sh` 对每个 `curtsy` run（且 `cpu_seconds > 0`）
  产出 `cpu_per_gbit`；`direct` run 或采集失败时为 `null`，compare 视其为「不存
  在」。所以「不可比」只发生在两侧采样状态不一致时（如一侧 curtsy、一侧直连，
  或一侧 CPU 采集失败）。
- **`cpu_per_gbit` 的定义**（单位：% 单核 / Gbps）：
  `(cpu_seconds / test_seconds × 100) / (bits_per_second / 1e9)`。`cpu_seconds`
  是 run 期间 Curtsy 进程全线程 CPU 时间（/proc/<pid>/stat 的 utime+stime 差，
  按 CLK_TCK 换算成秒）；`test_seconds` 是该 run 的测试总时长。多 worker 时该值
  可大于 100%×Gbps 的直觉值（多个核同时工作）。该指标对测试时长不变（时长同比例
  进入分子分母），因此不同 `--duration` 的会话也可横向比较。

退出码：

| 码 | 含义 |
| --- | --- |
| 0 | PASS（所有门限内；缺失按警告报告） |
| 1 | FAIL（某 run 触发吞吐/CPU/丢包/重传门限，或 `--fail-on-missing` 且有缺失） |
| 2 | 用法错误 |
| 3 | 无法对比（文件不可解析、或两个 summary 无任何重叠 run） |

输出：`--json <file>` 写机器可读报告（`verdict / results[] / failures[] /
missing_in_candidate[] / missing_in_baseline[] / warnings[] / parameters`）；
`--text <file>` 写人读报告（默认 stdout）。典型用法：

```bash
tools/benchmark/compare.sh \
    /tmp/curtsy-benchmark/baseline/summary.json \
    /tmp/curtsy-benchmark/retune/summary.json \
    --json compare-retune.json \
    || echo "regression gate failed (exit $?)"
```

对比前建议固定：`--duration`、`--mtu`、`--udp-socket-buffer`、`--worker-threads`、
`--acceleration` 与 `--label`，并记录网卡型号/驱动（`ethtool -i`）；回环冒烟结果
不适合作为跨机 25G 的回归基线。

## 8. 已知限制

- **IPv4 only**：工具当前不构造 IPv6 iperf3 会话。
- **UDP 丢包预期**：`-b 25G` 在小报文下通常打不满链路，iperf3 报出的
  `lost_percent` 高属正常；UDP 指标应看 `bits_per_second` + `lost_percent` 组合。
- **远端节点**：`--client`/`--server`/`--proxy` 传远程主机时要求免密 ssh
  （BatchMode），并需在远端预装 iperf3；`--proxy` 为远程时 `--curtsy-binary`
  指向**远端**的绝对路径。
- **回环冒烟与真实 25G 的差异**：回环路径（MTU 65536、零 RTT）不代表真实
  跨机性能，只能验证工具链路本身。真实结论必须在 25GbE 双机（或三机）上复测。
- **`--config` 复用**：使用已有配置时，`--listen-port`/`--upstream-port` 必须
   与配置一致，否则等待监听逻辑与转发目标会错位。
- **`--recommend` 远程节点需 jq**：`lib/recommend-system.sh` 依赖 jq；远程节点
    缺 jq 时该节点推荐运行会失败并告警（不影响其他节点）。
- **`compare.sh` 的 CPU-per-Gbit 采样边界**：`cpu_per_gbit` 只在 `curtsy` run
    且 CPU 采样成功（`cpu_seconds > 0`）时产出；直连 run 该字段为 `null`。因此
    两侧采样状态一致（同为 curtsy）时才参与门禁，否则按「不可比」报告。CPU 采样
    失败（如 `/proc/<pid>/stat` 不可读）的 curtsy run 同样记 `null` 并按不可比
    处理。

## 9. 校验命令

```bash
# 语法检查（shellcheck 缺失时以 bash -n 替代）
bash -n tools/benchmark/run-benchmark.sh \
      tools/benchmark/compare.sh \
      tools/benchmark/lib/common.sh \
      tools/benchmark/lib/collect-env.sh \
      tools/benchmark/lib/summarize.sh \
      tools/benchmark/lib/recommend-system.sh
if command -v shellcheck >/dev/null; then
    shellcheck -s bash tools/benchmark/compare.sh tools/benchmark/lib/recommend-system.sh
fi

# 帮助 / 本地 dry-run
tools/benchmark/run-benchmark.sh --help
tools/benchmark/run-benchmark.sh --check
tools/benchmark/run-benchmark.sh --recommend --session rec-check   # 只读，本机即可
tools/benchmark/compare.sh --help

# fixture 驱动测试（compare 的 pass/阈值 FAIL/不可比 incl. CPU-per-Gbit、
# recommend 的只读性、summarize 的 CPU-per-Gbit 产出）
tools/benchmark/tests/run-tests.sh

# 回环端到端冒烟
tools/benchmark/run-benchmark.sh --run --force \
    --duration 3 --tcp-connections 1,4 --udp-packet-sizes 64,1400
```
