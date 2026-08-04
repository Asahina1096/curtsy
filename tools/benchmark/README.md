# Curtsy 基准测试工具（tools/benchmark）

Curtsy 25 Gbps 基准测试工具：用 iperf3 对比「直连基线」与「经 Curtsy 转发」的
TCP/UDP 吞吐，并收集环境、网卡、软中断计数器，输出可机器对比的结果。附带两个
只读工具：

- **`lib/recommend-system.sh` / `run-benchmark.sh --recommend`**：只读盘点
  NIC/IRQ/NUMA/RPS/RSS/sysctl 并输出建议命令（绝不修改系统）；
- **`compare.sh`**：对两份 `summary.json` 做回归门禁（吞吐/CPU-per-Gbit/丢包/重传）。

详细说明见 [docs/performance.md](../../docs/performance.md)。

## 快速开始

```bash
# 环境校验 + 生成执行计划（不跑基准），无 25GbE 的机器也能用
tools/benchmark/run-benchmark.sh --check

# 只读系统推荐（本机即可，不修改任何设置）
tools/benchmark/run-benchmark.sh --recommend

# 本机回环冒烟测试（绕过 25G 网卡门禁）
tools/benchmark/run-benchmark.sh --run --force \
    --session smoke --label "loopback" \
    --duration 3 --tcp-connections 1,4 --udp-packet-sizes 64,1400

# 双节点真实基准：本机跑 Curtsy（proxy），远程跑 iperf3 客户端
tools/benchmark/run-benchmark.sh --run \
    --client user@client-node --proxy local --server local \
    --label "mlx5-25g" --duration 30 --link-speed 25

# 回归对比（两次 run 的 summary.json）
tools/benchmark/compare.sh \
    /tmp/curtsy-benchmark/<sessionA>/summary.json \
    /tmp/curtsy-benchmark/<sessionB>/summary.json
```

## 关键选项

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `--check` / `--dry-run` | 默认 | 环境校验 + 生成 `plan.json`，不执行 |
| `--run` | — | 实际执行基准会话 |
| `--client` / `--proxy` / `--server` | `local` | 各角色节点（`local` 或 `user@host`，需免密 ssh） |
| `--protocols` | `both` | `tcp` / `udp` / `both` |
| `--duration` | `10` | 单次测试时长（秒） |
| `--bandwidth` | `25G` | UDP 目标速率（iperf3 `-b`） |
| `--direction` | `both` | `forward` / `reverse` / `both` |
| `--tcp-connections` | 见 profile | 覆盖 TCP 并发连接数列表 |
| `--udp-packet-sizes` | 见 profile | 覆盖 UDP 报文大小列表 |
| `--link-speed` | `25` | 最小网卡速率门禁（Gbps） |
| `--mtu` | `1500` | 目标 MTU（只校验/记录，绝不修改） |
| `--acceleration` | `auto` | sockmap：`auto` / `enabled` / `disabled` |
| `--force` | 关 | 绕过 link-speed 门禁（如回环冒烟） |
| `--output-dir` | `/tmp/curtsy-benchmark` | 结果输出目录 |
| `--session` | 时间戳 | 会话标识（多个 run 的分组） |
| `--label` | — | 自由文本标签，写入每个结果 |

## 结果布局

```
<output-dir>/<session>/
  session-meta.json      会话元数据与完整命令行
  plan.json              计划测试、警告与建议命令
  env-before/、env-after/  各节点的环境/网卡/软中断快照
  run-<seq>-<proto>-<mode>-<point>/
    meta.json            本 run 元数据（mode=direct|curtsy）
    iperf3-forward.json   iperf3 原始 JSON
    iperf3-reverse.json   反向原始 JSON（如启用 reverse）
    curtsy-config.yaml    proxied 所用的配置
  summary.json           机器可读汇总（回归对比用）
  report.txt             人读汇总表
```

## 依赖与限制

- 必需：bash ≥ 4、iproute2（`ip`/`ss`）、iperf3、jq。ethtool 等可选工具缺失时降级。
- 只允许修改 `tools/benchmark/` 与 `docs/performance.md`；绝不自动修改系统设置，
  只打印建议命令。
- 远程节点需配置免密 ssh（BatchMode）；`--recommend` 的远程节点需装有 jq。
- IPv4 only。

## 校验

```bash
bash -n tools/benchmark/run-benchmark.sh \
      tools/benchmark/compare.sh \
      tools/benchmark/lib/common.sh \
      tools/benchmark/lib/collect-env.sh \
      tools/benchmark/lib/summarize.sh \
      tools/benchmark/lib/recommend-system.sh
tools/benchmark/run-benchmark.sh --help
tools/benchmark/run-benchmark.sh --check
tools/benchmark/tests/run-tests.sh          # fixture 驱动测试（compare + recommend）
```
