# Curtsy

Curtsy 是一个使用 SwiftNIO 编写的 Linux TCP/UDP 透明流量转发器。它在一个地址和端口上监听 TCP、UDP 或两种协议，并把流量转发到固定上游。

## 构建

需要 Swift 6 或更高版本：

```bash
swift build -c release
```

生成的程序位于 `.build/release/curtsy`。

## Debian 打包

仓库包含 debhelper 打包元数据。构建机需要 `dpkg-dev`、`debhelper`、`clang`，并确保 Swift 6 工具链已在 `PATH` 中，然后可构建 `.deb`：

```bash
dpkg-buildpackage -us -uc -b
```

构建会执行 `swift build -c release --static-swift-stdlib`，并在未设置
`DEB_BUILD_OPTIONS=nocheck` 时运行 `swift test`。生成的二进制包位于仓库上级目录。

安装后包含：

- `/usr/bin/curtsy`
- `/etc/curtsy/config.yaml`，来自 [`config.example.yaml`](config.example.yaml)
- `curtsy.service` systemd unit

服务默认不会在安装后自动启用或启动。先修改 `/etc/curtsy/config.yaml`，再检查并启动：

```bash
sudo curtsy --config /etc/curtsy/config.yaml --check-config
sudo systemctl enable --now curtsy
```

常用 systemd 操作：

```bash
sudo systemctl status curtsy
sudo systemctl reload curtsy
sudo systemctl restart curtsy
sudo journalctl -u curtsy -f
```

## 配置与运行

复制并修改 [`config.example.yaml`](config.example.yaml)，最小配置只需要监听端口和上游主机：

```yaml
listen:
  port: 9000

upstream:
  host: "example.com"
```

未写出的配置项会自动适配；需要固定行为时再显式覆盖。然后检查配置：

```bash
.build/release/curtsy --config config.yaml --check-config
```

启动服务：

```bash
.build/release/curtsy --config config.yaml
```

`protocols` 省略时同时启用 TCP 和 UDP，也可设为 `[tcp]`、`[udp]` 或 `[tcp, udp]`。`listen.host` 省略时为 `*`，监听所有 IPv4/IPv6 地址；上游支持 IPv4、IPv6 和主机名。`upstream.port` 省略时使用 `listen.port`。

`runtime.workerThreads` 省略、设为 `0` 或设为 `auto` 时，Curtsy 会按 CPU 数自动选择 worker 数，并限制过高核心数带来的空载内存和调度成本；显式正整数会固定 worker 数。`runtime.tuningDaemon` 默认启用，`runtime.tuningIntervalSeconds` 默认 5 秒。`limits` 下的整数项省略或写 `auto` 时，会按 Linux 主机 CPU/内存探测结果生成保守初始值，并由常驻 tuning daemon 持续观测后调整；显式整数始终优先。启动日志会输出最终生效的 worker 和主要限额。

## 信号

- `SIGHUP`：重新读取并应用配置。配置无效或新端口绑定失败时继续使用旧配置。
- `SIGINT` / `SIGTERM`：停止监听并优雅退出。现有 TCP 连接最多等待 `shutdownGraceSeconds`。

热加载后，已有 TCP 连接继续使用原上游，新连接使用新上游；上游变化时已有 UDP 映射会被清除并按新配置重建。

## TCP 性能

TCP 转发路径使用大块自适应读取、批量 flush 和背压控制，目标是在常规 Linux 主机上让单连接达到 1 Gbps。实际吞吐仍取决于 CPU、网卡、上游服务以及链路的带宽时延积。

多连接场景下，Curtsy 会为每个事件循环创建一个 `SO_REUSEPORT` TCP 监听 socket，并在 Linux 上通过 `SO_ATTACH_REUSEPORT_EBPF` 加载 socket-filter eBPF 程序，按连接四元组 hash 直接分流到对应 worker，避免单监听 socket 成为 accept 瓶颈以及连接建立后的跨线程迁移。worker 数量默认自动适配 CPU，并可通过 `runtime.workerThreads` 固定。

在具备 eBPF 权限的 Linux 上，Curtsy 还可创建 `BPF_MAP_TYPE_SOCKHASH`，并为每对客户端/上游 TCP socket 挂载 `SK_SKB` stream parser 与 verdict 程序。双向数据通过 `bpf_sk_redirect_hash` 在内核中直接转发，绕过 SwiftNIO relay 的 `tcp_recvmsg`、`tcp_sendmsg` 和用户缓冲区复制。BPF 同时记录双向最后活动时间，因此加速连接仍遵守 `tcpIdleSeconds`；半关闭和 FIN 继续由 NIO 通道生命周期处理。

`performance.tcpSockmapAcceleration` 控制该路径：`enabled` 强制尝试启用，`disabled` 始终使用用户态 relay，默认的 `auto` 对所有上游尝试启用（包括回环）。在 Linux 6.8 回环实测中，sockmap 与多连接用户态 relay 吞吐相当或更高，同时转发进程 CPU 占用从约 1 核降到接近零，因此 `auto` 不再排除回环上游。热加载改变此项时，已有 TCP 连接保持原模式，新连接使用新模式；UDP listener 和已有 UDP 会话不会因此重建。

加载 eBPF 通常需要 root，或内核版本对应的 `CAP_BPF`、`CAP_NET_ADMIN`、`CAP_PERFMON` 等 capability。权限不足、内核不支持或单连接 sockhash 配对失败时，Curtsy 会记录日志并自动回退到现有用户态 relay；监听分流也会回退到内核原生的 `SO_REUSEPORT` hash，转发服务不会因此启动失败。

常驻 tuning daemon 默认启用。它会优先加载 eBPF kprobe observer，观测当前 Curtsy 进程触发的 TCP/UDP send/recv 内核调用，并结合 `/proc/net/netstat` 的监听队列溢出计数和 Curtsy 内部 TCP/UDP 使用量持续调参。当前版本只调整 Curtsy 自己的运行时限额，不写系统 sysctl；如果 eBPF observer 加载失败，会降级使用内部计数和 `/proc`，服务继续运行。

`limits.tcpListenBacklog` 默认为 4096，用于吸收突发连接。实际队列仍受系统 `net.core.somaxconn` 和 `net.ipv4.tcp_max_syn_backlog` 限制。连接状态表采用分片锁；低于当前日志等级的连接日志不会再构造消息或获取日志锁，每条 TCP 连接只保留一个空闲计时器。

用户态 TCP relay 的待发送数据受全局 `limits.maxTCPBufferedBytes` 约束；默认值按系统内存自动计算并限制在保守范围内。该预算由所有连接和两个转发方向共享；达到上限时，无法安全缓存下一块数据的连接会被关闭，避免大量慢速连接耗尽进程内存。sockmap 内核转发不占用此用户态预算。

高 RTT 链路需要足够大的系统 TCP 自动调优上限。例如 1 Gbps、100 ms RTT 的链路至少需要约 12.5 MB 的 TCP 窗口，可按部署环境检查并调整 `net.ipv4.tcp_rmem`、`net.ipv4.tcp_wmem`、`net.core.rmem_max` 和 `net.core.wmem_max`。Curtsy 不会自行覆盖这些系统级参数。

## 配置约束

- 当前版本只支持一条监听规则和一个上游。
- 所有超时单位均为秒，必须大于零，且不能超过 `9223372036` 秒。
- UDP 会话按客户端 IP 与端口隔离，空闲超过 `udpSessionSeconds` 后回收。
- 达到 `maxUDPAssociations` 后，新 UDP 客户端会被丢弃，已有会话不受影响；默认上限按系统内存自动计算。
- UDP 转发由独立 I/O 线程以 `recvmmsg`/`sendmmsg` 批量收发（64 报文/批），会话在首个报文到达时同步建立，不存在待转发缓冲窗口；`maxUDPPendingDatagrams` 和 `maxUDPPendingBytes` 仅为兼容旧配置保留，当前不再使用。
- 程序不会终止 TLS、检查流量内容或记录转发数据正文。

## 测试

```bash
swift test
```

默认测试不要求 eBPF 权限。若要在具备权限的 Linux 主机上显式验证 eBPF loader，可运行：

```bash
CURTSY_ENABLE_EBPF_TESTS=1 swift test --filter ForwardingTests.testOptionalEBPFLoadersWhenExplicitlyEnabled
```
