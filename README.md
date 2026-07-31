# Curtsy

Curtsy 是一个使用 Zig 编写的 Linux TCP/UDP 透明流量转发器。它在一个地址和端口上监听 TCP、UDP 或两种协议，并把流量转发到固定上游。

当前版本只支持一条监听规则和一个上游，不终止 TLS、不检查流量内容、不记录转发数据正文。

## 构建

需要 Zig 0.16 或更高版本：

```bash
zig build -Doptimize=ReleaseSafe
```

生成的程序位于 `zig-out/bin/curtsy`。默认按架构基线 CPU 编译，可在任意同架构机器上运行；如需针对本机优化可加 `-Dcpu=native`（产物可能无法在更老的 CPU 上运行）。

常用命令：

```bash
zig build test
zig build run -- --config config.yaml --check-config
zig build run -- --config config.yaml
```

## Debian 打包

仓库包含 debhelper 打包元数据。构建机需要 `dpkg-dev`、`debhelper` 和 Zig 0.16+，然后可构建 `.deb`：

```bash
dpkg-buildpackage -us -uc -b
```

构建会执行 `zig build -Doptimize=ReleaseSafe`，并在未设置 `DEB_BUILD_OPTIONS=nocheck` 时运行 `zig build test`。生成的二进制包位于仓库上级目录。

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
zig-out/bin/curtsy --config config.yaml --check-config
```

启动服务：

```bash
zig-out/bin/curtsy --config config.yaml
```

`protocols` 省略时同时启用 TCP 和 UDP，也可设为 `[tcp]`、`[udp]` 或 `[tcp, udp]`。`listen.host` 省略时为 `*`，监听所有 IPv4/IPv6 地址；上游支持 IPv4、IPv6 和主机名。`upstream.port` 省略时使用 `listen.port`。

`runtime.workerThreads` 省略、设为 `0` 或设为 `auto` 时，Curtsy 会按 CPU 数自动选择 worker 数，并限制过高核心数带来的空载内存和调度成本；显式正整数会固定 worker 数。`runtime.tuningDaemon` 默认启用，`runtime.tuningIntervalSeconds` 默认 5 秒。`limits` 下的整数项省略或写 `auto` 时，会按 Linux 主机 CPU/内存探测结果生成保守初始值，并由常驻 tuning daemon 持续观测后调整；显式整数始终优先。启动日志会输出最终生效的 worker 和主要限额。

## 信号

- `SIGHUP`：重新读取并应用配置。配置无效或新端口绑定失败时继续使用旧配置。
- `SIGINT` / `SIGTERM`：停止监听并优雅退出。现有 TCP 连接最多等待 `shutdownGraceSeconds`。

热加载后，已有 TCP 连接继续使用原上游，新连接使用新上游；上游变化时已有 UDP 映射会被清除并按新配置重建。

## TCP 性能

TCP 转发路径使用每 worker 一个 epoll loop：每个 worker 持有 `SO_REUSEPORT` 监听 socket，连接和对应上游 socket 固定在同一线程。普通用户态 relay 优先使用每 worker 一个非阻塞 pipe，通过 `splice(2)` 完成 socket→pipe→socket 零拷贝；目标端产生背压时，pipe 中剩余数据会回退到原有的用户态缓冲队列。读缓冲采用 64 KiB 到 256 KiB 的自适应块，配合批量 flush 和水位线背压控制；待发送数据受全局 `limits.maxTCPBufferedBytes` 约束，防止大量慢速连接耗尽进程内存。worker 在一次 epoll 唤醒内复用同一个单调时钟时间戳，避免为每个数据块重复调用 `clock_gettime`。

多 worker 时，Curtsy 会尝试通过 `SO_ATTACH_REUSEPORT_EBPF` 加载 reuseport eBPF 程序，按连接四元组 hash 分流到对应 worker。失败时回退到内核原生 `SO_REUSEPORT` hash，不影响服务启动。

在具备 eBPF 权限的 Linux 上，Curtsy 还可创建 `BPF_MAP_TYPE_SOCKHASH`，并为每对客户端/上游 TCP socket 挂载 `SK_SKB` stream parser 与 verdict 程序。双向数据通过 `bpf_sk_redirect_hash` 在内核中直接转发，绕过用户态 relay 的 `tcp_recvmsg`、`tcp_sendmsg` 和用户缓冲区复制。BPF 同时记录双向最后活动时间，因此加速连接仍遵守 `tcpIdleSeconds`。

`performance.tcpSockmapAcceleration` 控制该路径：`enabled` 强制尝试启用，`disabled` 始终使用用户态 relay，默认的 `auto` 对所有上游尝试启用。权限不足、内核不支持或单连接 sockhash 配对失败时，Curtsy 会记录日志并自动回退到用户态 relay。

sockmap 是否更快取决于数据路径。跨主机、高 RTT 或 CPU 受限环境通常更可能受益；loopback 和部分小包场景中，SK_SKB/sockhash 的逐包成本可能高于用户态 relay。部署前应使用实际网卡、包大小和 RTT 分别压测 `enabled` 与 `disabled`，不要仅根据本机回环结果选择。

常驻 tuning daemon 默认启用。它会优先加载 eBPF kprobe observer，观测当前 Curtsy 进程触发的 TCP/UDP send/recv 内核调用，并结合 `/proc/net/netstat` 的监听队列溢出计数和 Curtsy 内部 TCP/UDP 使用量持续调参。当前版本只调整 Curtsy 自己的运行时限额，不写系统 sysctl；如果 eBPF observer 加载失败，会降级使用内部计数和 `/proc`，服务继续运行。

高 RTT 链路需要足够大的系统 TCP 自动调优上限。例如 1 Gbps、100 ms RTT 的链路至少需要约 12.5 MB 的 TCP 窗口，可按部署环境检查并调整 `net.ipv4.tcp_rmem`、`net.ipv4.tcp_wmem`、`net.core.rmem_max` 和 `net.core.wmem_max`。Curtsy 不会自行覆盖这些系统级参数。

## UDP 性能

UDP 转发由独立 I/O 线程池驱动（默认每 CPU 一个线程，可用 `performance.udpIOThreads` 固定）：每个线程持有一个经 `SO_REUSEPORT` 绑定同一地址的监听 socket，内核按客户端四元组 hash 把流量稳定分流到固定线程；各线程用 epoll 管理自己的监听与上游 socket，`recvmmsg`/`sendmmsg` 以 64 报文为一批收发，会话在首个报文到达时同步建立。`maxUDPAssociations` 由所有线程共享，仍是全局上限而不是每线程配额。

UDP 高吞吐场景下，内核默认的 208 KiB socket 缓冲经常是最先触顶的瓶颈。`performance.udpSocketBufferBytes`（默认 4 MiB，设为 `0` 保持内核默认）会应用到监听、上游和每客户端 socket 的收发缓冲；没有 `CAP_NET_ADMIN` 时内核会把请求静默收敛到 `net.core.rmem_max` / `net.core.wmem_max`，因此建议部署时同步调大这两个 sysctl（Debian 包自带 `usr/lib/sysctl.d/60-curtsy.conf`，把两者设为 8 MiB）。

在具备 eBPF 权限且内核 >= 5.12 的 Linux 上，Curtsy 还可以为 UDP 会话启用 sockmap 内核转发：首个报文仍由用户态建立会话，随后为该客户端创建一个 connect 到其地址的专用 socket，并把客户端 socket 与上游 socket 配对放入 `BPF_MAP_TYPE_SOCKHASH`；`SK_SKB` verdict 程序用 `bpf_sk_redirect_hash` 把两个方向的报文直接转发到对端发送路径，不再经过用户态。每个 I/O 线程持有独立的 sockhash 与 verdict 程序，会话不跨线程迁移。

`performance.udpSockmapAcceleration` 控制该路径，语义与 TCP 版本相同（`enabled` / `disabled` / 默认 `auto`）。权限不足、内核不支持或单会话配对失败时逐层回退到用户态 relay，服务启动不受影响；重定向失败而落入用户态的零星报文由引擎兜底转发。热加载改变此项时，已有 UDP 会话会被清除并按新模式重建。

## 配置约束

- 当前版本只支持一条监听规则和一个上游。
- 所有超时单位均为秒，必须大于零，且不能超过 `9223372036` 秒。
- UDP 会话按客户端 IP 与端口隔离，空闲超过 `udpSessionSeconds` 后回收。
- 达到 `maxUDPAssociations` 后，新 UDP 客户端会被丢弃，已有会话不受影响；默认上限按系统内存自动计算。
- UDP 转发由独立 I/O 线程池以 `recvmmsg`/`sendmmsg` 批量收发（64 报文/批），会话在首个报文到达时同步建立，不存在待转发缓冲窗口；`maxUDPPendingDatagrams` 和 `maxUDPPendingBytes` 仅为兼容旧配置保留，当前不再使用。
- 程序不会终止 TLS、检查流量内容或记录转发数据正文。

## 测试

```bash
zig build test
```

默认测试不要求 eBPF 权限。eBPF loader 相关测试在无权限或内核不支持时会按预期跳过高权限路径。
