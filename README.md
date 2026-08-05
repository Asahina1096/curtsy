# Curtsy

Curtsy 是一个以 Zig 实现用户态、以 C 实现 eBPF 内核程序的 Linux 透明流量转发器，内置 TCP/UDP 数据面及规则、上游、CLI 等系统级模块。它在一个地址和端口上监听所配置的协议，并把流量转发到固定上游。

默认只运行一条监听规则和一个上游，不终止 TLS、不检查流量内容、不记录转发数据正文。配置中出现顶层 `rules` 列表时会启用可选的多规则模块：一个进程内运行多条独立的监听规则，每条规则可配置多个上游并做负载均衡。

## 构建

首次构建先准备仓库内工具链：

```bash
./tools/bootstrap-build-deps.sh
```

脚本下载经过校验的 Zig 0.16.0 和固定版本静态库到 `.toolchain/`。该目录
不提交到版本库。正常构建只使用这里的 Zig、Clang 前端、libbpf、libelf、
zlib 和 zstd，不读取 PATH 中的编译器，也不查找 `/usr/include` 或
`/usr/lib`。依赖缺失时构建会直接失败并提示运行 bootstrap。当前固定依赖
包支持 x86_64 Linux；bootstrap 自身需要 `curl`、`tar`、`dpkg-deb` 和
校验和工具，正常构建不调用这些命令。

eBPF C 使用 Zig 发行包内置的 Clang 前端，生成带 BTF 和重定位信息的
标准 BPF ELF；libbpf 及其依赖静态链接到 `curtsy`：

```bash
.toolchain/zig/zig build -Doptimize=ReleaseSafe
```

生成的程序位于 `zig-out/bin/curtsy`。默认按架构基线 CPU 编译，可在任意同架构机器上运行；如需针对本机优化可加 `-Dcpu=native`（产物可能无法在更老的 CPU 上运行）。

常用命令：

```bash
.toolchain/zig/zig build test
.toolchain/zig/zig build run -- --config config.yaml --check-config
.toolchain/zig/zig build run -- --config config.yaml
```

## Debian 打包

仓库包含 debhelper 打包元数据。先运行 bootstrap，再通过统一入口脚本构建
`.deb`；编译器和 BPF 相关依赖仍来自 `.toolchain/`：

```bash
./tools/build-deb.sh
```

脚本在仓库内 `dist/debian/` 生成 `.deb`、`.changes` 和 `.buildinfo`。构建会
执行 `.toolchain/zig/zig build -Doptimize=ReleaseSafe`，并在未设置
`DEB_BUILD_OPTIONS=nocheck` 时运行本地工具链测试；额外参数（如 `-nc`）会传给
`dpkg-buildpackage`。打包需要 `dpkg` >= 1.21（脚本使用的 `dpkg-buildpackage`
显式输出文件选项依赖该版本），版本不足时脚本会提前报错退出。

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

## 多规则与负载均衡（可选模块）

默认关闭。配置中出现顶层 `rules` 列表即启用，此时不能再使用顶层 `listen`/`upstream`。`version`、`timeouts`、`limits`、`logging`、`runtime`、`performance` 仍是全局配置，作为各规则的默认值：

```yaml
rules:
  - listen: { host: "*", port: 9000 }
    protocols: [tcp, udp]
    upstreams:
      - { host: "a.example.com", port: 9000 }
      - { host: "b.example.com", port: 9000, weight: 2 }
    balance: round_robin
    timeouts: { tcpIdleSeconds: 600 }        # 可选，规则级覆盖
    limits: { maxTCPBufferedBytes: 8388608 } # 可选，规则级覆盖
  - listen: { host: "127.0.0.1", port: 53 }
    protocols: [udp]
    upstreams: [ { host: "8.8.8.8", port: 53 } ]
```

- 每条规则独立监听一组地址，转发到自己的上游集合；两条规则不得共享同一监听地址和协议。
- `upstreams` 至少一个；`port` 省略时使用该规则的 `listen.port`，`weight` 默认为 1。
- `balance` 支持 `round_robin`（默认，TCP 按连接轮转，UDP 按客户端会话轮转）、`source_hash`（按客户端地址 hash，同一客户端固定落同一上游）、`weighted_round_robin`（按权重分配）。
- 上游健康检查是被动的：连续失败 3 次的上游会被摘除 10 秒，反复失败指数回退（上限 5 分钟），冷却结束后自动恢复并用真实流量探测；TCP connect 失败时会在连接内换下一个上游重试。
- `protocols`、`timeouts.connectSeconds`、`timeouts.tcpIdleSeconds`、`timeouts.udpSessionSeconds`、`limits.tcpListenBacklog`、`limits.maxTCPBufferedBytes`、`limits.maxUDPAssociations` 可按规则覆盖；`runtime`/`logging`/`performance` 不可按规则覆盖。
- `workerThreads`/`udpIOThreads` 为 auto 时按规则数均分（如 8 CPU、4 条规则 = 每规则 2 线程），显式整数不干预。
- 热加载按规则 diff：监听地址未变的规则原地更新（上游健康状态按地址继承），新增规则绑定成功后才退役被删除的规则；已有 TCP 连接保持原上游，UDP 会话在上游集合变化时重建。在 rules 与单规则两种写法之间切换需要重启进程。

## 命令行运行模式（可选模块）

默认关闭。不使用配置文件时，可用命令行简写直接指定监听与上游，与 `--config` 互斥（同时给出会报错退出）。简写会被渲染成 `rules:` 文档并走与多规则完全相同的引擎路径，因此默认值、校验和 SIGHUP 热重载都一致：

```bash
# 单规则简写（等价于一条 rules 规则）
curtsy --listen :9000 --upstream example.com
curtsy -l 127.0.0.1:53 -u 8.8.8.8 --protocols udp --balance source_hash

# 多规则简写（--rule 可重复）
curtsy --rule "listen=:9001,upstreams=a:9001,b:9001/weight=2" \
       --rule "listen=127.0.0.1:53,upstreams=8.8.8.8:53"

# 检查配置
curtsy --listen :9000 --upstream example.com --check-config

```

- 端点简写 `[HOST][:PORT]`：`:9000`/`9000` 表示监听全部地址；`[::1]:9000` 为方括号 IPv6 字面量；上游只写主机时端口取该规则监听端口。
- `--rule` 的值是逗号分隔的 `key=value`，`listen`（必填）与 `upstreams`（必填，`a:9001,b:9001/weight=2` 形式，支持 `/weight=N`）之外可带 `protocols=<names>` 与 `balance=<name>`。
- `--rule` 与 `--listen`/`--upstream`/`--protocols`/`--balance` 互斥；`--protocols`/`--balance` 只用于单规则简写。
- CLI 模式始终是 rules 模式；由于参数在进程生命周期内固定，SIGHUP 重载会重新校验规则并重新解析监听/上游主机名（DNS 变化生效），参数描述的集合本身不变。
- 全局 section（timeouts/limits/logging/runtime/performance）仍是 YAML 专属，命令行简写只覆盖端点类配置。

## 多实例运行

一台宿主机上可以同时运行多个相互独立的 curtsy 实例，每个实例有自己的配置文件、监听地址和热重载。实例只是一个进程身份：`--instance NAME` 只给每条日志加 `instance=NAME` 前缀（并设置进程名、用于 systemd 单元命名），不参与任何配置、路由或转发逻辑；字符集为 `[A-Za-z0-9._-]`，最长 64 字节，是 systemd 模板单元实例名合法字符集的安全子集。

systemd 模板单元（已随包安装）：

```bash
# 每个实例一个配置文件
sudo mkdir -p /etc/curtsy/instances
sudo install -m 0644 config.example.yaml /etc/curtsy/instances/edge.yaml
sudo install -m 0644 config.example.yaml /etc/curtsy/instances/dmz.yaml
sudo systemctl enable --now curtsy@edge curtsy@dmz
```

每个实例实际运行 `curtsy --instance %i --config /etc/curtsy/instances/%i.yaml`；原 `curtsy.service` 保持为默认单实例（使用 `/etc/curtsy/config.yaml`）。

命令行多实例：

```bash
curtsy --config edge.yaml --instance edge
curtsy --config dmz.yaml --instance dmz
```

端口共享：监听 socket 带 `SO_REUSEPORT`，但内核只把**相同 effective UID** 的 socket 分到同一组。systemd 模板的 `DynamicUser=true` 会给每个实例分配独立 uid，因此两个实例无法共享同一 `地址:端口`（后绑定者 bind 失败）；需要共享端口时须固定 `User=`（或去掉 `DynamicUser` 以同一用户运行）。共享端口是有意的水平伸缩（内核/BPF 分流），不是自动冲突检测；共享时建议各实例 `workerThreads` 一致，避免 reuseport eBPF（按各自 worker 数取模）与内核 hash 混用导致分布不均。

资源规划：auto 的 `workerThreads` 与限额按每实例独立取满计算，tuning daemon 又读取全局 `/proc/net/netstat`，多实例会互相叠加；建议多实例部署时显式配置 worker 数与限额。

eBPF：observer kprobe 按实例自身 pid 过滤，sockmap/reuseport 程序按进程/socket 装载，多个实例互不冲突。

## 信号

- `SIGHUP`：重新读取并应用配置。若配置文件自上次成功加载以来未被修改（mtime 与大小一致），重载是 no-op：只记录一条日志并跳过解析/校验/应用全部阶段，因此误发的 `systemctl reload` 近乎零成本；`touch` 或编辑文件（mtime 变化）都会照常触发全量重载，主机名照常重新解析（DNS 变化生效）。注意判定基于文件系统时间戳粒度（ext4 约 1ms），编辑与重载间隔极短（亚毫秒级）的自动化可能被判定为未修改。重载是事务式的：新规则和新增协议监听会先绑定但保持暂停（不接受 TCP、不转发 UDP），连同上游 generation 和 listen backlog 预检全部就绪后才提交并激活；任一失败则整体保留旧配置，候选配置正常释放。配置无效或新端口绑定失败时继续使用旧配置。同一时刻到达的多个 SIGHUP 会合并为一次重载。
- `SIGINT` / `SIGTERM`：停止监听并优雅退出。现有 TCP 连接最多等待 `shutdownGraceSeconds`。

热加载后，已有 TCP 连接继续使用原上游，新连接使用新上游；上游变化时已有 UDP 映射会被清除并按新配置重建。

## 内置系统模块

Curtsy 当前的 CLI、rules、upstream、balancer、TCP/UDP 协议实现都是系统级内置模块，随主程序一起编译，并通过 `src/module.zig` 中的 comptime 注册表确定模块集合和顺序。新增模块需要修改源码、注册并重新构建 `curtsy`。

SIGHUP 热重载只重新解析配置，并事务式替换规则、监听器和上游 generation；它不会在运行时装载或卸载机器码。项目未来可能支持外部插件，但当前不提供共享库 ABI、`plugins:` 配置项、`--plugin` 参数或外部插件兼容性承诺。

## TCP 性能

TCP 转发路径使用每 worker 一个 epoll loop：每个 worker 持有 `SO_REUSEPORT` 监听 socket，连接和对应上游 socket 固定在同一线程。普通用户态 relay 优先使用每 worker 一个非阻塞 pipe，通过 `splice(2)` 完成 socket→pipe→socket 零拷贝；目标端产生背压时，pipe 中剩余数据会回退到原有的用户态缓冲队列。读缓冲采用 64 KiB 到 1 MiB 的自适应块（pipe 容量按需增长，权限受限时会停留在内核允许的较小值），配合批量 flush 和水位线背压控制；splice 与 buffered 两条 relay 路径每次就绪事件最多搬移 2 MiB（每个 read 请求按剩余预算截断，避免单次超大请求越界），防止单条热连接独占 worker。待发送数据受全局 `limits.maxTCPBufferedBytes` 约束，防止大量慢速连接耗尽进程内存。worker 在一次 epoll 唤醒内复用同一个单调时钟时间戳，避免为每个数据块重复调用 `clock_gettime`。

多 worker 时，Curtsy 会尝试通过 `SO_ATTACH_REUSEPORT_EBPF` 加载 reuseport eBPF 程序，按连接四元组 hash 分流到对应 worker。失败时回退到内核原生 `SO_REUSEPORT` hash，不影响服务启动。

### CPU 亲和

默认情况下线程调度交给内核。需要更好 cache 局部性的多核/NUMA 主机可以用 `performance.threadCpuAffinity` 把 TCP worker 与 UDP I/O 线程固定到 CPU：`none`（默认）不绑定；`sequential` 把线程 i 绑到允许的第 i 个 CPU；也可写 CPU 列表如 `[0, 2, 4]`，线程 i 绑到 `list[i % len]`。绑定在启动期一次完成（线程数变化需重启），失败只记 warning、线程照常运行；共享机器上盲目绑定可能劣化，建议用 `tools/benchmark` 实测对比。

在具备 eBPF 权限的 Linux 上，Curtsy 还可创建 `BPF_MAP_TYPE_SOCKHASH`，并为每对客户端/上游 TCP socket 挂载 `SK_SKB` stream parser 与 verdict 程序。双向数据通过 `bpf_sk_redirect_hash` 在内核中直接转发，绕过用户态 relay 的 `tcp_recvmsg`、`tcp_sendmsg` 和用户缓冲区复制。BPF 同时记录双向最后活动时间，因此加速连接仍遵守 `tcpIdleSeconds`。

`performance.tcpSockmapAcceleration` 控制该路径：`enabled` 强制尝试启用，`disabled` 始终使用用户态 relay，默认的 `auto` 跳过 loopback 上游（该场景下 SK_SKB/sockhash 的逐包成本可能高于用户态 relay）。权限不足、内核不支持或单连接 sockhash 配对失败时，Curtsy 会记录日志并自动回退到用户态 relay。

sockmap 是否更快取决于数据路径。跨主机、高 RTT 或 CPU 受限环境通常更可能受益；loopback 和部分小包场景中，SK_SKB/sockhash 的逐包成本可能高于用户态 relay。部署前应使用实际网卡、包大小和 RTT 分别压测 `enabled` 与 `disabled`，不要仅根据本机回环结果选择。

常驻 tuning daemon 默认启用。它会优先加载 eBPF kprobe observer，观测当前 Curtsy 进程触发的 TCP/UDP send/recv 内核调用，并结合 `/proc/net/netstat` 的监听队列溢出计数和 Curtsy 内部 TCP/UDP 使用量持续调参。当前版本只调整 Curtsy 自己的运行时限额，不写系统 sysctl；如果 eBPF observer 加载失败，会降级使用内部计数和 `/proc`，服务继续运行。

高 RTT 链路需要足够大的系统 TCP 自动调优上限。例如 1 Gbps、100 ms RTT 的链路至少需要约 12.5 MB 的 TCP 窗口，可按部署环境检查并调整 `net.ipv4.tcp_rmem`、`net.ipv4.tcp_wmem`、`net.core.rmem_max` 和 `net.core.wmem_max`。Curtsy 不会自行覆盖这些系统级参数。

## UDP 性能

UDP 转发由独立 I/O 线程池驱动（默认每 CPU 一个线程，可用 `performance.udpIOThreads` 固定）：每个线程持有一个经 `SO_REUSEPORT` 绑定同一地址的监听 socket，内核按客户端四元组 hash 把流量稳定分流到固定线程——即一个 UDP 五元组会话始终固定到同一个引擎，不跨线程迁移。各线程用 epoll 管理自己的监听与上游 socket，收发均以 64 报文为一批。收到就绪事件后，引擎用非阻塞 `recvmmsg` 连续聚合：把多次 syscall 收到的报文合并成一批（最多 64 报文）再 `sendmmsg` 转发，一次就绪事件内最多执行 16 次 `recvmmsg`（公平配额），因此热 socket 可在单次就绪事件内转发多个 64 报文批，同时不会饿死同引擎其他就绪 socket。会话在首个报文到达时同步建立。`maxUDPAssociations` 由所有线程共享，仍是全局上限而不是每线程配额。

UDP 高吞吐场景下，内核默认的 208 KiB socket 缓冲经常是最先触顶的瓶颈。`performance.udpSocketBufferBytes`（默认 4 MiB，设为 `0` 保持内核默认）会应用到监听、上游和每客户端 socket 的收发缓冲；没有 `CAP_NET_ADMIN` 时内核会把请求静默收敛到 `net.core.rmem_max` / `net.core.wmem_max`，因此建议部署时同步调大这两个 sysctl（Debian 包自带 `usr/lib/sysctl.d/60-curtsy.conf`，把两者设为 8 MiB）。

在具备 eBPF 权限且内核 >= 5.12 的 Linux 上，Curtsy 还可以为 UDP 会话启用 sockmap 内核转发：首个报文仍由用户态建立会话，随后为该客户端创建一个 connect 到其地址的专用 socket，并把客户端 socket 与上游 socket 配对放入 `BPF_MAP_TYPE_SOCKHASH`；`SK_SKB` verdict 程序用 `bpf_sk_redirect_hash` 把两个方向的报文直接转发到对端发送路径，不再经过用户态。每个 I/O 线程持有独立的 sockhash 与 verdict 程序，会话不跨线程迁移。

`performance.udpSockmapAcceleration` 控制该路径（`enabled` / `disabled` / 默认 `auto`）。UDP `auto` 从稳定的用户态 `recvmmsg`/`sendmmsg` 批量路径启动；只有非 loopback 上游连续 5 个一秒窗口达到每窗口至少 200 个报文、平均报文至少 256 字节时，才会尝试 sockmap。加载失败、连续配对失败或加速后仍持续有大量报文回落用户态时，会关闭 sockmap 并冷却 30 秒后重新观测，因此 loopback、小包和不稳定负载保持用户态路径。`enabled` 强制尽力尝试，`disabled` 始终关闭；sockmap 不承诺报文顺序。权限不足、内核不支持或单会话配对失败时安全回退，不影响服务启动。热加载从 `enabled` 切到 `auto`/`disabled`，或 `auto` 切到 loopback 上游时，会在发布新配置前同步禁止新会话进入 sockmap，再由 I/O 线程按“先解绑会话、后销毁 runtime”的顺序完成切换，并把控制器重置为可重新探测的用户态状态；`auto` 配置不变且仍非 loopback 的重载（例如 tuning 守护进程的限额微调）会保留已加载的 runtime 和自适应状态，不会中断加速。

## 配置约束

- 默认只支持一条监听规则和一个上游；多规则与多上游需使用可选的 `rules` 写法（见上文）。
- 所有超时单位均为秒，必须大于零，且不能超过 `9223372036` 秒。
- UDP 会话按客户端 IP 与端口隔离，空闲超过 `udpSessionSeconds` 后回收。
- 达到 `maxUDPAssociations` 后，新 UDP 客户端会被丢弃，已有会话不受影响；默认上限按系统内存自动计算。
- UDP 转发由独立 I/O 线程池以 `recvmmsg`/`sendmmsg` 批量收发（64 报文/批），就绪事件内用非阻塞 `recvmmsg` 合并聚合报文并转发多个 64 报文批，单次就绪最多 16 次接收 syscall；每个客户端五元组会话固定到一个 `SO_REUSEPORT` 引擎，会话在首个报文到达时同步建立，不存在待转发缓冲窗口；`maxUDPPendingDatagrams` 和 `maxUDPPendingBytes` 仅为兼容旧配置保留，当前不再使用。
- 程序不会终止 TLS、检查流量内容或记录转发数据正文。

## 测试

```bash
# 运行完整测试套件
.toolchain/zig/zig build test

# 仅编译测试（不执行），用于快速检查测试代码能否通过编译
.toolchain/zig/zig build test-compile

# 只运行名称包含指定子串的测试
.toolchain/zig/zig build test -Dtest-filter="socket address formatting"

# 真实加载并运行 eBPF 集成测试；权限或内核能力不足会明确失败
sudo .toolchain/zig/zig build test-ebpf
```

默认测试不要求 eBPF 权限，高权限路径会跳过；`test-ebpf` 是独立入口，会设置严格门禁并在缺少 `CAP_BPF`/`CAP_NET_ADMIN` 或内核支持时失败。`test-compile` 与 `test` 共用同一个测试二进制（含 `-Dtest-filter` 过滤），区别仅在于是否执行。
