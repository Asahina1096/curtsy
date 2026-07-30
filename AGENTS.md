# AGENTS.md

本文件面向 AI 编码代理，介绍 Curtsy 项目的架构、构建方式与开发约定。阅读本文件前不需要任何项目背景知识。

## 项目概述

Curtsy 是一个使用 SwiftNIO 编写的 TCP/UDP 透明流量转发器（主要面向 Linux）。它在固定地址和端口上监听 TCP、UDP 或两种协议，并把流量转发到固定上游。当前版本只支持一条监听规则和一个上游，不终止 TLS、不检查流量内容、不记录转发数据正文。

- 语言与工具链：Swift 6（`swift-tools-version: 6.0`），Swift Package Manager。仅支持 Linux（代码无条件使用 Glibc 与 Linux 内核 API，不保留其他平台的编译期回退）。
- 关键配置清单：`Package.swift`（包定义）、`Package.resolved`（依赖锁定）、`config.example.yaml`（配置示例）。
- 运行时产物：单一可执行文件 `curtsy`（当前版本 0.1.0），无 CI 配置、无容器文件；`debian/` 目录提供 Debian 打包（含 `debian/curtsy.service` systemd 单元，以 `DynamicUser` + `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON`/`CAP_NET_BIND_SERVICE` 最小权限运行）。

## 构建与测试命令

需要 Swift 6 或更高版本：

```bash
swift build -c release      # 产物位于 .build/release/curtsy
swift test                  # 运行全部 XCTest 测试
swift test --filter ForwardingTests.testTCPRoundTrip   # 运行单个测试
```

运行与配置校验：

```bash
.build/release/curtsy --config config.yaml --check-config   # 校验配置后退出（配置错误退出码 2）
.build/release/curtsy --config config.yaml                  # 启动服务
```

## 技术栈与依赖

全部依赖均为 Swift 包（见 `Package.swift`）：

- `swift-nio`（NIOCore / NIOPosix / NIOConcurrencyHelpers）：事件循环与网络 I/O，是整个转发路径的基础；测试额外使用 `NIOEmbedded`。
- `swift-argument-parser`：命令行入口。
- `Yams`：YAML 配置解析。
- `swift-log`：日志（输出到 stderr）。
- `swift-atomics`：无锁计数（TCP 缓冲预算、日志级别阈值）。

## 代码组织

SwiftPM 标准布局，共两个源 target 和一个测试 target：

- `Sources/Curtsy/`：主可执行 target（同时作为库被测试 target `@testable import`）。
  - `CurtsyCommand.swift`：`@main` 入口，解析 `--config` / `--check-config`，引导日志系统。
  - `Configuration.swift`：YAML 配置模型（`ForwarderConfiguration`）、严格键白名单校验（未知键直接报错）与数值范围校验。所有超时单位为秒且必须大于零。
  - `RuntimeSupport.swift`：`ResolvedConfiguration`（地址解析）、`RuntimeConfiguration`（线程安全的配置快照）、`LogStore`（带原子阈值的日志门面）、`ChannelRegistry`（分片锁连接表）。
  - `ForwarderService.swift`：服务编排器。持有 `MultiThreadedEventLoopGroup`（线程数 = CPU 核数），处理 `SIGHUP` 热加载与 `SIGINT`/`SIGTERM` 优雅退出（最多等待 `shutdownGraceSeconds`）。
  - `TCPForwarder.swift`：`TCPListener`（每事件循环一个 `SO_REUSEPORT` 监听 socket）、`TCPFrontendHandler` / `TCPRelayHandler`（双向 relay、背压、`IdleStateHandler` 空闲超时）、`TCPBufferBudget`（全局用户态缓冲预算，默认 256 MiB）。
  - `UDPForwarder.swift`：`UDPListener`（按 `performance.udpIOThreads` 编排多个引擎，默认每 CPU 一个；首个引擎绑定后其余引擎以 `SO_REUSEPORT` 绑定同一具体地址）/ `UDPRelayEngine`（每个 I/O 线程用 epoll 管理自己的监听与上游 socket，`recvmmsg`/`sendmmsg` 批量收发，64 报文批次；按客户端四元组隔离会话，50ms 周期扫描空闲回收）、`UDPAssociationBudget`（所有引擎共享，保证 `maxUDPAssociations` 是全局上限而非每线程配额）。
  - `TCPSockmapAccelerator.swift` / `UDPSockmapAccelerator.swift` / `ReusePortBPF.swift`：eBPF 加速路径的 Swift 封装（TCP/UDP sockmap 内核转发、reuseport 分流程序）。loader 失败（无权限、内核不支持）时抛错，由调用方回退到用户态路径。
- `Sources/CBPFSupport/`：C target，直接调用 `bpf()` syscall 加载 eBPF 程序并管理 `BPF_MAP_TYPE_SOCKHASH`，头文件在 `include/CBPFSupport.h`。Swift 侧通过它创建/配对/解除 sockmap 连接并查询空闲剩余时间；UDP sockmap 使用仅 verdict 的 SK_SKB 程序（`BPF_SK_SKB_VERDICT`，需内核 ≥ 5.12），复用与 TCP 相同的 cookie 配对与活动时间戳逻辑。另封装 UDP 批量 I/O（`recvmmsg`/`sendmmsg`）与 epoll/eventfd/UDP socket 创建（监听与 per-client connected socket 均带 `SO_REUSEPORT`，多引擎共享端口）及 `curtsy_udp_set_socket_buffers`（SO_RCVBUF/SO_SNDBUF）等类型敏感的原语，Swift 侧不直接碰这些 C 类型。
- `Tests/CurtsyTests/`：XCTest 测试（见"测试策略"一节）。

## 运行时架构要点

- 热加载（`SIGHUP`）：监听地址变化时先绑新端口再停旧监听；失败则整体回滚到旧配置。已有 TCP 连接继续使用原上游，上游变化时已有 UDP 会话会被清除并按新配置重建。改变 TCP sockmap 模式时已有 TCP 连接保持原模式；改变 UDP sockmap 模式时已有 UDP 会话被清除并按新模式重建。
- 优雅退出：先停止 accept，等待已有 TCP 连接，超时（`shutdownGraceSeconds`）后强制关闭。
- TCP 性能：大块自适应读缓冲（单块上限 112 KiB，刻意低于 glibc 128 KiB mmap 阈值，避免每批读取的缺页/munmap 抖动）、批量 flush、水位线背压控制；多 worker 时通过 `SO_ATTACH_REUSEPORT_EBPF` 按连接四元组 hash 分流，失败时回退内核原生 `SO_REUSEPORT` hash。
- UDP 性能：I/O 线程池（`curtsy-udp-io`，默认每 CPU 一个，`performance.udpIOThreads` 可调）经 `SO_REUSEPORT` 共享监听端口，内核按四元组 hash 稳定分流；每线程用 epoll 驱动自己的监听与上游 socket，`recvmmsg`/`sendmmsg` 以 64 报文为一批收发；会话建立是同步的（UDP connect 无握手），不存在待转发缓冲窗口。监听、上游、per-client socket 均应用 `performance.udpSocketBufferBytes`（默认 4 MiB，无 CAP_NET_ADMIN 时被内核静默收敛到 rmem/wmem max，Debian 包通过 `usr/lib/sysctl.d/60-curtsy.conf` 提供 8 MiB 上限）。
- UDP sockmap 加速（`performance.udpSockmapAcceleration`，语义同 TCP）：首报文走用户态建会话，随后为该客户端创建 connect 到其地址的专用 socket（bind 到监听地址，带 `SO_REUSEPORT` 与监听 socket 保持一致，内核 demux 四元组精确匹配优先于通配 listener），与上游 socket 配对放入该引擎线程独立的 UDP 专用 sockhash；verdict 程序双向重定向到对端发送路径，数据面不再过用户态。会话过期改为读 BPF 活动时间；过期或解除配对后报文自动回落 listener 重建会话。配对失败的会话、verdict 未命中（SK_PASS）的报文均由用户态引擎兜底转发。改变此项配置时已有 UDP 会话被清除并按新模式重建。
- sockmap 加速（`performance.tcpSockmapAcceleration`）：`enabled` / `disabled` / `auto`（默认，对所有上游尝试启用，包括回环）。无权限或内核不支持时自动回退用户态 relay，不影响服务启动。sockmap 内核转发不占用用户态缓冲预算，BPF 记录双向最后活动时间，加速连接仍遵守 `tcpIdleSeconds`。
- 并发约定：跨线程共享状态使用 `NIOLockedValueBox` 或 `ManagedAtomic`；事件循环上的可变状态只在对应 `EventLoop` 上访问；关键类标注 `@unchecked Sendable`。

## 代码风格约定

- 遵循现有文件风格：4 空格缩进、`swift-tools-version` 默认格式化风格；类型用 `final class` / `struct`，按功能分文件。
- 代码注释和标识符使用英文；用户可见文档（README 等）使用中文。
- 日志格式为 `key=value` 拼接的纯文本，通过 `LogStore` 输出；新增日志点沿用该格式。
- 配置新增字段时：同步更新 `Configuration.swift` 中的模型、默认值、`ConfigurationLoader.allowedKeys` 白名单、`validate(_:)` 校验，以及 `config.example.yaml`。
- 资源管理：BPF 描述符、channel、budget 计数都必须成对释放；`TCPBufferBudget` / `UDPAssociationBudget` 带有 release 多于 acquire 的 `precondition`，改动转发路径时注意保持配对。

## 测试策略

- 使用 XCTest，测试通过 `@testable import Curtsy` 直接测内部类型，不走命令行。
- `ConfigurationTests.swift`：配置默认值、覆盖、未知键拒绝、数值范围校验、地址解析与 sockmap 模式判断。
- `ForwardingTests.swift`：基于 `MultiThreadedEventLoopGroup` 的真实回环网络测试（TCP/UDP 回显往返、缓冲预算、UDP 会话隔离与超时重载、多 I/O 线程共享端口与预算、backlog 原地更新、通配符双栈监听等），绑定 `127.0.0.1` 的 0 号端口，无需 root。
- 测试通过依赖注入隔离系统依赖：`TCPListener` 可注入 `enableSockmapAcceleration` 和 `loadSockmapAccelerator`，因此测试不触碰 eBPF；UDP 引擎直接跑真实回环收发。
- 新增功能应附带同风格测试；修改转发逻辑后运行完整 `swift test`。

## 安全注意事项

- 加载 eBPF（sockmap、reuseport 程序）通常需要 root 或 `CAP_BPF` / `CAP_NET_ADMIN`；代码必须在权限不足时优雅回退，不得让服务启动失败。
- 不读取、不记录转发数据的正文；日志只包含地址、字节数等元数据。
- 配置文件做严格校验：未知键报错、端口限制在 1–65535、超时必须为正，防止拼写错误静默生效。
- 用户态 TCP 缓冲受全局预算限制，防止大量慢速连接耗尽内存；改动预算逻辑时保持原子计数正确。
- 信号处理通过 `DispatchSourceSignal`，需先屏蔽默认信号行为；不要引入阻塞事件循环的操作。
