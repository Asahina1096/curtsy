# AGENTS.md

本文件面向 AI 编码代理，介绍 Curtsy 项目的架构、构建方式与开发约定。阅读本文件前不需要任何项目背景知识。

## 项目概述

Curtsy 是一个使用 Zig 编写的 TCP/UDP 透明流量转发器，仅支持 Linux。它在固定地址和端口上监听 TCP、UDP 或两种协议，并把流量转发到固定上游。当前版本只支持一条监听规则和一个上游，不终止 TLS、不检查流量内容、不记录转发数据正文。

- 语言与工具链：Zig 0.16+。代码无条件使用 Linux syscall、epoll、eventfd、signalfd、recvmmsg/sendmmsg 与 eBPF API，不保留其他平台的编译期回退。
- 关键配置清单：`build.zig`（构建定义）、`config.example.yaml`（配置示例）。
- 运行时产物：单一可执行文件 `curtsy`（当前版本 0.3.1）；`debian/` 目录提供 Debian 打包（含 `debian/curtsy.service` systemd 单元，以 `DynamicUser` + `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON`/`CAP_NET_BIND_SERVICE` 最小权限运行）。

## 构建与测试命令

```bash
zig build -Doptimize=ReleaseSafe      # 产物位于 zig-out/bin/curtsy
zig build test                        # 运行全部 Zig 单元/回环测试
zig build run -- --config config.yaml --check-config
zig build run -- --config config.yaml
```

默认按架构基线 CPU 编译（`-mcpu baseline`），保证二进制可移植；本地开发想要本机优化时显式传 `-Dcpu=native`。

## 代码组织

- `src/main.zig`：命令行入口，解析 `--config` / `--check-config` / `--version` / `--help`，配置错误退出码为 2。
- `src/service.zig`：服务编排器。持有当前配置 arena，启动 TCP/UDP listener，处理 `SIGHUP` 热加载与 `SIGINT`/`SIGTERM` 优雅退出（最多等待 `shutdownGraceSeconds`）。
- `src/config.zig`：YAML 子集解析、配置模型、严格键白名单校验、数值范围校验、地址解析。所有超时单位为秒且必须大于零。
- `src/log.zig`：带原子阈值和 futex mutex 的日志门面，输出到 stderr。
- `src/autotune.zig`：CPU/内存自适应默认值公式。
- `src/tuning.zig`：常驻 tuning daemon，读取 eBPF observer 和 `/proc/net/netstat`，按压力调整自动限额。
- `src/tcp.zig`：TCP listener 和 relay。每 worker 一个 epoll loop、每监听地址一个 `SO_REUSEPORT` socket；用户态 relay 优先通过每 worker 非阻塞 pipe 使用 `splice(2)` 零拷贝，背压时回退预算缓冲；同时实现空闲超时、reuseport eBPF 和 TCP sockmap 加速。
- `src/udp.zig`：UDP listener 和 relay engine。多个 I/O 线程经 `SO_REUSEPORT` 共享端口，每线程 epoll 管理监听、上游和 per-client socket，`recvmmsg`/`sendmmsg` 批量转发，支持 UDP sockmap 加速。
- `src/bpf.zig`：纯 Zig eBPF/syscall 封装，包含 sockhash map、SK_SKB parser/verdict 程序、reuseport 分流程序、BPF observer、UDP 批量 I/O 和 Linux socket/epoll/eventfd helper。

## 运行时架构要点

- 热加载（`SIGHUP`）：监听地址变化时先绑新端口再停旧监听；失败则整体回滚到旧配置。已有 TCP 连接继续使用原上游，上游变化时已有 UDP 会话会被清除并按新配置重建。改变 TCP sockmap 模式时已有 TCP 连接保持原模式；改变 UDP sockmap 模式时已有 UDP 会话被清除并按新模式重建。
- 优雅退出：先停止 accept，等待已有 TCP 连接，超时后强制关闭。
- TCP 性能：`splice(2)` socket→pipe→socket 零拷贝快路径，背压时回退 64..256 KiB 自适应读缓冲、批量 flush 和水位线控制；每次 epoll 唤醒复用单调时间戳。多 worker 时尝试 `SO_ATTACH_REUSEPORT_EBPF`，失败时回退内核原生 `SO_REUSEPORT` hash。
- UDP 性能：I/O 线程池（默认每 CPU 一个，`performance.udpIOThreads` 可调）经 `SO_REUSEPORT` 共享监听端口；每线程用 epoll 驱动自己的监听与上游 socket，`recvmmsg`/`sendmmsg` 以 64 报文为一批收发；会话建立是同步的。
- sockmap 加速：`performance.tcpSockmapAcceleration` / `performance.udpSockmapAcceleration` 支持 `enabled` / `disabled` / `auto`。权限不足、内核不支持或配对失败时自动回退用户态 relay，不影响服务启动。
- 并发约定：跨线程共享状态使用 `std.atomic.Value` 或 `log.Mutex`；worker/engine 私有可变状态只在对应线程上访问。

## 代码风格约定

- 遵循现有 Zig 风格：4 空格缩进，模块内按功能分 section，类型用 `struct`，错误集尽量显式。
- 代码注释和标识符使用英文；用户可见文档（README 等）使用中文。
- 日志格式为 `key=value` 拼接的纯文本，通过 `LogStore` 输出；新增日志点沿用该格式。
- 配置新增字段时：同步更新 `src/config.zig` 中的模型、默认值、allowed keys、validate 校验、配置测试，以及 `config.example.yaml`。
- 资源管理：BPF 描述符、socket fd、epoll fd、eventfd、budget 计数都必须成对释放；`TCPBufferBudget` / `UdpAssociationBudget` 的 release 多于 acquire 会触发 debug assertion。

## 测试策略

- 使用 Zig 内置 test，测试分布在对应 `src/*.zig` 文件末尾。
- `src/config.zig` 覆盖配置默认值、覆盖、未知键拒绝、数值范围校验、地址解析与 sockmap 模式判断。
- `src/tcp.zig` / `src/udp.zig` 使用真实回环网络测试 TCP/UDP 回显往返、缓冲预算、UDP 会话隔离与超时重载、多 I/O 线程共享端口与预算、backlog 原地更新、通配符双栈监听等；测试绑定 `127.0.0.1` 的 0 号端口，无需 root。
- 新增功能应附带同风格测试；修改转发逻辑后运行完整 `zig build test`。

## 安全注意事项

- 加载 eBPF（sockmap、reuseport 程序）通常需要 root 或 `CAP_BPF` / `CAP_NET_ADMIN`；代码必须在权限不足时优雅回退，不得让服务启动失败。
- 不读取、不记录转发数据的正文；日志只包含地址、字节数等元数据。
- 配置文件做严格校验：未知键报错、端口限制在 1-65535、超时必须为正，防止拼写错误静默生效。
- 用户态 TCP 缓冲受全局预算限制，防止大量慢速连接耗尽内存；改动预算逻辑时保持原子计数正确。
- 信号处理通过 Linux `signalfd`，主线程屏蔽 `SIGINT` / `SIGTERM` / `SIGHUP` / `SIGPIPE` 后进入控制循环；不要在 worker/engine epoll loop 中引入阻塞操作。
