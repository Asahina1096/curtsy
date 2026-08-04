# AGENTS.md

本文件面向 AI 编码代理，介绍 Curtsy 项目的架构、构建方式与开发约定。阅读本文件前不需要任何项目背景知识。

## 项目概述

Curtsy 是一个以 Zig 实现用户态、以 C 实现 eBPF 内核程序的透明流量转发器，仅支持 Linux。内置 TCP/UDP 数据面，运行时插件可按名称增加协议或覆盖内置实现。它在固定地址和端口上监听配置的协议，并把流量转发到固定上游。默认只运行一条监听规则和一个上游；配置出现顶层 `rules` 列表时启用可选的多规则模块（多监听规则 + 规则内多上游负载均衡）。不终止 TLS、不检查流量内容、不记录转发数据正文。

- 语言与工具链：仓库内 `.toolchain` 固定 Zig 0.16.0 和 libbpf/libelf/zlib/zstd 静态依赖；eBPF 内核程序位于 `src/ebpf/*.bpf.c`，由 Zig 发行包内置的 Clang 前端在构建期编译为标准 BPF ELF。正常构建不从 PATH、`/usr/include` 或 `/usr/lib` 解析依赖。用户态代码无条件使用 Linux syscall、epoll、eventfd、signalfd、recvmmsg/sendmmsg 与 eBPF API，不保留其他平台的编译期回退。
- 关键配置清单：`build.zig`（构建定义）、`config.example.yaml`（配置示例）。
- 运行时产物：单一可执行文件 `curtsy`（当前版本 0.3.2）；`debian/` 目录提供 Debian 打包元数据（含 `debian/curtsy.service` systemd 单元，以 `DynamicUser` + `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON`/`CAP_NET_BIND_SERVICE` 最小权限运行）。打包统一入口是 `tools/build-deb.sh`，最终产物（`.deb`/`.changes`/`.buildinfo`）落在仓库内 `dist/debian/`。

## 构建与测试命令

```bash
./tools/bootstrap-build-deps.sh       # 首次构建或更新固定依赖时运行
.toolchain/zig/zig build -Doptimize=ReleaseSafe
.toolchain/zig/zig build test
.toolchain/zig/zig build run -- --config config.yaml --check-config
.toolchain/zig/zig build run -- --config config.yaml
./tools/build-deb.sh                  # Debian 打包，产物在 dist/debian/
```

默认按架构基线 CPU 编译（`-mcpu baseline`），保证二进制可移植；本地开发想要本机优化时显式传 `-Dcpu=native`。

## 代码组织

整体参考 nginx 模块架构：`src/module.zig` 是 `ngx_module_t`/`ngx_modules[]` 的对应物，`src/conf.zig` 是 `ngx_conf_file` 的对应物（配置引擎），每个功能是一个注册进 comptime 注册表的模块。模块声明自己的指令表（`Directive`，对应 `ngx_command_t`，带 root/rule 上下文）和 conf 生命周期钩子：`createConf`（默认值）→ 指令 `set` → `finalize`（跨键解码，如 upstream.port 默认取 listen.port）→ `validate`。有 rule 上下文的模块再实现 `createRuleConf`，由 rules 模块驱动嵌套分发，core 模块把规则级覆盖 merge 到全局配置上（对应 `merge_conf`）。

基础设施（src/ 根）：

- `src/main.zig`：命令行入口。一次运行就是一个配置 cycle：`conf.loadFile` 解析并校验 → `core.resolveForwarder` 解析地址 → `core.ForwarderService.run()`。配置错误退出码为 2。
- `src/module.zig`：`Module`/`Directive` 类型、模块注册表（comptime 模块类型列表 `module_types` 为唯一排序来源，据此生成每条模块引用 `ModuleRef`，含描述符指针与 conf slot 下标）、指令查找、协议模块注册表。
- `src/conf.zig`：配置引擎（Cycle）。解析 YAML → 各模块 createConf → 根键按指令表分发（未知键引擎直接拒绝，`rules` 与 `listen`/`upstream` 互斥在此检查）→ finalize → validate。rule 作用域经 `beginRule`/`dispatchMapping`/`endRule` 嵌套分发，每个规则产生一个 RuleBundle（各模块的规则级 conf slot）。
- `src/yaml.zig`：YAML 子集解析器与标量解码助手（纯机制，不含任何配置语义）。
- `src/net.zig`：`SocketAddr`、resolver（可注入测试）、listen 地址展开（`*` → 双栈通配对）、协议列表助手。
- `src/log.zig`：带原子阈值和 futex mutex 的日志门面，输出到 stderr。
- `src/autotune.zig`：CPU/内存自适应默认值公式。
- `src/bpf.zig`：eBPF/syscall 运行时封装，负责使用 libbpf 打开内嵌 BPF ELF、配置 map/只读常量、取得 FD、管理 link/object 生命周期，以及 sockhash 操作、UDP 批量 I/O 和 Linux socket/epoll/eventfd helper。
- `src/ebpf/`：C 编写的 eBPF 内核程序，包括 SK_SKB parser/verdict、reuseport 分流程序和 kprobe observer；Clang 产出的 ELF（含 BTF/重定位）嵌入 `curtsy`，运行时由 libbpf 加载。
- `src/libbpf_shim.c`：隔离 Zig 与 libbpf C API 的薄封装，避免在 Zig 侧复制 libbpf 结构布局。

模块（src/modules/）：

- `src/modules/core.zig`：核心模块（`ngx_core_module` 对应物）。拥有 `version`/`protocols`/`listen`/`upstream` 根指令（单规则语法糖，resolve 时合成为一条规则）、组合配置模型（`ForwarderConfiguration`/`ResolvedConfiguration`/`ResolvedForwarder`）、地址解析与跨规则监听冲突检测、协议模块接口（`Listener` vtable + `ProtocolModule`）、统一编排器 `ForwarderService`（单 cycle 驱动 1..N 条规则；SIGHUP 跑新 cycle 后按规则 listen 地址集合 diff，匹配规则原地更新、新规则先绑定再退役旧规则；auto 线程数按规则数均分；tuning daemon 聚合各规则用量）。
- `src/modules/rules.zig`：`rules` 根指令与规则内 `listen`/`upstreams`/`protocols`/`balance` 指令、规则模型与校验。
- `src/modules/cli.zig`：命令行运行模式模块（可选、默认关闭）。解析 `--listen`/`--upstream`（单规则简写）、可重复的 `--rule`/`--plugin`，以及归属最近插件的 `--plugin-config key=value`，把简写渲染成含可选 `plugins:` 与 `rules:` 的 YAML 文档后走 `conf.loadYaml`，因此 CLI 规则复用插件配置事务、rules 解码/校验/默认值与 core 编排器的 SIGHUP 热重载；命令行简写早校验端口/weight 和名字语法，动态协议/balancer 的存在性在插件加载后的 resolve 阶段校验。`src/main.zig` 在同时给出 `--config` 与 CLI 端点/plugin flag 时报错退出（互斥）。
- `src/plugin.zig` / `src/modules/plugins.zig`：运行时共享库插件管理器与 `plugins` 配置模块。插件使用 `include/curtsy_plugin.h` 的版本化 C ABI；候选重载先初始化新增插件，转发配置提交后再退役被移除插件。ABI v1 支持生命周期、日志、opaque context、动态 balancer、按名称增加协议或覆盖内置 TCP/UDP，以及 `plugins[].config` 扁平标量 mapping 的 `prepare`/`commit`/`discard` 事务；upstream generation 和动态 listener 对插件持引用，引用归零后才 `deinit`/`dlclose`。协议插件获得稳定 selector（选路及健康上报）和可选累计 metrics 回调。
- `src/modules/timeouts.zig` / `limits.zig` / `logging.zig` / `runtime.zig` / `performance.zig`：各配置 section 模块。timeouts/limits 同时有 root 和 rule 上下文（规则级为覆盖项，`merge()` 应用到全局值上并清掉对应 auto 标记）。
- `src/modules/upstream.zig`：上游框架（`ngx_upstream` 对应物）。`UpstreamPool`（peer 状态：被动健康摘除，连续失败 3 次摘除 10 秒，指数回退上限 5 分钟，冷却自动恢复；热加载经 `rebind` 按地址继承健康；pool 对象地址稳定）、注入数据面的 `Selector` 钩子、balancer 注册表。
- `src/modules/balancer/round_robin.zig` / `source_hash.zig` / `weighted_round_robin.zig`：可插拔负载均衡模块，`balance:` 按名字经注册表选择。
- `src/modules/tcp.zig`：TCP 协议模块（listener 和 relay）。每 worker 一个 epoll loop、每监听地址一个 `SO_REUSEPORT` socket；用户态 relay 优先 `splice(2)` 零拷贝，背压回退预算缓冲；空闲超时、reuseport eBPF、TCP sockmap 加速。多上游时经 `Selector` 按连接选路、connect 失败故障转移并上报健康；selector 为 null（单上游）时行为与固定上游完全一致。
- `src/modules/udp.zig`：UDP 协议模块（listener 和 relay engine）。多个 I/O 线程经 `SO_REUSEPORT` 共享端口，每线程 epoll 管理监听、上游和 per-client socket，`recvmmsg`/`sendmmsg` 批量转发，UDP sockmap 加速；多上游时按会话选路，ICMP 错误上报并触发摘除。
- `src/modules/tuning.zig`：常驻 tuning daemon，读取 eBPF observer 和 `/proc/net/netstat`，按压力调整自动限额；由 core 编排器驱动。

## 运行时架构要点

- 热加载（`SIGHUP`）：监听地址变化时先绑新端口再停旧监听。重载是事务式的：所有可失败操作（新规则绑定、上游 generation 准备、新增协议监听、listen backlog 预检）先全部准备好；新 listener 在准备阶段保持暂停，不接受 TCP 或转发 UDP。任一失败则整体保留旧配置并正常释放候选 cycle；全部就绪后才提交、激活并退役旧规则。已有 TCP 连接继续使用原上游，上游变化时已有 UDP 会话会被清除并按新配置重建。改变 TCP sockmap 模式时已有 TCP 连接保持原模式；改变 UDP sockmap 模式时已有 UDP 会话被清除并按新模式重建。统一编排器按规则 listen 地址集合 diff（单规则即一条规则的特例）：匹配规则原地更新（pool 健康状态按地址继承），新规则先绑定再退役旧规则，单规则 ↔ 多规则写法切换需重启。
- 优雅退出：先停止 accept，等待已有 TCP 连接，超时后强制关闭。
- TCP 性能：`splice(2)` socket→pipe→socket 零拷贝快路径，背压时回退 64..256 KiB 自适应读缓冲、批量 flush 和水位线控制；每次 epoll 唤醒复用单调时间戳。多 worker 时尝试 `SO_ATTACH_REUSEPORT_EBPF`，失败时回退内核原生 `SO_REUSEPORT` hash。
- UDP 性能：I/O 线程池（默认每 CPU 一个，`performance.udpIOThreads` 可调）经 `SO_REUSEPORT` 共享监听端口；每线程用 epoll 驱动自己的监听与上游 socket，`recvmmsg`/`sendmmsg` 以 64 报文为一批收发；会话建立是同步的。
- sockmap 加速：`performance.tcpSockmapAcceleration` 的 `auto` 跳过 loopback 上游。UDP `auto` 从用户态批量 relay 启动，仅在非 loopback、连续 5 个一秒窗口达到每窗口 200 报文且平均至少 256 字节后尝试 sockmap；加载、配对或回落异常进入 30 秒冷却并安全退回用户态。`enabled` 强制尽力尝试，`disabled` 始终关闭；不承诺 UDP 报文顺序。
- 并发约定：跨线程共享状态使用 `std.atomic.Value` 或 `log.Mutex`；worker/engine 私有可变状态只在对应线程上访问。

## 代码风格约定

- 遵循现有 Zig 风格：4 空格缩进，模块内按功能分 section，类型用 `struct`，错误集尽量显式。
- 代码注释和标识符使用英文；用户可见文档（README 等）使用中文。
- 日志格式为 `key=value` 拼接的纯文本，通过 `LogStore` 输出；新增日志点沿用该格式。
- 配置新增字段时：同步更新所属模块（`src/modules/`）的指令表、conf 类型、默认值、validate 校验与配置测试，以及 `config.example.yaml`；新增配置 section 时应新建一个模块并注册进 `src/module.zig`。
- 资源管理：BPF 描述符、socket fd、epoll fd、eventfd、budget 计数都必须成对释放；`TCPBufferBudget` / `UdpAssociationBudget` 的 release 多于 acquire 会触发 debug assertion。

## 测试策略

- 使用 Zig 内置 test，测试分布在对应源文件末尾。
- `src/conf.zig` 覆盖引擎级行为（未知键拒绝、`rules` 与 `listen`/`upstream` 互斥、重复键首个生效、非 mapping 根）；`src/modules/core.zig` 覆盖单规则默认值、覆盖、数值范围、地址解析、sockmap 模式与跨规则监听冲突；`src/modules/rules.zig` 覆盖规则解析、索引路径未知键、范围校验与 merge 语义。
- `src/modules/upstream.zig` 覆盖三种选路策略、摘除阈值与冷却恢复、全摘除回退、单上游退化、`rebind` 健康继承与 balancer 注册表。
- `src/modules/tcp.zig` 使用真实回环网络测试 TCP 回显往返、缓冲预算、UDP 会话隔离与超时重载、多 worker 共享端口与预算、backlog 原地更新、通配符双栈监听等；selector 钩子测试覆盖按连接选路、故障转移与摘除。
- `src/modules/udp.zig` 使用回环 UDP echo 测试 selector 按会话选路、ICMP 错误上报与摘除后重选。测试绑定 `127.0.0.1` 的 0 号端口，无需 root。
- 新增功能应附带同风格测试；修改转发逻辑后运行完整 `.toolchain/zig/zig build test`。真实 eBPF 集成测试使用 `sudo .toolchain/zig/zig build test-ebpf`，缺少权限或内核支持时必须失败，不能静默跳过。

## 安全注意事项

- 加载 eBPF（sockmap、reuseport 程序）通常需要 root 或 `CAP_BPF` / `CAP_NET_ADMIN`；代码必须在权限不足时优雅回退，不得让服务启动失败。
- 不读取、不记录转发数据的正文；日志只包含地址、字节数等元数据。
- 配置文件做严格校验：未知键报错、端口限制在 1-65535、超时必须为正，防止拼写错误静默生效。
- 用户态 TCP 缓冲受全局预算限制，防止大量慢速连接耗尽内存；改动预算逻辑时保持原子计数正确。
- 信号处理通过 Linux `signalfd`，主线程屏蔽 `SIGINT` / `SIGTERM` / `SIGHUP` / `SIGPIPE` 后进入控制循环；不要在 worker/engine epoll loop 中引入阻塞操作。
