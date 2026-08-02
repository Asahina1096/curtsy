//! TCP forwarding core.
//!
//! Each worker thread runs its own level-triggered epoll loop and holds one
//! SO_REUSEPORT listen socket per listen address (dual-stack when listen.host
//! is "*"). Accepted clients and their upstream connections live on the same
//! worker loop. The relay provides:
//!
//! - adaptive read chunks of 64 KiB..1 MiB, a per-worker splice(2) zero-copy
//!   fast path, and buffered fallback when the destination applies
//!   backpressure; both paths move at most 2 MiB per readiness event;
//! - watermark backpressure: reading from a peer pauses when the outbound
//!   queue exceeds 2 MiB and resumes below 1 MiB;
//! - a global TCPBufferBudget caps queued userspace bytes across all workers;
//! - tcp_idle_seconds closes connections with no read/write activity;
//! - TCP sockmap acceleration (auto/enabled/disabled; auto tries every
//!   upstream including loopback) with per-connection fallback to the
//!   userspace relay, idle enforced through the BPF activity timestamps;
//! - existing connections keep their upstream and acceleration mode across
//!   configuration reloads.
//!
//! SIGPIPE is avoided by using MSG_NOSIGNAL on every send. All cross-thread
//! shared state lives behind atomics or the listener state mutex; per-worker
//! connection state is only touched by that worker thread.

const std = @import("std");
const linux = std.os.linux;
const bpf = @import("../bpf.zig");
const config = @import("core.zig");
const upstream = @import("upstream.zig");
const autotune = @import("../autotune.zig");
const log = @import("../log.zig");

const Allocator = std.mem.Allocator;
const fd_t = linux.fd_t;

const allocator = std.heap.c_allocator;

/// Errno of the most recent failed syscall on this thread, for log messages
/// and start() diagnostics (same convention as bpf.lastErrno).
pub threadlocal var lastErrno: linux.E = .SUCCESS;

fn failWith(e: linux.E) Error {
    lastErrno = e;
    return error.SystemCall;
}

const Error = error{SystemCall};

/// Read buffers are allocated once per worker, so larger chunks reduce
/// syscall pressure without creating per-read allocator churn. The splice
/// path also uses max_read_chunk as the F_SETPIPE_SZ growth target: the
/// kernel pipe usually adopts it, and GETPIPE_SZ records the actual value
/// when an unprivileged process is capped below it.
const min_read_chunk: usize = 64 * 1_024;
const initial_read_chunk: usize = 128 * 1_024;
const max_read_chunk: usize = 1 * 1_024 * 1_024;

/// At most one full read batch per readiness event (buffered fallback).
const max_reads_per_event: usize = 8;

/// Cap on bytes moved by either relay path per readiness event. Without it
/// the buffered path could move up to 8 MiB (8 reads of a grown 1 MiB chunk)
/// when direct writes keep the pending queue empty, and the splice path could
/// overshoot by nearly a full chunk. Both loops clamp each request to the
/// remaining budget so one hot connection cannot monopolize the worker;
/// small-pipe hosts reach the same byte cap through more, smaller splice
/// iterations.
const max_relay_bytes_per_event: usize = 2 * 1_024 * 1_024;

/// Backpressure watermarks for the per-connection outbound queue. One full
/// read batch stays below the high watermark with hysteresis above the low
/// watermark so a batch never toggles the read registration.
const write_buffer_low_watermark: usize = 1 * 1_024 * 1_024;
const write_buffer_high_watermark: usize = 2 * 1_024 * 1_024;

/// Shrink an idle outbound queue beyond this capacity.
const pending_shrink_capacity: usize = 256 * 1_024;

const max_accept_per_event: usize = 128;
const sweep_interval_ns: u64 = 1_000_000_000;
const max_events_per_wait: usize = 1024;
/// Connections kept in the worker-local reuse pool to avoid malloc/free churn
/// on short-lived connection bursts.
const max_pooled_connections: usize = 256;

const splice_f_move: u32 = 0x01;
const splice_f_nonblock: u32 = 0x02;
const splice_f_more: u32 = 0x04;

fn monotonicNowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn secondsToNs(seconds: i64) u64 {
    return @as(u64, @intCast(seconds)) * 1_000_000_000;
}

fn sleepNs(ns: u64) void {
    var ts = linux.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    while (linux.errno(linux.nanosleep(&ts, &ts)) == .INTR) {}
}

fn closeFd(fd: fd_t) void {
    _ = linux.close(fd);
}

fn spliceNonBlocking(fd_in: fd_t, fd_out: fd_t, len: usize, more: bool) usize {
    const flags = splice_f_move | splice_f_nonblock | (if (more) splice_f_more else 0);
    return linux.syscall6(
        .splice,
        @as(usize, @bitCast(@as(isize, fd_in))),
        0,
        @as(usize, @bitCast(@as(isize, fd_out))),
        0,
        len,
        flags,
    );
}

// ---------------------------------------------------------------------------
// TCPBufferBudget: global cap on queued userspace relay bytes
// ---------------------------------------------------------------------------

pub const TCPBufferBudget = struct {
    used_bytes: std.atomic.Value(i64),
    configured_limit: std.atomic.Value(i64),

    pub fn init(initial_limit: i64) TCPBufferBudget {
        std.debug.assert(initial_limit > 0);
        return .{
            .used_bytes = std.atomic.Value(i64).init(0),
            .configured_limit = std.atomic.Value(i64).init(initial_limit),
        };
    }

    pub fn tryAcquire(self: *TCPBufferBudget, byte_count: usize) bool {
        if (byte_count == 0) return true;
        const count: i64 = @intCast(byte_count);
        while (true) {
            const current = self.used_bytes.load(.monotonic);
            const current_limit = self.configured_limit.load(.monotonic);
            if (current > current_limit or count > current_limit - current) return false;
            if (self.used_bytes.cmpxchgWeak(current, current + count, .monotonic, .monotonic) == null) {
                return true;
            }
        }
    }

    pub fn release(self: *TCPBufferBudget, byte_count: usize) void {
        if (byte_count == 0) return;
        const count: i64 = @intCast(byte_count);
        const previous = self.used_bytes.fetchSub(count, .monotonic);
        std.debug.assert(previous >= count); // released more than acquired
    }

    pub fn updateLimit(self: *TCPBufferBudget, new_limit: i64) void {
        std.debug.assert(new_limit > 0);
        self.configured_limit.store(new_limit, .monotonic);
    }

    pub fn limit(self: *const TCPBufferBudget) i64 {
        return self.configured_limit.load(.monotonic);
    }

    pub fn used(self: *const TCPBufferBudget) i64 {
        return self.used_bytes.load(.monotonic);
    }
};

// ---------------------------------------------------------------------------
// TCPSockmapAccelerator: refcounted wrapper over the TCP sockmap runtime
// ---------------------------------------------------------------------------

/// Owns the TCP sockhash/peer maps and the attached SK_SKB stream parser and
/// verdict programs. Reference counted because existing connections keep
/// using it after a reload swaps the listener's accelerator.
pub const TCPSockmapAccelerator = struct {
    /// Each proxied TCP connection consumes two map entries.
    pub const default_max_entries: u32 = 131_072;

    runtime: bpf.SockmapRuntime,
    refs: std.atomic.Value(u32),

    pub fn load(max_entries: u32, verifier_log: ?[]u8) (bpf.Error || Allocator.Error)!*TCPSockmapAccelerator {
        var runtime = try bpf.SockmapRuntime.createTcp(max_entries, verifier_log);
        errdefer runtime.destroy();
        const self = try allocator.create(TCPSockmapAccelerator);
        self.* = .{
            .runtime = runtime,
            .refs = std.atomic.Value(u32).init(1),
        };
        return self;
    }

    pub fn retain(self: *TCPSockmapAccelerator) void {
        _ = self.refs.fetchAdd(1, .acq_rel);
    }

    pub fn release(self: *TCPSockmapAccelerator) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) {
            self.runtime.destroy();
            allocator.destroy(self);
        }
    }

    /// Pairs a client socket with its upstream socket inside the kernel.
    pub fn pair(self: *TCPSockmapAccelerator, client_fd: fd_t, upstream_fd: fd_t) bpf.Error!bpf.SockmapRuntime.Pairing {
        return self.runtime.pair(client_fd, upstream_fd);
    }

    pub fn unpair(self: *TCPSockmapAccelerator, pairing: bpf.SockmapRuntime.Pairing) void {
        self.runtime.unpair(pairing.client_cookie, pairing.upstream_cookie);
    }

    /// Remaining idle time in nanoseconds; 0 means the connection expired.
    pub fn idleRemainingNs(
        self: *TCPSockmapAccelerator,
        pairing: bpf.SockmapRuntime.Pairing,
        idle_timeout_ns: u64,
    ) bpf.Error!u64 {
        return self.runtime.idleRemainingNs(pairing.client_cookie, pairing.upstream_cookie, idle_timeout_ns);
    }
};

/// Injectable accelerator factory. Test overrides count invocations and/or fail the load.
pub const SockmapLoader = *const fn (context: ?*anyopaque) (bpf.Error || Allocator.Error)!*TCPSockmapAccelerator;

fn defaultSockmapLoader(context: ?*anyopaque) (bpf.Error || Allocator.Error)!*TCPSockmapAccelerator {
    _ = context;
    var verifier_log: [256 * 1_024]u8 = undefined;
    return TCPSockmapAccelerator.load(TCPSockmapAccelerator.default_max_entries, &verifier_log);
}

// ---------------------------------------------------------------------------
// TCPListener
// ---------------------------------------------------------------------------

/// Scalars captured from a ResolvedConfiguration. New connections snapshot
/// these at accept time; existing connections keep the values they were
/// created with, so reloads never migrate connections.
const ConfigSnapshot = struct {
    upstream: config.SocketAddr,
    connect_ns: u64,
    idle_ns: u64,
    sockmap_requested: bool,
};

/// Optional upstream-selection hook (upstream module). When set, each new
/// connection asks the selector for its upstream address instead of using
/// the configured one, immediate connect failures fail over to the next
/// pick, and outcomes are reported back for passive health tracking. When
/// null the listener behaves exactly as a single-upstream forwarder.
pub const UpstreamSelector = upstream.Selector;

/// How many upstreams a connection may try before the client is dropped.
const max_failover_attempts: usize = 3;

const ListenerState = struct {
    snapshot: ConfigSnapshot,
    accelerator: ?*TCPSockmapAccelerator,
};

pub const StartError = error{ OutOfMemory, StartFailed, SystemCall };

pub const TCPListener = struct {
    pub const Options = struct {
        /// 0 derives the worker count from autotune.workerThreads(
        /// runtime.worker_threads); a positive value pins it (tests use 2).
        worker_threads: usize = 0,
        /// Test override for the sockmap on/off decision. null follows the configuration.
        enable_sockmap_acceleration: ?bool = null,
        sockmap_loader: ?SockmapLoader = null,
        sockmap_loader_context: ?*anyopaque = null,
        /// Rules plugin hook; null keeps the fixed configured upstream.
        upstream_selector: ?UpstreamSelector = null,
    };

    logger: *log.LogStore,
    options: Options,
    /// Global userspace relay buffer budget; shared with the tuning daemon.
    budget: TCPBufferBudget,

    state_mutex: log.Mutex = .{},
    state: ListenerState,

    /// Own copy of the listen addresses from init time (start() binds these;
    /// reloads never rebind — the service layer swaps listeners instead).
    listen_addresses: []config.SocketAddr,
    configured_worker_threads: i64,

    workers: []Worker = &.{},
    listen_fds: []fd_t = &.{}, // [worker * listen_addresses.len + address]
    bound_addresses: []config.SocketAddr = &.{}, // one concrete address per listen address
    listen_socket_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    accepting: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    force_close: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    active_connections: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    backlog: std.atomic.Value(i32),
    started: bool = false,
    stopped: bool = false,

    /// Loads the sockmap accelerator up front: failures degrade to the userspace relay and are retried on reload.
    pub fn init(
        configuration: config.ResolvedConfiguration,
        logger: *log.LogStore,
        options: Options,
    ) error{OutOfMemory}!TCPListener {
        const requested = options.enable_sockmap_acceleration orelse configuration.shouldEnableTCPSockmap();
        const snapshot = ConfigSnapshot{
            .upstream = configuration.upstream_address,
            .connect_ns = secondsToNs(configuration.configuration.timeouts.connect_seconds),
            .idle_ns = secondsToNs(configuration.configuration.timeouts.tcp_idle_seconds),
            .sockmap_requested = requested,
        };

        var self = TCPListener{
            .logger = logger,
            .options = options,
            .budget = TCPBufferBudget.init(configuration.configuration.limits.max_tcp_buffered_bytes),
            .state = .{ .snapshot = snapshot, .accelerator = null },
            .listen_addresses = try allocator.dupe(config.SocketAddr, configuration.listen_addresses),
            .configured_worker_threads = configuration.configuration.runtime.worker_threads,
            .backlog = std.atomic.Value(i32).init(@intCast(configuration.configuration.limits.tcp_listen_backlog)),
        };
        errdefer allocator.free(self.listen_addresses);

        if (requested) {
            self.state.accelerator = self.tryLoadAccelerator();
        } else {
            logger.info("tcp sockmap acceleration disabled", .{});
        }
        return self;
    }

    pub fn deinit(self: *TCPListener) void {
        self.stop();
        self.state_mutex.lock();
        const accelerator_ref = self.state.accelerator;
        self.state.accelerator = null;
        self.state_mutex.unlock();
        if (accelerator_ref) |acc| acc.release();
        allocator.free(self.listen_addresses);
        allocator.free(self.listen_fds);
        allocator.free(self.bound_addresses);
        allocator.free(self.workers);
    }

    fn loader(self: *const TCPListener) SockmapLoader {
        return self.options.sockmap_loader orelse defaultSockmapLoader;
    }

    fn tryLoadAccelerator(self: *TCPListener) ?*TCPSockmapAccelerator {
        const accelerator_ref = self.loader()(self.options.sockmap_loader_context) catch |err| {
            self.logger.warning("tcp sockmap acceleration unavailable; using userspace relay error={s} errno={s}", .{
                @errorName(err), @tagName(bpf.lastErrno),
            });
            return null;
        };
        self.logger.info("tcp sockmap acceleration enabled", .{});
        return accelerator_ref;
    }

    fn workerCount(self: *const TCPListener) usize {
        if (self.options.worker_threads > 0) return self.options.worker_threads;
        const count = autotune.workerThreads(self.configured_worker_threads, .system());
        return @intCast(count);
    }

    /// Snapshot of the accept-time configuration; retains the accelerator so
    /// the connection can use it even if a reload disables sockmap later.
    fn currentSnapshot(self: *TCPListener) ListenerState {
        self.state_mutex.lock();
        defer self.state_mutex.unlock();
        const state = self.state;
        if (state.accelerator) |acc| acc.retain();
        return state;
    }

    /// Binds one SO_REUSEPORT listen socket per worker per listen address and
    /// spawns the worker threads. Port 0 binds propagate the concrete port to
    /// the remaining workers of the same address group (the IPv4 and IPv6
    /// wildcard groups may end up on
    /// different ports).
    pub fn start(self: *TCPListener) StartError!void {
        if (self.started) return;
        self.started = true;

        const address_count = self.listen_addresses.len;
        const worker_count = self.workerCount();
        const backlog = self.backlog.load(.acquire);

        self.workers = try allocator.alloc(Worker, worker_count);
        self.listen_fds = try allocator.alloc(fd_t, worker_count * address_count);
        self.bound_addresses = try allocator.alloc(config.SocketAddr, address_count);
        for (self.listen_fds) |*fd| fd.* = -1;

        var reuseport_prog: fd_t = -1;
        var balancer: []const u8 = if (worker_count > 1) "kernel-hash" else "single-worker";
        if (worker_count > 1) {
            var verifier_log: [64 * 1_024]u8 = undefined;
            reuseport_prog = bpf.loadReusePortBpf(@intCast(worker_count), &verifier_log) catch |err| blk: {
                self.logger.warning("tcp reuseport eBPF unavailable; using kernel hash workers={d} error={s} errno={s}", .{
                    worker_count, @errorName(err), @tagName(bpf.lastErrno),
                });
                break :blk -1;
            };
        }
        defer if (reuseport_prog >= 0) closeFd(reuseport_prog);

        var spawned: usize = 0;
        var initialized_workers: usize = 0;
        errdefer {
            for (self.workers[0..spawned]) |*worker| {
                worker.stopping.store(true, .release);
                if (worker.wake_fd >= 0) bpf.eventfdSignal(worker.wake_fd);
            }
            for (self.workers[0..spawned]) |*worker| {
                if (worker.thread) |thread| thread.join();
            }
            for (self.listen_fds) |fd| {
                if (fd >= 0) closeFd(fd);
            }
            for (self.workers[0..initialized_workers]) |*worker| {
                if (worker.epoll_fd >= 0) closeFd(worker.epoll_fd);
                if (worker.wake_fd >= 0) closeFd(worker.wake_fd);
                worker.closeSplicePipe();
                if (worker.read_buffer.len > 0) allocator.free(worker.read_buffer);
            }
            allocator.free(self.bound_addresses);
            allocator.free(self.listen_fds);
            allocator.free(self.workers);
            self.bound_addresses = &.{};
            self.listen_fds = &.{};
            self.workers = &.{};
            self.listen_socket_count.store(0, .release);
            self.started = false;
        }

        // Bind all listen sockets before spawning workers so bind failures
        // surface synchronously.
        for (self.listen_addresses, 0..) |listen_address, address_index| {
            for (0..worker_count) |worker_index| {
                const bind_address = if (worker_index == 0) listen_address else self.bound_addresses[address_index];
                const fd = try self.createListenSocket(bind_address, backlog);
                self.listen_fds[worker_index * address_count + address_index] = fd;
                if (worker_index == 0) {
                    self.bound_addresses[address_index] = socketName(fd) orelse {
                        lastErrno = .INVAL;
                        return error.StartFailed;
                    };
                }
            }

            if (reuseport_prog >= 0) {
                const first_fd = self.listen_fds[address_index];
                const attach_rc = linux.setsockopt(first_fd, linux.SOL.SOCKET, bpf.so_attach_reuseport_ebpf, std.mem.asBytes(&reuseport_prog), @sizeOf(fd_t));
                if (linux.errno(attach_rc) != .SUCCESS) {
                    self.logger.warning("tcp reuseport eBPF attach failed; using kernel hash address={f} errno={s}", .{
                        self.bound_addresses[address_index], @tagName(linux.errno(attach_rc)),
                    });
                } else {
                    balancer = "ebpf";
                }
            }
            self.logger.info("tcp listening on {f} workers={d} balancer={s}", .{
                self.bound_addresses[address_index], worker_count, balancer,
            });
        }
        self.listen_socket_count.store(worker_count * address_count, .release);

        for (0..worker_count) |worker_index| {
            const fds = self.listen_fds[worker_index * address_count .. (worker_index + 1) * address_count];
            self.workers[worker_index] = Worker{
                .listener = self,
                .index = worker_index,
                .listen_fds = fds,
            };
            self.workers[worker_index].epoll_fd = bpf.epollCreate() catch {
                lastErrno = bpf.lastErrno;
                return error.StartFailed;
            };
            self.workers[worker_index].wake_fd = bpf.eventfdCreate() catch {
                lastErrno = bpf.lastErrno;
                return error.StartFailed;
            };
            self.workers[worker_index].read_buffer = try allocator.alloc(u8, max_read_chunk);
            self.workers[worker_index].initSplicePipe();
            initialized_workers += 1;

            const worker = &self.workers[worker_index];
            worker.registerWake() catch {
                lastErrno = bpf.lastErrno;
                return error.StartFailed;
            };
            for (fds, 0..) |fd, address_index| {
                worker.registerListen(fd, address_index) catch {
                    lastErrno = bpf.lastErrno;
                    return error.StartFailed;
                };
            }
        }

        for (0..worker_count) |worker_index| {
            const thread = std.Thread.spawn(.{}, Worker.main, .{&self.workers[worker_index]}) catch {
                return error.OutOfMemory;
            };
            self.workers[worker_index].thread = thread;
            spawned += 1;
        }
    }

    fn createListenSocket(self: *TCPListener, address: config.SocketAddr, backlog: i32) StartError!fd_t {
        _ = self;
        var storage: linux.sockaddr.storage = undefined;
        const length = address.toSockaddrStorage(&storage);
        const family: u32 = switch (address.family) {
            .v4 => linux.AF.INET,
            .v6 => linux.AF.INET6,
        };
        const rc = linux.socket(family, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(rc) != .SUCCESS) return failWith(linux.errno(rc));
        const fd: fd_t = @intCast(rc);
        errdefer closeFd(fd);

        const yes: i32 = 1;
        if (linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(i32)) != 0)
            return failWith(.OPNOTSUPP);
        // One listen socket per worker on the same address; the kernel hashes
        // connection four-tuples to a stable worker unless the reuseport eBPF
        // program steers them.
        if (linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, std.mem.asBytes(&yes), @sizeOf(i32)) != 0)
            return failWith(.OPNOTSUPP);
        if (address.family == .v6) {
            if (linux.setsockopt(fd, linux.SOL.IPV6, linux.IPV6.V6ONLY, std.mem.asBytes(&yes), @sizeOf(i32)) != 0)
                return failWith(.OPNOTSUPP);
        }
        const bind_rc = linux.bind(fd, @ptrCast(&storage), length);
        if (linux.errno(bind_rc) != .SUCCESS) return failWith(linux.errno(bind_rc));
        const listen_rc = linux.listen(fd, @intCast(backlog));
        if (linux.errno(listen_rc) != .SUCCESS) return failWith(linux.errno(listen_rc));
        return fd;
    }

    /// Concrete bound addresses, one per configured listen address. Empty
    /// before start().
    pub fn localAddresses(self: *const TCPListener) []const config.SocketAddr {
        return self.bound_addresses;
    }

    /// Number of currently open listen sockets across all workers.
    pub fn listenerSocketCount(self: *const TCPListener) usize {
        return self.listen_socket_count.load(.acquire);
    }

    pub fn activeConnectionCount(self: *const TCPListener) usize {
        return self.active_connections.load(.acquire);
    }

    /// Queued userspace relay bytes, for the tuning daemon.
    pub fn bufferedBytesUsed(self: *const TCPListener) i64 {
        return self.budget.used();
    }

    pub fn currentListeningBacklog(self: *const TCPListener) i32 {
        return self.backlog.load(.acquire);
    }

    /// In-place listen() backlog update on every listen socket, with rollback
    /// to the previous backlog on failure.
    pub fn updateListeningBacklog(self: *TCPListener, backlog: i32) error{ListenFailed}!void {
        const old_backlog = self.backlog.load(.acquire);
        if (backlog == old_backlog) return;

        for (self.listen_fds, 0..) |fd, i| {
            if (fd < 0) continue;
            if (linux.listen(fd, @intCast(backlog)) != 0) {
                for (self.listen_fds[0..i]) |rollback_fd| {
                    if (rollback_fd >= 0) _ = linux.listen(rollback_fd, @intCast(old_backlog));
                }
                return error.ListenFailed;
            }
        }
        self.backlog.store(backlog, .release);
    }

    /// Hot reload: updates the budget limit and the snapshot new connections
    /// see. Existing connections keep their upstream and acceleration mode.
    /// A previously failed accelerator load is retried while sockmap stays
    /// requested; disabling sockmap releases the accelerator once existing
    /// sockmap connections drop their references.
    pub fn updateConfiguration(self: *TCPListener, configuration: config.ResolvedConfiguration) void {
        const requested = self.options.enable_sockmap_acceleration orelse configuration.shouldEnableTCPSockmap();

        self.state_mutex.lock();
        const previous = self.state;
        self.state_mutex.unlock();

        // Retry a previously failed load while sockmap stays requested.
        var accelerator_ref = previous.accelerator;
        if (requested and accelerator_ref == null) {
            accelerator_ref = self.tryLoadAccelerator();
        }

        self.budget.updateLimit(configuration.configuration.limits.max_tcp_buffered_bytes);

        self.state_mutex.lock();
        self.state = .{
            .snapshot = .{
                .upstream = configuration.upstream_address,
                .connect_ns = secondsToNs(configuration.configuration.timeouts.connect_seconds),
                .idle_ns = secondsToNs(configuration.configuration.timeouts.tcp_idle_seconds),
                .sockmap_requested = requested,
            },
            .accelerator = if (requested) accelerator_ref else null,
        };
        self.state_mutex.unlock();

        if (!requested and previous.snapshot.sockmap_requested) {
            self.logger.info("tcp sockmap acceleration disabled", .{});
        }
        // Drop the state's previous reference when the state no longer holds
        // it (sockmap disabled, or a failed load replaced by a fresh one).
        if (previous.accelerator) |acc| {
            if (self.state.accelerator != acc) acc.release();
        }
    }

    /// Stops accepting new connections and closes the listen sockets on the
    /// worker threads. Existing connections keep relaying (graceful drain).
    pub fn stopAccepting(self: *TCPListener) void {
        self.accepting.store(false, .release);
        for (self.workers) |*worker| {
            if (worker.wake_fd >= 0) bpf.eventfdSignal(worker.wake_fd);
        }
        while (self.listen_socket_count.load(.acquire) > 0) {
            sleepNs(1 * std.time.ns_per_ms);
        }
    }

    /// Immediately closes every active connection on all workers.
    pub fn forceCloseConnections(self: *TCPListener) void {
        self.force_close.store(true, .release);
        for (self.workers) |*worker| {
            if (worker.wake_fd >= 0) bpf.eventfdSignal(worker.wake_fd);
        }
    }

    /// Stops the worker threads and joins them; idempotent. Connections and
    /// listen sockets that are still open are closed by the workers.
    pub fn stop(self: *TCPListener) void {
        if (self.stopped) return;
        self.stopped = true;
        self.stopAccepting();
        self.forceCloseConnections();
        for (self.workers) |*worker| {
            worker.stopping.store(true, .release);
            if (worker.wake_fd >= 0) bpf.eventfdSignal(worker.wake_fd);
        }
        for (self.workers) |*worker| {
            if (worker.thread) |thread| {
                thread.join();
                worker.thread = null;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Protocol module registration (core orchestrator entry point)
// ---------------------------------------------------------------------------

pub const protocol_module = config.ProtocolModule{
    .name = "tcp",
    .protocol = .tcp,
    .drains_connections = true,
    .create = createProtocolListener,
};

fn createProtocolListener(
    outer_allocator: Allocator,
    resolved: config.ResolvedConfiguration,
    logger: *log.LogStore,
    selector: ?upstream.Selector,
) anyerror!*config.Listener {
    const listener = try outer_allocator.create(TCPListener);
    errdefer outer_allocator.destroy(listener);
    listener.* = try TCPListener.init(resolved, logger, .{ .upstream_selector = selector });
    errdefer listener.deinit();
    try listener.start();

    const wrapper = try outer_allocator.create(config.Listener);
    wrapper.* = .{
        .allocator = outer_allocator,
        .context = listener,
        .stop_accepting_fn = listenerStopAccepting,
        .destroy_fn = listenerDestroy,
        .update_configuration_fn = listenerUpdateConfiguration,
        .update_backlog_fn = listenerUpdateBacklog,
        .force_close_fn = listenerForceClose,
        .active_count_fn = listenerActiveCount,
        .buffered_bytes_fn = listenerBufferedBytes,
        .associations_fn = listenerZeroAssociations,
    };
    return wrapper;
}

fn listenerStopAccepting(context: *anyopaque) void {
    const listener: *TCPListener = @ptrCast(@alignCast(context));
    listener.stopAccepting();
}

fn listenerDestroy(listener_allocator: Allocator, context: *anyopaque) void {
    const listener: *TCPListener = @ptrCast(@alignCast(context));
    listener.deinit();
    listener_allocator.destroy(listener);
}

fn listenerUpdateConfiguration(context: *anyopaque, resolved: config.ResolvedConfiguration, reset_sessions: bool) void {
    _ = reset_sessions; // existing TCP connections always keep their upstream
    const listener: *TCPListener = @ptrCast(@alignCast(context));
    listener.updateConfiguration(resolved);
}

fn listenerUpdateBacklog(context: *anyopaque, backlog: i32) anyerror!void {
    const listener: *TCPListener = @ptrCast(@alignCast(context));
    try listener.updateListeningBacklog(backlog);
}

fn listenerForceClose(context: *anyopaque) void {
    const listener: *TCPListener = @ptrCast(@alignCast(context));
    listener.forceCloseConnections();
}

fn listenerActiveCount(context: *anyopaque) usize {
    const listener: *TCPListener = @ptrCast(@alignCast(context));
    return listener.activeConnectionCount();
}

fn listenerBufferedBytes(context: *anyopaque) i64 {
    const listener: *TCPListener = @ptrCast(@alignCast(context));
    return listener.bufferedBytesUsed();
}

fn listenerZeroAssociations(context: *anyopaque) u64 {
    _ = context;
    return 0;
}

// ---------------------------------------------------------------------------
// Worker: one thread running its own epoll loop
// ---------------------------------------------------------------------------

fn socketName(fd: fd_t) ?config.SocketAddr {
    var storage: linux.sockaddr.storage = undefined;
    var length: linux.socklen_t = @sizeOf(linux.sockaddr.storage);
    const rc = linux.getsockname(fd, @ptrCast(&storage), &length);
    if (linux.errno(rc) != .SUCCESS) return null;
    return socketAddrFromStorage(&storage);
}

fn socketAddrFromStorage(storage: *const linux.sockaddr.storage) ?config.SocketAddr {
    switch (storage.family) {
        linux.AF.INET => {
            const in: *const linux.sockaddr.in = @ptrCast(@alignCast(storage));
            return config.SocketAddr.initV4(@bitCast(in.addr), std.mem.bigToNative(u16, in.port));
        },
        linux.AF.INET6 => {
            const in6: *const linux.sockaddr.in6 = @ptrCast(@alignCast(storage));
            var address = config.SocketAddr.initV6(in6.addr, std.mem.bigToNative(u16, in6.port));
            address.scope_id = in6.scope_id;
            return address;
        },
        else => return null,
    }
}

const Worker = struct {
    listener: *TCPListener,
    index: usize,
    listen_fds: []fd_t,
    epoll_fd: fd_t = -1,
    wake_fd: fd_t = -1,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    connections: ?*Connection = null,
    zombies: ?*Connection = null,
    /// Worker-local freelist of dead Connection objects (linked through
    /// zombie_next); avoids malloc/free per accept/close cycle.
    connection_pool: ?*Connection = null,
    connection_pool_count: usize = 0,
    /// Earliest timer deadline across all connections, recomputed lazily.
    /// Connection deadlines only move later on activity, so a stale (earlier)
    /// cache is safe: it can only cause an extra wake, never a missed one.
    cached_deadline_ns: u64 = std.math.maxInt(u64),
    deadline_cache_dirty: bool = true,
    next_sweep_ns: u64 = 0,
    read_buffer: []u8 = &.{},
    /// Shared by this worker only. The pipe is always empty between dispatches;
    /// any bytes that hit destination backpressure are copied into the normal
    /// budgeted queue before relaySplice returns.
    splice_pipe: [2]fd_t = .{ -1, -1 },
    splice_capacity: usize = 0,

    const wake_tag: u64 = 0;

    fn initSplicePipe(self: *Worker) void {
        var pipe_fds: [2]fd_t = undefined;
        const rc = linux.pipe2(&pipe_fds, .{ .NONBLOCK = true, .CLOEXEC = true });
        if (linux.errno(rc) != .SUCCESS) {
            self.listener.logger.warning("tcp splice unavailable; using buffered relay worker={d} errno={s}", .{
                self.index, @tagName(linux.errno(rc)),
            });
            return;
        }
        self.splice_pipe = pipe_fds;

        // Growing the pipe is an optimization only. Unprivileged processes
        // may be capped below max_read_chunk; GETPIPE_SZ records the actual
        // value so each splice request always fits in the empty pipe.
        _ = linux.fcntl(pipe_fds[1], linux.F.SETPIPE_SZ, max_read_chunk);
        const capacity_rc = linux.fcntl(pipe_fds[1], linux.F.GETPIPE_SZ, 0);
        if (linux.errno(capacity_rc) == .SUCCESS) {
            self.splice_capacity = @intCast(capacity_rc);
        } else {
            self.splice_capacity = min_read_chunk;
        }
    }

    fn closeSplicePipe(self: *Worker) void {
        for (&self.splice_pipe) |*fd| {
            if (fd.* >= 0) closeFd(fd.*);
            fd.* = -1;
        }
        self.splice_capacity = 0;
    }

    fn registerWake(self: *Worker) Error!void {
        var event = linux.epoll_event{
            .events = linux.EPOLL.IN,
            .data = .{ .u64 = wake_tag },
        };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, self.wake_fd, &event);
        if (linux.errno(rc) != .SUCCESS) return failWith(linux.errno(rc));
    }

    fn registerListen(self: *Worker, fd: fd_t, address_index: usize) Error!void {
        var event = linux.epoll_event{
            .events = linux.EPOLL.IN,
            .data = .{ .u64 = (@as(u64, @intCast(address_index)) << 1) | 1 },
        };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, fd, &event);
        if (linux.errno(rc) != .SUCCESS) return failWith(linux.errno(rc));
    }

    fn main(self: *Worker) void {
        var events: [max_events_per_wait]linux.epoll_event = undefined;
        var now = monotonicNowNs();
        while (!self.stopping.load(.acquire)) {
            const timeout_ms = self.computeTimeoutMs(now);
            const rc = linux.epoll_wait(self.epoll_fd, &events, events.len, timeout_ms);
            const errno = linux.errno(rc);
            switch (errno) {
                .SUCCESS => {},
                .INTR => continue,
                else => {
                    self.listener.logger.err("tcp worker epoll_wait failed worker={d} errno={s}", .{
                        self.index, @tagName(errno),
                    });
                    break;
                },
            }
            const count: usize = @intCast(rc);
            now = monotonicNowNs();
            for (events[0..count]) |event| {
                self.dispatch(event, now);
            }
            self.applyCommands();
            self.maybeSweepTimers(now);
            self.freeZombies();
        }
        self.teardown();
    }

    fn dispatch(self: *Worker, event: linux.epoll_event, now: u64) void {
        const tag = event.data.u64;
        if (tag == wake_tag) {
            bpf.eventfdDrain(self.wake_fd);
            return;
        }
        if (tag & 1 == 1) {
            const address_index: usize = @intCast(tag >> 1);
            if (address_index < self.listen_fds.len and self.listen_fds[address_index] >= 0) {
                self.acceptLoop(address_index, now);
            }
            return;
        }
        const endpoint: *Endpoint = @ptrFromInt(tag);
        const connection = endpoint.connection;
        if (connection.dead) return;
        self.handleEndpointEvent(endpoint, event.events, now);
    }

    /// Late commands from the listener: stop accepting (close listen sockets)
    /// and force-close all connections. Checked after every epoll wake.
    fn applyCommands(self: *Worker) void {
        if (!self.listener.accepting.load(.acquire)) {
            for (self.listen_fds, 0..) |fd, address_index| {
                if (fd < 0) continue;
                _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, fd, null);
                closeFd(fd);
                self.listen_fds[address_index] = -1;
                _ = self.listener.listen_socket_count.fetchSub(1, .release);
            }
        }
        if (self.listener.force_close.load(.acquire)) {
            var current = self.connections;
            while (current) |connection| {
                current = connection.next;
                self.killConnection(connection);
            }
        }
    }

    fn computeTimeoutMs(self: *Worker, now: u64) i32 {
        if (self.deadline_cache_dirty) self.refreshDeadlineCache();
        const next_deadline = @min(self.cached_deadline_ns, self.next_sweep_ns);
        if (next_deadline <= now) return 0;
        const delta_ms = (next_deadline - now + 999_999) / 1_000_000;
        return @intCast(@min(delta_ms, sweep_interval_ns / 1_000_000));
    }

    /// Full O(N) scan for the earliest connection deadline. Runs at most once
    /// per actual deadline arrival (or once per sweep) instead of once per
    /// epoll wake, because deadlines only move later between scans.
    fn refreshDeadlineCache(self: *Worker) void {
        var next_deadline: u64 = std.math.maxInt(u64);
        var current = self.connections;
        while (current) |connection| : (current = connection.next) {
            const deadline = switch (connection.mode) {
                .connecting => connection.connect_deadline_ns,
                .userspace => connection.last_activity_ns + connection.idle_ns,
                .sockmap => connection.sockmap_next_check_ns,
            };
            next_deadline = @min(next_deadline, deadline);
        }
        self.cached_deadline_ns = next_deadline;
        self.deadline_cache_dirty = false;
    }

    /// Sweeps connection timers at most once per sweep_interval_ns, plus
    /// promptly whenever a real deadline has arrived.
    fn maybeSweepTimers(self: *Worker, now: u64) void {
        if (self.deadline_cache_dirty) self.refreshDeadlineCache();
        if (now >= self.next_sweep_ns or now >= self.cached_deadline_ns) {
            self.sweepTimers(now);
            self.refreshDeadlineCache();
            self.next_sweep_ns = now + sweep_interval_ns;
        }
    }

    fn sweepTimers(self: *Worker, now: u64) void {
        var current = self.connections;
        while (current) |connection| {
            current = connection.next;
            switch (connection.mode) {
                .connecting => {
                    if (now >= connection.connect_deadline_ns) {
                        self.listener.logger.err("tcp connect failed client={s} upstream={f} error=connect timeout", .{
                            connection.clientText(), connection.upstream_addr,
                        });
                        if (self.listener.options.upstream_selector) |s| {
                            s.reportFailure(connection.upstream_addr, now);
                        }
                        self.killConnection(connection);
                    }
                },
                .userspace => {
                    if (now - connection.last_activity_ns >= connection.idle_ns) {
                        self.listener.logger.debug("tcp connection closed after idle timeout", .{});
                        self.killConnection(connection);
                    }
                },
                .sockmap => {
                    if (now >= connection.sockmap_next_check_ns) {
                        self.checkSockmapIdle(connection, now);
                    }
                },
            }
        }
    }

    fn checkSockmapIdle(self: *Worker, connection: *Connection, now: u64) void {
        const accelerator_ref = connection.accelerator orelse unreachable;
        const pairing = connection.pairing orelse unreachable;
        const remaining = accelerator_ref.idleRemainingNs(pairing, connection.idle_ns) catch |err| {
            self.listener.logger.warning("tcp sockmap activity lookup failed; closing connection error={s} errno={s}", .{
                @errorName(err), @tagName(bpf.lastErrno),
            });
            self.killConnection(connection);
            return;
        };
        if (remaining == 0) {
            self.listener.logger.debug("tcp sockmap connection closed after idle timeout", .{});
            self.killConnection(connection);
            return;
        }
        connection.sockmap_next_check_ns = now + @max(remaining, 1_000_000);
    }

    // ------------------------------------------------------------------
    // Accept and upstream connect
    // ------------------------------------------------------------------

    fn acceptLoop(self: *Worker, address_index: usize, now: u64) void {
        const listen_fd = self.listen_fds[address_index];
        var accepted: usize = 0;
        while (accepted < max_accept_per_event) : (accepted += 1) {
            var storage: linux.sockaddr.storage = undefined;
            var length: linux.socklen_t = @sizeOf(linux.sockaddr.storage);
            const rc = linux.accept4(listen_fd, @ptrCast(&storage), &length, linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC);
            const errno = linux.errno(rc);
            switch (errno) {
                .SUCCESS => {},
                .AGAIN, .INTR => return,
                else => {
                    self.listener.logger.warning("tcp accept failed worker={d} errno={s}", .{ self.index, @tagName(errno) });
                    return;
                },
            }
            const client_fd: fd_t = @intCast(rc);
            if (!self.listener.accepting.load(.acquire)) {
                closeFd(client_fd);
                return;
            }
            self.setupConnection(client_fd, &storage, now);
        }
    }

    fn allocConnection(self: *Worker) ?*Connection {
        if (self.connection_pool) |pooled| {
            self.connection_pool = pooled.zombie_next;
            self.connection_pool_count -= 1;
            return pooled;
        }
        return allocator.create(Connection) catch null;
    }

    fn releaseConnection(self: *Worker, connection: *Connection) void {
        if (self.connection_pool_count < max_pooled_connections) {
            connection.zombie_next = self.connection_pool;
            self.connection_pool = connection;
            self.connection_pool_count += 1;
        } else {
            allocator.destroy(connection);
        }
    }

    fn setupConnection(self: *Worker, client_fd: fd_t, client_storage: *const linux.sockaddr.storage, now: u64) void {
        const listener = self.listener;
        const yes: i32 = 1;
        _ = linux.setsockopt(client_fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&yes), @sizeOf(i32));

        const state = listener.currentSnapshot();
        const client_address = socketAddrFromStorage(client_storage);
        listener.logger.debug("tcp accepted client={f}", .{client_address orelse config.SocketAddr.initV4(.{ 0, 0, 0, 0 }, 0)});

        if (!listener.accepting.load(.acquire)) {
            if (state.accelerator) |acc| acc.release();
            closeFd(client_fd);
            return;
        }

        const connection = self.allocConnection() orelse {
            if (state.accelerator) |acc| acc.release();
            closeFd(client_fd);
            return;
        };
        connection.* = .{
            .worker = self,
            .client = .{ .connection = connection, .fd = client_fd, .is_client = true },
            .upstream = .{ .connection = connection, .fd = -1, .is_client = false },
            .idle_ns = state.snapshot.idle_ns,
            .last_activity_ns = now,
            .upstream_addr = state.snapshot.upstream,
            .client_addr = client_address,
            .connect_ns = state.snapshot.connect_ns,
            .accelerator = state.accelerator,
        };
        if (client_address) |address| {
            const text = std.fmt.bufPrint(&connection.client_text, "{f}", .{address}) catch unreachable;
            connection.client_text_len = text.len;
        }

        // Nonblocking upstream connect with connect_seconds deadline. With a
        // selector (rules plugin) the upstream is picked per connection and
        // immediate connect failures fail over to the next pick; without one
        // the loop below runs exactly once with the configured upstream.
        const selector = listener.options.upstream_selector;
        const can_failover = if (selector) |s| s.isMulti() else false;
        const max_attempts: usize = if (can_failover) max_failover_attempts else 1;
        var connect_errno: linux.E = .SUCCESS;
        var attempt: usize = 0;
        connect_attempts: while (true) {
            if (can_failover) connection.upstream_addr = selector.?.pick(client_address, now);
            switch (self.connectUpstreamOnce(connection)) {
                .connected => {
                    connect_errno = .SUCCESS;
                    break :connect_attempts;
                },
                .pending => {
                    connect_errno = .INPROGRESS;
                    break :connect_attempts;
                },
                .connect_failed => {
                    if (selector) |s| s.reportFailure(connection.upstream_addr, now);
                    attempt += 1;
                    if (attempt >= max_attempts) {
                        self.discardNewConnection(connection);
                        return;
                    }
                },
                .socket_failed => {
                    self.discardNewConnection(connection);
                    return;
                },
            }
        }

        // Register both fds with the loop and link the connection.
        connection.next = self.connections;
        self.connections = connection;
        self.deadline_cache_dirty = true;
        _ = listener.active_connections.fetchAdd(1, .release);

        self.registerEndpoint(&connection.client);
        self.registerEndpoint(&connection.upstream);

        if (connect_errno == .SUCCESS) {
            self.onUpstreamConnected(connection, now);
        } else {
            connection.mode = .connecting;
            connection.connect_deadline_ns = now + state.snapshot.connect_ns;
            connection.upstream.want_write = true;
            self.updateMask(&connection.upstream);
        }
    }

    /// Failure path before the connection entered the loop's bookkeeping.
    fn discardNewConnection(self: *Worker, connection: *Connection) void {
        if (connection.client.fd >= 0) closeFd(connection.client.fd);
        if (connection.upstream.fd >= 0) closeFd(connection.upstream.fd);
        if (connection.accelerator) |acc| acc.release();
        self.releaseConnection(connection);
    }

    const ConnectOutcome = enum { connected, pending, connect_failed, socket_failed };

    /// One nonblocking connect attempt to connection.upstream_addr on a fresh
    /// socket. Immediate connect failures close the fd and report
    /// .connect_failed (the caller may re-pick); a socket() error reports
    /// .socket_failed and must not be retried against another upstream.
    fn connectUpstreamOnce(self: *Worker, connection: *Connection) ConnectOutcome {
        const listener = self.listener;
        listener.logger.debug("tcp opening upstream client={s} upstream={f}", .{
            connection.clientText(), connection.upstream_addr,
        });

        var upstream_storage: linux.sockaddr.storage = undefined;
        const upstream_len = connection.upstream_addr.toSockaddrStorage(&upstream_storage);
        const family: u32 = switch (connection.upstream_addr.family) {
            .v4 => linux.AF.INET,
            .v6 => linux.AF.INET6,
        };
        const socket_rc = linux.socket(family, linux.SOCK.STREAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(socket_rc) != .SUCCESS) {
            listener.logger.err("tcp connect failed client={s} upstream={f} errno={s}", .{
                connection.clientText(), connection.upstream_addr, @tagName(linux.errno(socket_rc)),
            });
            return .socket_failed;
        }
        const upstream_fd: fd_t = @intCast(socket_rc);
        connection.upstream.fd = upstream_fd;
        const yes: i32 = 1;
        _ = linux.setsockopt(upstream_fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, std.mem.asBytes(&yes), @sizeOf(i32));

        const connect_rc = linux.connect(upstream_fd, @ptrCast(&upstream_storage), upstream_len);
        const connect_errno = linux.errno(connect_rc);
        if (connect_errno == .SUCCESS) return .connected;
        if (connect_errno == .INPROGRESS) return .pending;

        listener.logger.err("tcp connect failed client={s} upstream={f} errno={s}", .{
            connection.clientText(), connection.upstream_addr, @tagName(connect_errno),
        });
        closeFd(upstream_fd);
        connection.upstream.fd = -1;
        return .connect_failed;
    }

    /// Selector failover while the connection is still in connecting mode:
    /// drop the failed upstream fd, re-pick and restart the connect. Returns
    /// true when a new attempt is underway (or already connected).
    fn retryUpstream(self: *Worker, connection: *Connection, now: u64) bool {
        const listener = self.listener;
        const selector = listener.options.upstream_selector orelse return false;
        if (!selector.isMulti()) return false;
        selector.reportFailure(connection.upstream_addr, now);
        connection.failover_attempts += 1;
        if (connection.failover_attempts >= max_failover_attempts) return false;

        _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, connection.upstream.fd, null);
        closeFd(connection.upstream.fd);
        connection.upstream.fd = -1;
        connection.upstream.registered = false;
        connection.upstream.want_write = false;
        self.deadline_cache_dirty = true;

        while (connection.failover_attempts < max_failover_attempts) {
            connection.upstream_addr = selector.pick(connection.client_addr, now);
            switch (self.connectUpstreamOnce(connection)) {
                .connected => {
                    self.registerEndpoint(&connection.upstream);
                    if (connection.dead) return true;
                    self.onUpstreamConnected(connection, now);
                    return true;
                },
                .pending => {
                    self.registerEndpoint(&connection.upstream);
                    if (connection.dead) return true;
                    connection.mode = .connecting;
                    connection.connect_deadline_ns = now + connection.connect_ns;
                    connection.upstream.want_write = true;
                    self.updateMask(&connection.upstream);
                    self.deadline_cache_dirty = true;
                    return true;
                },
                .connect_failed => {
                    selector.reportFailure(connection.upstream_addr, now);
                    connection.failover_attempts += 1;
                },
                .socket_failed => return false,
            }
        }
        return false;
    }

    fn onUpstreamConnected(self: *Worker, connection: *Connection, now: u64) void {
        const listener = self.listener;
        if (listener.options.upstream_selector) |s| s.reportSuccess(connection.upstream_addr);
        self.deadline_cache_dirty = true; // deadline basis changes with the mode
        if (connection.accelerator) |accelerator_ref| {
            if (accelerator_ref.pair(connection.client.fd, connection.upstream.fd)) |pairing| {
                connection.pairing = pairing;
                connection.mode = .sockmap;
                connection.sockmap_next_check_ns = now + connection.idle_ns;
                connection.client.read_wanted = true;
                connection.upstream.read_wanted = true;
                connection.upstream.want_write = false;
                self.updateMask(&connection.client);
                self.updateMask(&connection.upstream);
                listener.logger.debug("tcp connected mode=sockmap client={s} upstream={f}", .{
                    connection.clientText(), connection.upstream_addr,
                });
                return;
            } else |err| {
                listener.logger.debug("tcp sockmap pairing failed; using userspace relay client={s} error={s} errno={s}", .{
                    connection.clientText(), @errorName(err), @tagName(bpf.lastErrno),
                });
            }
        }
        connection.mode = .userspace;
        connection.last_activity_ns = now;
        connection.client.read_wanted = true;
        connection.upstream.read_wanted = true;
        connection.upstream.want_write = false;
        self.updateMask(&connection.client);
        self.updateMask(&connection.upstream);
        listener.logger.debug("tcp connected mode=userspace client={s} upstream={f}", .{
            connection.clientText(), connection.upstream_addr,
        });
    }

    // ------------------------------------------------------------------
    // Event handling
    // ------------------------------------------------------------------

    fn handleEndpointEvent(self: *Worker, endpoint: *Endpoint, mask: u32, now: u64) void {
        const connection = endpoint.connection;

        if (connection.mode == .connecting) {
            // Only the upstream fd matters; any client-side event before the
            // upstream is up tears the attempt down. Writability means the
            // connect settled; error/hangup events are routed through the
            // same SO_ERROR check so selector failover applies to them too.
            if (!endpoint.is_client and mask & (linux.EPOLL.OUT | linux.EPOLL.ERR | linux.EPOLL.HUP) != 0) {
                self.finishConnect(connection, now);
                return;
            }
            if (mask & (linux.EPOLL.ERR | linux.EPOLL.HUP | linux.EPOLL.RDHUP | linux.EPOLL.IN) != 0) {
                self.killConnection(connection);
            }
            return;
        }

        if (mask & linux.EPOLL.ERR != 0) {
            self.killConnection(connection);
            return;
        }
        if (mask & (linux.EPOLL.IN | linux.EPOLL.RDHUP | linux.EPOLL.HUP) != 0 and
            endpoint.read_open and endpoint.read_wanted)
        {
            switch (connection.mode) {
                .userspace => self.relayRead(endpoint, now),
                .sockmap => self.sockmapRead(endpoint, now),
                .connecting => unreachable,
            }
            if (connection.dead) return;
        }
        if (mask & linux.EPOLL.OUT != 0) {
            self.flushPending(endpoint, now);
        }
    }

    fn finishConnect(self: *Worker, connection: *Connection, now: u64) void {
        var socket_error: i32 = 0;
        var length: linux.socklen_t = @sizeOf(i32);
        const rc = linux.getsockopt(connection.upstream.fd, linux.SOL.SOCKET, linux.SO.ERROR, std.mem.asBytes(&socket_error).ptr, &length);
        const errno = linux.errno(rc);
        if (errno != .SUCCESS or socket_error != 0) {
            const tag = if (errno != .SUCCESS) errno else linux.E.SUCCESS;
            self.listener.logger.err("tcp connect failed client={s} upstream={f} errno={d}", .{
                connection.clientText(),                                    connection.upstream_addr,
                if (errno != .SUCCESS) @intFromEnum(tag) else socket_error,
            });
            if (self.retryUpstream(connection, now)) return;
            self.killConnection(connection);
            return;
        }
        self.onUpstreamConnected(connection, now);
    }

    /// Userspace relay. Prefer socket -> pipe -> socket splice when the peer's
    /// queue is empty, then fall back to the buffered path if splice is not
    /// supported or ordering requires appending behind queued bytes.
    fn relayRead(self: *Worker, endpoint: *Endpoint, now: u64) void {
        if (self.relaySplice(endpoint, now)) return;
        self.relayBuffered(endpoint, now);
    }

    /// Zero-copy fast path. The worker pipe is empty on entry and exit. If the
    /// destination stops accepting data, the pipe remainder is copied into
    /// the normal budgeted queue so epoll flushing preserves ordering.
    fn relaySplice(self: *Worker, endpoint: *Endpoint, now: u64) bool {
        if (self.splice_pipe[0] < 0 or self.splice_capacity == 0) return false;

        const connection = endpoint.connection;
        const peer = connection.peerOf(endpoint);
        if (peer.pendingLen() != 0 or peer.fin_when_drained or peer.wr_shutdown) return false;

        var batch_bytes: usize = 0;
        while (batch_bytes < max_relay_bytes_per_event) {
            if (!endpoint.read_open or !endpoint.read_wanted) break;
            if (peer.fin_when_drained or peer.wr_shutdown) {
                self.killConnection(connection);
                return true;
            }

            // Clamp to the remaining byte budget so one oversized request
            // cannot overshoot the per-event cap. The loop condition keeps
            // the remaining budget strictly positive here.
            const request = @min(endpoint.read_chunk, self.splice_capacity, max_relay_bytes_per_event - batch_bytes);
            const rc = spliceNonBlocking(endpoint.fd, self.splice_pipe[1], request, true);
            const errno = linux.errno(rc);
            if (errno != .SUCCESS) {
                switch (errno) {
                    .AGAIN => break,
                    .INTR => continue,
                    .INVAL, .NOSYS, .OPNOTSUPP => {
                        // No bytes entered the pipe. Disable splice for this
                        // worker and retry this event through buffered I/O.
                        self.closeSplicePipe();
                        return batch_bytes != 0;
                    },
                    else => {
                        self.killConnection(connection);
                        return true;
                    },
                }
            }

            const moved: usize = @intCast(rc);
            if (moved == 0) {
                self.onPeerEof(endpoint);
                return true;
            }
            batch_bytes += moved;
            connection.last_activity_ns = now;
            if (endpoint.is_client) {
                connection.bytes_to_upstream += @intCast(moved);
            } else {
                connection.bytes_to_client += @intCast(moved);
            }
            // Grow the splice chunk after a full socket-to-pipe splice so a
            // hot sustained stream issues fewer, larger splice requests.
            // Growth beyond the pipe's actual capacity is harmless: the
            // request is always min(read_chunk, splice_capacity).
            if (moved == request and endpoint.read_chunk < max_read_chunk) {
                endpoint.read_chunk = @min(endpoint.read_chunk * 2, max_read_chunk);
            }

            var remaining = moved;
            while (remaining > 0) {
                // No SPLICE_F_MORE on the outgoing side: it makes the kernel
                // hold small segments, which penalizes request/response
                // latency for marginal bulk-throughput gain.
                const send_rc = spliceNonBlocking(self.splice_pipe[0], peer.fd, remaining, false);
                const send_errno = linux.errno(send_rc);
                if (send_errno != .SUCCESS) {
                    switch (send_errno) {
                        .AGAIN => break,
                        .INTR => continue,
                        else => {
                            self.closeSplicePipe();
                            self.killConnection(connection);
                            return true;
                        },
                    }
                }
                const sent: usize = @intCast(send_rc);
                if (sent == 0) break;
                remaining -= sent;
            }

            if (remaining > 0) {
                const budget = &self.listener.budget;
                if (!budget.tryAcquire(remaining)) {
                    self.discardPipeBytes(remaining);
                    self.listener.logger.warning("tcp buffer budget exhausted limit={d}", .{budget.limit()});
                    self.killConnection(connection);
                    return true;
                }
                // Reserve queue space and read the pipe straight into it,
                // avoiding the read_buffer bounce copy.
                peer.pending.ensureUnusedCapacity(allocator, remaining) catch {
                    budget.release(remaining);
                    self.discardPipeBytes(remaining);
                    self.killConnection(connection);
                    return true;
                };
                if (!self.readPipeBytes(peer.pending.unusedCapacitySlice()[0..remaining])) {
                    budget.release(remaining);
                    self.killConnection(connection);
                    return true;
                }
                peer.pending.items.len += remaining;
                peer.budget_bytes += remaining;
                self.updateMask(peer);
                break;
            }
        }

        if (batch_bytes > 0 and batch_bytes < endpoint.read_chunk / 2 and endpoint.read_chunk > min_read_chunk) {
            endpoint.read_chunk = @max(endpoint.read_chunk / 2, min_read_chunk);
        }
        return true;
    }

    fn readPipeBytes(self: *Worker, destination: []u8) bool {
        var read_total: usize = 0;
        while (read_total < destination.len) {
            const rc = linux.read(
                self.splice_pipe[0],
                destination.ptr + read_total,
                destination.len - read_total,
            );
            const errno = linux.errno(rc);
            if (errno != .SUCCESS) {
                switch (errno) {
                    .INTR => continue,
                    else => {
                        self.closeSplicePipe();
                        return false;
                    },
                }
            }
            const count: usize = @intCast(rc);
            if (count == 0) {
                self.closeSplicePipe();
                return false;
            }
            read_total += count;
        }
        return true;
    }

    fn discardPipeBytes(self: *Worker, byte_count: usize) void {
        _ = self.readPipeBytes(self.read_buffer[0..byte_count]);
    }

    /// Buffered fallback: read up to one batch from endpoint and forward to
    /// the peer, pausing reads when the peer's outbound queue crosses the high
    /// watermark.
    fn relayBuffered(self: *Worker, endpoint: *Endpoint, now: u64) void {
        const connection = endpoint.connection;
        const peer = connection.peerOf(endpoint);
        var reads: usize = 0;
        var batch_bytes: usize = 0;
        // Bound bytes per event to max_relay_bytes_per_event as well; with a
        // grown 1 MiB chunk, 8 reads could otherwise queue 8 MiB when direct
        // writes keep the pending queue empty. max_reads_per_event is kept as
        // a secondary bound so partial reads and EINTR retries still have
        // headroom within the byte cap.
        while (reads < max_reads_per_event and batch_bytes < max_relay_bytes_per_event) : (reads += 1) {
            if (!endpoint.read_open or !endpoint.read_wanted) break;
            if (peer.fin_when_drained or peer.wr_shutdown) {
                // The peer's output is closing (half-close in progress); more
                // data from this side has nowhere to go, like a failed write
                // to an output-closed peer.
                self.killConnection(connection);
                return;
            }

            // Clamp to the remaining byte budget so one oversized read cannot
            // overshoot the per-event cap. The loop condition keeps the
            // remaining budget strictly positive here.
            const request = @min(endpoint.read_chunk, max_relay_bytes_per_event - batch_bytes);
            const rc = linux.read(endpoint.fd, self.read_buffer.ptr, request);
            const errno = linux.errno(rc);
            if (errno != .SUCCESS) {
                switch (errno) {
                    .AGAIN => break,
                    .INTR => continue,
                    else => {
                        self.killConnection(connection);
                        return;
                    },
                }
            }
            const count: usize = @intCast(rc);
            if (count == 0) {
                self.onPeerEof(endpoint);
                return;
            }
            batch_bytes += count;
            connection.last_activity_ns = now;
            if (endpoint.is_client) {
                connection.bytes_to_upstream += @intCast(count);
            } else {
                connection.bytes_to_client += @intCast(count);
            }
            if (!self.deliver(peer, self.read_buffer[0..count])) return;

            // Adaptive chunk: grow when reads fill the buffer, shrink when a
            // batch is mostly idle.
            if (count == endpoint.read_chunk and endpoint.read_chunk < max_read_chunk) {
                endpoint.read_chunk = @min(endpoint.read_chunk * 2, max_read_chunk);
            }
            if (peer.pendingLen() >= write_buffer_high_watermark) {
                endpoint.read_wanted = false;
                self.updateMask(endpoint);
                break;
            }
        }
        if (batch_bytes > 0 and batch_bytes < endpoint.read_chunk / 2 and endpoint.read_chunk > min_read_chunk) {
            endpoint.read_chunk = @max(endpoint.read_chunk / 2, min_read_chunk);
        }
    }

    /// Sockmap-forwarded connection: the kernel moves the data; userspace
    /// reads only see FIN (close both sides, unpair) or stragglers the
    /// verdict passed through (relay them in userspace).
    fn sockmapRead(self: *Worker, endpoint: *Endpoint, now: u64) void {
        const connection = endpoint.connection;
        var attempts: usize = 0;
        while (attempts < 4) : (attempts += 1) {
            const rc = linux.read(endpoint.fd, self.read_buffer.ptr, self.read_buffer.len);
            const errno = linux.errno(rc);
            if (errno != .SUCCESS) {
                switch (errno) {
                    .AGAIN => return,
                    .INTR => return,
                    else => {
                        self.killConnection(connection);
                        return;
                    },
                }
            }
            const count: usize = @intCast(rc);
            if (count == 0) {
                self.killConnection(connection);
                return;
            }
            connection.last_activity_ns = now;
            const peer = connection.peerOf(endpoint);
            _ = self.deliver(peer, self.read_buffer[0..count]);
            if (connection.dead or count < self.read_buffer.len) return;
        }
    }

    /// Forward data to a peer fd: write immediately when the queue is empty,
    /// queue the rest under the buffer budget. Returns false when the
    /// connection was torn down (budget exhausted or write error).
    fn deliver(self: *Worker, peer: *Endpoint, data: []const u8) bool {
        const connection = peer.connection;
        var written: usize = 0;
        if (peer.pendingLen() == 0 and !peer.fin_when_drained and !peer.wr_shutdown) {
            written = self.sendSome(peer.fd, data) catch {
                self.killConnection(connection);
                return false;
            };
        }
        const rest = data[written..];
        if (rest.len == 0) return true;

        const budget = &connection.worker.listener.budget;
        if (!budget.tryAcquire(rest.len)) {
            self.listener.logger.warning("tcp buffer budget exhausted limit={d}", .{budget.limit()});
            self.killConnection(connection);
            return false;
        }
        peer.pending.appendSlice(allocator, rest) catch {
            budget.release(rest.len);
            self.killConnection(connection);
            return false;
        };
        peer.budget_bytes += rest.len;
        if (peer.pendingLen() >= write_buffer_high_watermark) {
            const source = connection.peerOf(peer);
            if (source.read_wanted) {
                source.read_wanted = false;
                self.updateMask(source);
            }
        }
        self.updateMask(peer);
        return true;
    }

    /// Nonblocking send of as much of data as the kernel takes right now.
    fn sendSome(self: *Worker, fd: fd_t, data: []const u8) Error!usize {
        _ = self;
        var total: usize = 0;
        while (total < data.len) {
            const rc = linux.sendto(fd, data.ptr + total, data.len - total, linux.MSG.NOSIGNAL, null, 0);
            const errno = linux.errno(rc);
            switch (errno) {
                .SUCCESS => total += @intCast(rc),
                .AGAIN => return total,
                .INTR => continue,
                else => return failWith(errno),
            }
        }
        return total;
    }

    /// Drain the outbound queue of endpoint while the kernel accepts data.
    fn flushPending(self: *Worker, endpoint: *Endpoint, now: u64) void {
        const connection = endpoint.connection;
        const budget = &self.listener.budget;
        // Release budget once per flush instead of once per sendto, so the
        // cross-worker shared counter is not hammered under backpressure.
        var flushed: usize = 0;
        defer {
            if (flushed > 0) budget.release(flushed);
        }
        while (endpoint.budget_bytes > 0) {
            const items = endpoint.pending.items[endpoint.pending_head..];
            const rc = linux.sendto(endpoint.fd, items.ptr, items.len, linux.MSG.NOSIGNAL, null, 0);
            const errno = linux.errno(rc);
            switch (errno) {
                .SUCCESS => {
                    const count: usize = @intCast(rc);
                    endpoint.pending_head += count;
                    endpoint.budget_bytes -= count;
                    flushed += count;
                    connection.last_activity_ns = now;
                },
                .AGAIN => break,
                .INTR => continue,
                else => {
                    self.killConnection(connection);
                    return;
                },
            }
        }

        if (endpoint.budget_bytes == 0) {
            endpoint.pending_head = 0;
            endpoint.pending.clearRetainingCapacity();
            if (endpoint.pending.capacity > pending_shrink_capacity) {
                endpoint.pending.deinit(allocator);
                endpoint.pending = .empty;
            }
            if (endpoint.fin_when_drained) {
                self.shutdownWrite(endpoint);
            }
        }

        // Resume reading the peer once the queue drains below the low
        // watermark.
        const source = connection.peerOf(endpoint);
        if (endpoint.budget_bytes <= write_buffer_low_watermark and
            source.read_open and !source.read_wanted and !connection.dead)
        {
            source.read_wanted = true;
            self.updateMask(source);
        }
        self.updateMask(endpoint);
        self.checkFullyClosed(connection);
    }

    /// Half-close: this side hit EOF, so finish flushing the peer's queue and
    /// then send FIN (allowRemoteHalfClosure semantics).
    fn onPeerEof(self: *Worker, endpoint: *Endpoint) void {
        const connection = endpoint.connection;
        endpoint.read_open = false;
        endpoint.read_wanted = false;
        self.updateMask(endpoint);
        const peer = connection.peerOf(endpoint);
        peer.fin_when_drained = true;
        if (peer.pendingLen() == 0) {
            self.shutdownWrite(peer);
        }
        self.checkFullyClosed(connection);
    }

    fn shutdownWrite(self: *Worker, endpoint: *Endpoint) void {
        _ = self;
        if (endpoint.wr_shutdown) return;
        endpoint.wr_shutdown = true;
        _ = linux.shutdown(endpoint.fd, linux.SHUT.WR);
    }

    fn checkFullyClosed(self: *Worker, connection: *Connection) void {
        _ = self;
        if (connection.dead) return;
        if (!connection.client.read_open and !connection.upstream.read_open and
            connection.client.pendingLen() == 0 and connection.upstream.pendingLen() == 0)
        {
            connection.worker.killConnection(connection);
        }
    }

    // ------------------------------------------------------------------
    // epoll registration
    // ------------------------------------------------------------------

    fn desiredMask(endpoint: *const Endpoint) u32 {
        var mask: u32 = 0;
        const connection = endpoint.connection;
        if (connection.mode == .connecting) {
            if (endpoint.read_open) {
                mask |= linux.EPOLL.RDHUP;
            }
            if (!endpoint.is_client and endpoint.want_write) {
                mask |= linux.EPOLL.OUT;
            }
            return mask;
        }
        if (endpoint.read_open and endpoint.read_wanted) {
            mask |= linux.EPOLL.IN | linux.EPOLL.RDHUP;
        }
        if (endpoint.budget_bytes > 0 or endpoint.want_write) {
            mask |= linux.EPOLL.OUT;
        }
        return mask;
    }

    fn registerEndpoint(self: *Worker, endpoint: *Endpoint) void {
        const mask = desiredMask(endpoint);
        var event = linux.epoll_event{
            .events = mask,
            .data = .{ .u64 = @intFromPtr(endpoint) },
        };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, endpoint.fd, &event);
        if (linux.errno(rc) != .SUCCESS) {
            self.listener.logger.warning("tcp epoll registration failed errno={s}", .{@tagName(linux.errno(rc))});
            self.killConnection(endpoint.connection);
            return;
        }
        endpoint.registered = true;
        endpoint.registered_mask = mask;
    }

    fn updateMask(self: *Worker, endpoint: *Endpoint) void {
        if (endpoint.connection.dead or !endpoint.registered) return;
        const mask = desiredMask(endpoint);
        if (mask == endpoint.registered_mask) return; // avoid redundant epoll_ctl
        var event = linux.epoll_event{
            .events = mask,
            .data = .{ .u64 = @intFromPtr(endpoint) },
        };
        const rc = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_MOD, endpoint.fd, &event);
        if (linux.errno(rc) != .SUCCESS) {
            self.listener.logger.warning("tcp epoll update failed errno={s}", .{@tagName(linux.errno(rc))});
            self.killConnection(endpoint.connection);
            return;
        }
        endpoint.registered_mask = mask;
    }

    // ------------------------------------------------------------------
    // Connection teardown
    // ------------------------------------------------------------------

    /// Releases all connection resources (fds, budget, pairing) and moves the
    /// connection to the zombie list; memory is freed after the current
    /// dispatch round so stale epoll events can safely observe `dead`.
    fn killConnection(self: *Worker, connection: *Connection) void {
        if (connection.dead) return;
        connection.dead = true;

        const listener = self.listener;
        inline for ([_]*Endpoint{ &connection.client, &connection.upstream }) |endpoint| {
            if (endpoint.budget_bytes > 0) {
                listener.budget.release(endpoint.budget_bytes);
                endpoint.budget_bytes = 0;
            }
            endpoint.pending.deinit(allocator);
            if (endpoint.fd >= 0) {
                // close() implicitly removes the fd from this epoll instance;
                // stale queued events are filtered by the connection.dead
                // check in dispatch.
                closeFd(endpoint.fd);
                endpoint.fd = -1;
                endpoint.registered = false;
            }
        }
        if (connection.pairing) |pairing| {
            if (connection.accelerator) |accelerator_ref| {
                accelerator_ref.unpair(pairing);
            }
            connection.pairing = null;
        }
        if (connection.accelerator) |accelerator_ref| {
            accelerator_ref.release();
            connection.accelerator = null;
        }

        // Unlink from the active list.
        var link: *?*Connection = &self.connections;
        while (link.*) |current| {
            if (current == connection) {
                link.* = connection.next;
                break;
            }
            link = &current.next;
        }
        connection.next = null;
        connection.zombie_next = self.zombies;
        self.zombies = connection;
        _ = listener.active_connections.fetchSub(1, .release);

        listener.logger.debug("tcp client connection closed bytes_to_upstream={d}", .{connection.bytes_to_upstream});
        listener.logger.debug("tcp relay direction closed bytes={d}", .{connection.bytes_to_client});
    }

    fn freeZombies(self: *Worker) void {
        var current = self.zombies;
        self.zombies = null;
        while (current) |connection| {
            current = connection.zombie_next;
            self.releaseConnection(connection);
        }
    }

    fn teardown(self: *Worker) void {
        var current = self.connections;
        while (current) |connection| {
            current = connection.next;
            self.killConnection(connection);
        }
        self.freeZombies();
        while (self.connection_pool) |pooled| {
            self.connection_pool = pooled.zombie_next;
            allocator.destroy(pooled);
        }
        self.connection_pool_count = 0;
        for (self.listen_fds, 0..) |fd, address_index| {
            if (fd >= 0) {
                _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_DEL, fd, null);
                closeFd(fd);
                self.listen_fds[address_index] = -1;
                _ = self.listener.listen_socket_count.fetchSub(1, .release);
            }
        }
        if (self.epoll_fd >= 0) {
            closeFd(self.epoll_fd);
            self.epoll_fd = -1;
        }
        if (self.wake_fd >= 0) {
            closeFd(self.wake_fd);
            self.wake_fd = -1;
        }
        self.closeSplicePipe();
        if (self.read_buffer.len > 0) {
            allocator.free(self.read_buffer);
            self.read_buffer = &.{};
        }
    }
};

// ---------------------------------------------------------------------------
// Connection: an accepted client paired with its upstream connection
// ---------------------------------------------------------------------------

const ConnectionMode = enum { connecting, userspace, sockmap };

const Connection = struct {
    worker: *Worker,
    client: Endpoint,
    upstream: Endpoint,
    mode: ConnectionMode = .connecting,
    connect_deadline_ns: u64 = 0,
    idle_ns: u64,
    last_activity_ns: u64,
    sockmap_next_check_ns: u64 = 0,
    pairing: ?bpf.SockmapRuntime.Pairing = null,
    accelerator: ?*TCPSockmapAccelerator = null, // retained
    upstream_addr: config.SocketAddr,
    /// Captured for selector re-picks during failover (rules plugin only).
    client_addr: ?config.SocketAddr = null,
    /// Connect timeout per upstream attempt, from the accept-time snapshot.
    connect_ns: u64 = 0,
    /// Selector failovers already performed for this connection.
    failover_attempts: usize = 0,
    /// "[addr]:port" text; the longest form is an IPv6 literal (53 bytes).
    client_text: [56]u8 = undefined,
    client_text_len: usize = 0,
    bytes_to_upstream: i64 = 0,
    bytes_to_client: i64 = 0,
    dead: bool = false,
    next: ?*Connection = null,
    zombie_next: ?*Connection = null,

    fn clientText(self: *const Connection) []const u8 {
        return self.client_text[0..self.client_text_len];
    }

    fn peerOf(self: *Connection, endpoint: *Endpoint) *Endpoint {
        return if (endpoint.is_client) &self.upstream else &self.client;
    }
};

/// One side of a connection: an fd plus its outbound queue (data read from
/// the peer, waiting to be written to this fd) and its epoll registration.
const Endpoint = struct {
    connection: *Connection,
    fd: fd_t,
    is_client: bool,
    read_open: bool = true,
    read_wanted: bool = false,
    want_write: bool = false, // connecting: wait for EPOLLOUT
    fin_when_drained: bool = false,
    wr_shutdown: bool = false,
    registered: bool = false,
    registered_mask: u32 = 0,
    read_chunk: usize = initial_read_chunk,
    pending: std.ArrayList(u8) = .empty,
    pending_head: usize = 0,
    budget_bytes: usize = 0,

    fn pendingLen(self: *const Endpoint) usize {
        return self.budget_bytes;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sleepMs(milliseconds: u64) void {
    var ts = linux.timespec{
        .sec = @intCast(milliseconds / 1_000),
        .nsec = @intCast((milliseconds % 1_000) * 1_000_000),
    };
    while (true) {
        const rc = linux.nanosleep(&ts, &ts);
        if (linux.errno(rc) != .INTR) return;
    }
}

/// Minimal threaded TCP echo server on 127.0.0.1:0, used as the upstream in
/// the forwarding tests. One detached handler thread per connection.
const EchoServer = struct {
    state: *State,
    port: u16,

    const State = struct {
        listen_fd: fd_t,
        thread: std.Thread = undefined,
        stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        open_handlers: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    };

    fn start() !EchoServer {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        try testing.expect(linux.errno(rc) == .SUCCESS);
        const fd: fd_t = @intCast(rc);
        errdefer closeFd(fd);

        const yes: i32 = 1;
        _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(i32));

        var addr = linux.sockaddr.in{
            .port = 0,
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        try testing.expect(linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) == .SUCCESS);
        try testing.expect(linux.errno(linux.listen(fd, 128)) == .SUCCESS);

        var bound: linux.sockaddr.in = undefined;
        var bound_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
        try testing.expect(linux.errno(linux.getsockname(fd, @ptrCast(&bound), &bound_len)) == .SUCCESS);

        const state = try testing.allocator.create(State);
        errdefer testing.allocator.destroy(state);
        state.* = .{ .listen_fd = fd };
        state.thread = try std.Thread.spawn(.{}, EchoServer.acceptLoop, .{state});

        return EchoServer{
            .state = state,
            .port = std.mem.bigToNative(u16, bound.port),
        };
    }

    fn acceptLoop(self: *State) void {
        while (!self.stopping.load(.acquire)) {
            const rc = linux.accept(self.listen_fd, null, null);
            const errno = linux.errno(rc);
            if (errno != .SUCCESS) {
                if (errno == .INTR) continue;
                return; // EBADF after stop() closed the listener
            }
            const fd: fd_t = @intCast(rc);
            _ = self.open_handlers.fetchAdd(1, .acq_rel);
            const handler = std.Thread.spawn(.{}, EchoServer.echoLoop, .{ self, fd }) catch {
                closeFd(fd);
                _ = self.open_handlers.fetchSub(1, .acq_rel);
                continue;
            };
            handler.detach();
        }
    }

    fn echoLoop(self: *State, fd: fd_t) void {
        defer {
            closeFd(fd);
            _ = self.open_handlers.fetchSub(1, .acq_rel);
        }
        var buf: [64 * 1_024]u8 = undefined;
        while (!self.stopping.load(.acquire)) {
            const rc = linux.read(fd, &buf, buf.len);
            const errno = linux.errno(rc);
            if (errno != .SUCCESS) {
                if (errno == .INTR) continue;
                return;
            }
            const count: usize = @intCast(rc);
            if (count == 0) return;
            var written: usize = 0;
            while (written < count) {
                const wrc = linux.sendto(fd, buf[written..count].ptr, count - written, linux.MSG.NOSIGNAL, null, 0);
                const werrno = linux.errno(wrc);
                if (werrno != .SUCCESS) {
                    if (werrno == .INTR) continue;
                    return;
                }
                written += @intCast(wrc);
            }
        }
    }

    fn stop(self: *EchoServer) void {
        const state = self.state;
        state.stopping.store(true, .release);
        _ = linux.shutdown(state.listen_fd, linux.SHUT.RDWR);
        closeFd(state.listen_fd);
        state.thread.join();
        var attempts: usize = 0;
        while (state.open_handlers.load(.acquire) > 0 and attempts < 500) : (attempts += 1) {
            sleepMs(2);
        }
        testing.allocator.destroy(state);
    }
};

fn makeTestResolved(gpa: Allocator, upstream_port: u16) !config.ResolvedConfiguration {
    const listen = try gpa.alloc(config.SocketAddr, 1);
    listen[0] = config.SocketAddr.parseIp("127.0.0.1", 0).?;
    return .{
        .configuration = .{
            .version = 1,
            .protocols = @constCast(&[_]config.ForwardProtocol{.tcp}),
            .listen = .{ .host = "127.0.0.1", .port = 0 },
            .upstream = .{ .host = "127.0.0.1", .port = upstream_port },
            .timeouts = .{ .tcp_idle_seconds = 5 },
            .limits = .{
                .tcp_listen_backlog = 128,
                .max_tcp_buffered_bytes = 64 * 1_024 * 1_024,
                .max_udp_associations = 1_024,
                .max_udp_pending_datagrams = 64,
                .max_udp_pending_bytes = 256 * 1_024,
            },
        },
        .listen_addresses = listen,
        .upstream_address = config.SocketAddr.parseIp("127.0.0.1", upstream_port).?,
    };
}

/// Blocking loopback client socket with a receive timeout.
fn connectClient(port: u16) !fd_t {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    try testing.expect(linux.errno(rc) == .SUCCESS);
    const fd: fd_t = @intCast(rc);
    errdefer closeFd(fd);

    var timeout = linux.timeval{ .sec = 10, .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&timeout), @sizeOf(linux.timeval));

    var addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    try testing.expect(linux.errno(linux.connect(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) == .SUCCESS);
    return fd;
}

fn writeAll(fd: fd_t, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const rc = linux.sendto(fd, bytes.ptr + written, bytes.len - written, linux.MSG.NOSIGNAL, null, 0);
        const errno = linux.errno(rc);
        try testing.expect(errno == .SUCCESS);
        written += @intCast(rc);
    }
}

fn readFully(fd: fd_t, out: []u8) !void {
    var total: usize = 0;
    while (total < out.len) {
        const rc = linux.read(fd, out.ptr + total, out.len - total);
        const errno = linux.errno(rc);
        try testing.expect(errno == .SUCCESS);
        const count: usize = @intCast(rc);
        try testing.expect(count > 0); // EOF before the expected bytes
        total += count;
    }
}

fn waitForCondition(condition: *const fn () bool, timeout_ms: u64) bool {
    var waited: u64 = 0;
    while (waited < timeout_ms) {
        if (condition()) return true;
        sleepMs(5);
        waited += 5;
    }
    return condition();
}

test "tcp buffer budget caps aggregate queued bytes" {
    var budget = TCPBufferBudget.init(10);

    try testing.expect(budget.tryAcquire(6));
    try testing.expectEqual(@as(i64, 6), budget.used());
    try testing.expect(!budget.tryAcquire(5));

    budget.release(6);
    try testing.expect(budget.tryAcquire(10));
    budget.updateLimit(5);
    try testing.expect(!budget.tryAcquire(1));

    budget.release(10);
    try testing.expect(budget.tryAcquire(5));
    budget.release(5);
    try testing.expectEqual(@as(i64, 0), budget.used());
}

test "tcp splice helper moves bytes between stream sockets" {
    var source: [2]fd_t = undefined;
    try testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &source)),
    );
    defer closeFd(source[0]);
    defer closeFd(source[1]);

    var destination: [2]fd_t = undefined;
    try testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &destination)),
    );
    defer closeFd(destination[0]);
    defer closeFd(destination[1]);

    var pipe_fds: [2]fd_t = undefined;
    try testing.expectEqual(
        linux.E.SUCCESS,
        linux.errno(linux.pipe2(&pipe_fds, .{ .NONBLOCK = true, .CLOEXEC = true })),
    );
    defer closeFd(pipe_fds[0]);
    defer closeFd(pipe_fds[1]);

    const message = "splice without userspace payload copies";
    try writeAll(source[0], message);

    const into_pipe = spliceNonBlocking(source[1], pipe_fds[1], message.len, true);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(into_pipe));
    try testing.expectEqual(message.len, into_pipe);

    const into_socket = spliceNonBlocking(pipe_fds[0], destination[0], message.len, false);
    try testing.expectEqual(linux.E.SUCCESS, linux.errno(into_socket));
    try testing.expectEqual(message.len, into_socket);

    var received: [message.len]u8 = undefined;
    try readFully(destination[1], &received);
    try testing.expectEqualStrings(message, &received);
}

test "tcp echo roundtrip" {
    var echo = try EchoServer.start();
    defer echo.stop();

    var logger = log.LogStore.init("critical");
    const resolved = try makeTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = try TCPListener.init(resolved, &logger, .{
        .worker_threads = 2,
        .enable_sockmap_acceleration = false,
    });
    defer listener.deinit();
    try listener.start();
    try testing.expectEqual(@as(usize, 2), listener.listenerSocketCount());

    const listen_port = listener.localAddresses()[0].port;
    const client = try connectClient(listen_port);
    defer closeFd(client);

    // The accept is asynchronous; wait for the listener to see it.
    const one_connection = struct {
        var listener_ptr: *TCPListener = undefined;
        fn check() bool {
            return listener_ptr.activeConnectionCount() == 1;
        }
    };
    one_connection.listener_ptr = &listener;
    try testing.expect(waitForCondition(one_connection.check, 5_000));

    try writeAll(client, "hello curtsy");
    var received: [12]u8 = undefined;
    try readFully(client, &received);
    try testing.expectEqualStrings("hello curtsy", &received);

    // No relay bytes may remain queued once the echo returned.
    try testing.expectEqual(@as(i64, 0), listener.bufferedBytesUsed());

    listener.stopAccepting();
    try testing.expectEqual(@as(usize, 0), listener.listenerSocketCount());
    listener.forceCloseConnections();
    const drained = struct {
        var listener_ptr: *TCPListener = undefined;
        fn check() bool {
            return listener_ptr.activeConnectionCount() == 0;
        }
    };
    drained.listener_ptr = &listener;
    try testing.expect(waitForCondition(drained.check, 5_000));
}

test "tcp large transfer completes through batched flushes" {
    var echo = try EchoServer.start();
    defer echo.stop();

    var logger = log.LogStore.init("critical");
    const resolved = try makeTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = try TCPListener.init(resolved, &logger, .{
        .worker_threads = 2,
        .enable_sockmap_acceleration = false,
    });
    defer listener.deinit();
    try listener.start();
    defer {
        listener.stopAccepting();
        listener.forceCloseConnections();
    }

    const client = try connectClient(listener.localAddresses()[0].port);
    defer closeFd(client);

    // Interleave writes and reads of 64 KiB chunks over 8 MiB so the blocking
    // client socket never deadlocks against its own receive buffer.
    const total: usize = 8 * 1_024 * 1_024;
    const chunk: usize = 64 * 1_024;
    const send_buf = try testing.allocator.alloc(u8, chunk);
    defer testing.allocator.free(send_buf);
    @memset(send_buf, 0xa5);
    const recv_buf = try testing.allocator.alloc(u8, chunk);
    defer testing.allocator.free(recv_buf);

    var transferred: usize = 0;
    while (transferred < total) : (transferred += chunk) {
        try writeAll(client, send_buf);
        try readFully(client, recv_buf);
        try testing.expect(std.mem.allEqual(u8, recv_buf, 0xa5));
    }
    try testing.expectEqual(@as(i64, 0), listener.bufferedBytesUsed());
}

test "tcp splice relay sustains a large transfer" {
    var echo = try EchoServer.start();
    defer echo.stop();

    var logger = log.LogStore.init("critical");
    const resolved = try makeTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = try TCPListener.init(resolved, &logger, .{
        .worker_threads = 1,
        .enable_sockmap_acceleration = false,
    });
    defer listener.deinit();
    try listener.start();
    defer {
        listener.stopAccepting();
        listener.forceCloseConnections();
    }

    const client = try connectClient(listener.localAddresses()[0].port);
    defer closeFd(client);
    // Bound the send so a relay stall can never hang the writer thread; the
    // receive timeout set by connectClient bounds the read side the same way.
    var send_timeout = linux.timeval{ .sec = 10, .usec = 0 };
    _ = linux.setsockopt(client, linux.SOL.SOCKET, linux.SO.SNDTIMEO, std.mem.asBytes(&send_timeout), @sizeOf(linux.timeval));

    const total: usize = 4 * 1_024 * 1_024; // 4 MiB through the splice fast path
    const send_buf = try testing.allocator.alloc(u8, total);
    defer testing.allocator.free(send_buf);
    @memset(send_buf, 0x5c);
    const recv_buf = try testing.allocator.alloc(u8, total);
    defer testing.allocator.free(recv_buf);

    // Push the payload from a separate thread so the blocking client socket
    // cannot deadlock against its own receive buffer on the full-duplex
    // echo; the main thread drains the echo concurrently. Sustained back
    // pressure like this is what forces the splice chunk to grow. The writer
    // reports no shared state; a full 4 MiB echo through readFully below is
    // what proves the whole payload made the round trip.
    const Writer = struct {
        fn run(fd: fd_t, bytes: []const u8) !void {
            try writeAll(fd, bytes);
        }
    };
    const writer = try std.Thread.spawn(.{}, Writer.run, .{ client, send_buf });
    // Join exactly once on the success path below and on any error path
    // (errdefer) before the test unwinds and closes the client fd.
    errdefer writer.join();

    try readFully(client, recv_buf);
    try testing.expect(std.mem.allEqual(u8, recv_buf, 0x5c));
    try testing.expectEqual(@as(i64, 0), listener.bufferedBytesUsed());
    writer.join();
}

test "tcp listener uses resolved sockmap decision and allows test override" {
    var logger = log.LogStore.init("critical");
    const resolved = try makeTestResolved(testing.allocator, 9);
    defer testing.allocator.free(resolved.listen_addresses);

    const CountingLoader = struct {
        count: usize = 0,
        fn load(context: ?*anyopaque) bpf.Error!*TCPSockmapAccelerator {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.count += 1;
            return error.PermissionDenied;
        }
    };
    var counting = CountingLoader{};

    // Auto mode attempts to load even for loopback upstreams.
    var automatic = try TCPListener.init(resolved, &logger, .{
        .sockmap_loader = CountingLoader.load,
        .sockmap_loader_context = &counting,
    });
    defer automatic.deinit();
    try testing.expectEqual(@as(usize, 1), counting.count);

    // Failed loads are retried on configuration updates while sockmap stays
    // requested.
    automatic.updateConfiguration(resolved);
    try testing.expectEqual(@as(usize, 2), counting.count);

    // Explicit override forces the decision regardless of configuration.
    var disabled = try TCPListener.init(resolved, &logger, .{
        .enable_sockmap_acceleration = false,
        .sockmap_loader = CountingLoader.load,
        .sockmap_loader_context = &counting,
    });
    defer disabled.deinit();
    try testing.expectEqual(@as(usize, 2), counting.count);

    var enabled = try TCPListener.init(resolved, &logger, .{
        .enable_sockmap_acceleration = true,
        .sockmap_loader = CountingLoader.load,
        .sockmap_loader_context = &counting,
    });
    defer enabled.deinit();
    try testing.expectEqual(@as(usize, 3), counting.count);
}

test "tcp listening backlog can be updated in place" {
    var logger = log.LogStore.init("critical");
    const resolved = try makeTestResolved(testing.allocator, 9);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = try TCPListener.init(resolved, &logger, .{
        .worker_threads = 2,
        .enable_sockmap_acceleration = false,
    });
    defer listener.deinit();
    try listener.start();
    defer listener.stopAccepting();

    const addresses = try testing.allocator.dupe(config.SocketAddr, listener.localAddresses());
    defer testing.allocator.free(addresses);

    try listener.updateListeningBacklog(256);
    try testing.expectEqual(@as(i32, 256), listener.currentListeningBacklog());
    try testing.expectEqualSlices(config.SocketAddr, addresses, listener.localAddresses());

    // Same backlog is a no-op; ports did not change.
    try listener.updateListeningBacklog(256);
    try testing.expectEqual(@as(i32, 256), listener.currentListeningBacklog());
}

test "wildcard creates ipv4 and ipv6 listeners" {
    var logger = log.LogStore.init("critical");
    var resolved = try makeTestResolved(testing.allocator, 9);
    const original_listen_addresses = resolved.listen_addresses;
    defer testing.allocator.free(original_listen_addresses);
    resolved.configuration.listen.host = "*";
    const pair = try testing.allocator.alloc(config.SocketAddr, 2);
    defer testing.allocator.free(pair);
    pair[0] = config.SocketAddr.initV4(.{ 0, 0, 0, 0 }, 0);
    pair[1] = config.SocketAddr.initV6(@splat(0), 0);
    resolved.listen_addresses = pair;

    var listener = try TCPListener.init(resolved, &logger, .{
        .worker_threads = 2,
        .enable_sockmap_acceleration = false,
    });
    defer listener.deinit();
    try listener.start();
    defer listener.stopAccepting();

    try testing.expectEqual(@as(usize, 2), listener.localAddresses().len);
    try testing.expectEqual(@as(usize, 4), listener.listenerSocketCount());
    try testing.expectEqual(config.SocketAddr.Family.v4, listener.localAddresses()[0].family);
    try testing.expectEqual(config.SocketAddr.Family.v6, listener.localAddresses()[1].family);
}

test "tcp listener falls back when sockmap loader throws" {
    var echo = try EchoServer.start();
    defer echo.stop();

    var logger = log.LogStore.init("critical");
    const resolved = try makeTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);

    const FailingLoader = struct {
        fn load(context: ?*anyopaque) bpf.Error!*TCPSockmapAccelerator {
            _ = context;
            return error.PermissionDenied;
        }
    };

    var listener = try TCPListener.init(resolved, &logger, .{
        .worker_threads = 2,
        .enable_sockmap_acceleration = true,
        .sockmap_loader = FailingLoader.load,
    });
    defer listener.deinit();
    try listener.start();
    defer {
        listener.stopAccepting();
        listener.forceCloseConnections();
    }

    const client = try connectClient(listener.localAddresses()[0].port);
    defer closeFd(client);

    try writeAll(client, "fallback");
    var received: [8]u8 = undefined;
    try readFully(client, &received);
    try testing.expectEqualStrings("fallback", &received);
}

test "tcp idle timeout closes inactive connections" {
    var echo = try EchoServer.start();
    defer echo.stop();

    var logger = log.LogStore.init("critical");
    var resolved = try makeTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);
    resolved.configuration.timeouts.tcp_idle_seconds = 1;

    var listener = try TCPListener.init(resolved, &logger, .{
        .worker_threads = 1,
        .enable_sockmap_acceleration = false,
    });
    defer listener.deinit();
    try listener.start();
    defer {
        listener.stopAccepting();
        listener.forceCloseConnections();
    }

    const client = try connectClient(listener.localAddresses()[0].port);
    defer closeFd(client);

    const one_connection = struct {
        var listener_ptr: *TCPListener = undefined;
        fn check() bool {
            return listener_ptr.activeConnectionCount() == 1;
        }
    };
    one_connection.listener_ptr = &listener;
    try testing.expect(waitForCondition(one_connection.check, 5_000));

    // Without any traffic the connection is reaped after tcp_idle_seconds.
    const drained = struct {
        var listener_ptr: *TCPListener = undefined;
        fn check() bool {
            return listener_ptr.activeConnectionCount() == 0;
        }
    };
    drained.listener_ptr = &listener;
    try testing.expect(waitForCondition(drained.check, 5_000));
}

// ---------------------------------------------------------------------------
// Upstream selector hook tests (rules plugin)
// ---------------------------------------------------------------------------

const MockSelector = struct {
    addresses: []const config.SocketAddr,
    cursor: usize = 0,
    picks: std.ArrayList(config.SocketAddr) = .empty,
    failures: std.ArrayList(config.SocketAddr) = .empty,
    successes: std.ArrayList(config.SocketAddr) = .empty,

    fn selector(self: *MockSelector) UpstreamSelector {
        return .{
            .context = self,
            .is_multi_fn = isMulti,
            .pick_fn = pick,
            .report_success_fn = reportSuccess,
            .report_failure_fn = reportFailure,
        };
    }

    fn isMulti(context: *anyopaque) bool {
        const self: *MockSelector = @ptrCast(@alignCast(context));
        return self.addresses.len > 1;
    }

    fn deinit(self: *MockSelector) void {
        self.picks.deinit(testing.allocator);
        self.failures.deinit(testing.allocator);
        self.successes.deinit(testing.allocator);
    }

    fn pick(context: *anyopaque, client: ?config.SocketAddr, now_ns: u64) config.SocketAddr {
        _ = client;
        _ = now_ns;
        const self: *MockSelector = @ptrCast(@alignCast(context));
        const address = self.addresses[self.cursor % self.addresses.len];
        self.cursor += 1;
        self.picks.append(testing.allocator, address) catch {};
        return address;
    }

    fn reportSuccess(context: *anyopaque, upstream_addr: config.SocketAddr) void {
        const self: *MockSelector = @ptrCast(@alignCast(context));
        self.successes.append(testing.allocator, upstream_addr) catch {};
    }

    fn reportFailure(context: *anyopaque, upstream_addr: config.SocketAddr, now_ns: u64) void {
        _ = now_ns;
        const self: *MockSelector = @ptrCast(@alignCast(context));
        self.failures.append(testing.allocator, upstream_addr) catch {};
    }
};

test "tcp selector chooses the upstream per connection" {
    var echo_a = try EchoServer.start();
    defer echo_a.stop();
    var echo_b = try EchoServer.start();
    defer echo_b.stop();
    const addr_a = config.SocketAddr.parseIp("127.0.0.1", echo_a.port).?;
    const addr_b = config.SocketAddr.parseIp("127.0.0.1", echo_b.port).?;

    var mock = MockSelector{ .addresses = &.{ addr_a, addr_b } };
    defer mock.deinit();

    var logger = log.LogStore.init("critical");
    const resolved = try makeTestResolved(testing.allocator, echo_a.port);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = try TCPListener.init(resolved, &logger, .{
        .worker_threads = 2,
        .enable_sockmap_acceleration = false,
        .upstream_selector = mock.selector(),
    });
    defer listener.deinit();
    try listener.start();
    defer {
        listener.stopAccepting();
        listener.forceCloseConnections();
    }

    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const client = try connectClient(listener.localAddresses()[0].port);
        defer closeFd(client);
        try writeAll(client, "ping");
        var received: [4]u8 = undefined;
        try readFully(client, &received);
        try testing.expectEqualStrings("ping", &received);
    }

    // Every connection was routed through the selector, alternating upstreams.
    try testing.expectEqual(@as(usize, 4), mock.picks.items.len);
    for (mock.picks.items, 0..) |picked, n| {
        const expected = if (n % 2 == 0) addr_a else addr_b;
        try testing.expect(picked.eql(expected));
    }
    try testing.expectEqual(@as(usize, 0), mock.failures.items.len);
    try testing.expectEqual(@as(usize, 4), mock.successes.items.len);
}

test "tcp single upstream selector keeps the fixed upstream path" {
    var echo = try EchoServer.start();
    defer echo.stop();
    const address = config.SocketAddr.parseIp("127.0.0.1", echo.port).?;

    var mock = MockSelector{ .addresses = &.{address} };
    defer mock.deinit();

    var logger = log.LogStore.init("critical");
    const resolved = try makeTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = try TCPListener.init(resolved, &logger, .{
        .worker_threads = 1,
        .enable_sockmap_acceleration = false,
        .upstream_selector = mock.selector(),
    });
    defer listener.deinit();
    try listener.start();
    defer {
        listener.stopAccepting();
        listener.forceCloseConnections();
    }

    const client = try connectClient(listener.localAddresses()[0].port);
    defer closeFd(client);
    try writeAll(client, "ping");
    var received: [4]u8 = undefined;
    try readFully(client, &received);
    try testing.expectEqualStrings("ping", &received);

    try testing.expectEqual(@as(usize, 0), mock.picks.items.len);
    try testing.expectEqual(@as(usize, 0), mock.failures.items.len);
}

test "tcp selector fails over from a dead upstream and evicts it" {
    const pool_module = @import("upstream.zig");

    var echo = try EchoServer.start();
    defer echo.stop();
    const live = config.SocketAddr.parseIp("127.0.0.1", echo.port).?;
    const dead = config.SocketAddr.parseIp("127.0.0.1", 1).?; // nothing listens: ECONNREFUSED

    var pool = try pool_module.UpstreamPool.init(testing.allocator, &.{ dead, live }, &.{ 1, 1 }, pool_module.defaultBalancer());
    defer pool.deinit();

    const selector = pool_module.poolSelector(&pool);

    var logger = log.LogStore.init("critical");
    const resolved = try makeTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = try TCPListener.init(resolved, &logger, .{
        .worker_threads = 2,
        .enable_sockmap_acceleration = false,
        .upstream_selector = selector,
    });
    defer listener.deinit();
    try listener.start();
    defer {
        listener.stopAccepting();
        listener.forceCloseConnections();
    }

    // Every connection succeeds: the dead upstream always fails over to live.
    var i: usize = 0;
    while (i < pool_module.failure_threshold + 1) : (i += 1) {
        const client = try connectClient(listener.localAddresses()[0].port);
        defer closeFd(client);
        try writeAll(client, "ok");
        var received: [2]u8 = undefined;
        try readFully(client, &received);
        try testing.expectEqualStrings("ok", &received);
    }

    // After threshold failures the dead upstream is parked and picks return live.
    try testing.expect(pool.pick(null, pool_module.monotonicNowNs()).eql(live));
}
