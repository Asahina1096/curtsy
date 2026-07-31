//! Batched UDP relay and UDP sockmap acceleration.
//!
//! A `UdpListener` orchestrates `performance.udp_io_threads` engine threads
//! (0/auto = worker count). The first engine binds each configured listen
//! address; the remaining engines SO_REUSEPORT-bind the concrete addresses
//! the first one got, so the kernel hashes each client four-tuple to a
//! stable engine. Every engine thread epoll-manages its own listen, upstream
//! and per-client sockets and moves datagrams with 64-message
//! recvmmsg/sendmmsg batches. UDP connect is synchronous, so associations
//! are established on the first datagram with no pending-buffer window.
//!
//! Sessions are keyed by client four-tuple and share one global
//! `UdpAssociationBudget`, so `max_udp_associations` stays a global bound
//! rather than a per-thread quota. A 50 ms sweep reaps sessions idle beyond
//! `udp_session_seconds`.
//!
//! UDP sockmap acceleration (auto/enabled/disabled): the first datagram
//! establishes the session in userspace, then a per-client connected socket
//! (bound to the listen address with SO_REUSEPORT) is paired with the
//! upstream socket in that engine's own UDP sockhash; sessions never migrate
//! between engines. Expiry for steered sessions reads the BPF activity time
//! via `idleRemainingNs`. Expired or unpaired sessions fall back to the
//! listener and re-establish; pairing failures and SK_PASS datagrams are
//! relayed by userspace. Changing the mode via `updateConfiguration` clears
//! existing sessions and rebuilds under the new mode.

const std = @import("std");
const config = @import("config.zig");
const log = @import("log.zig");
const bpf = @import("bpf.zig");
const autotune = @import("autotune.zig");

const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const posix = std.posix;

pub const SocketAddr = config.SocketAddr;
pub const ResolvedConfiguration = config.ResolvedConfiguration;
pub const ForwarderConfiguration = config.ForwarderConfiguration;
pub const LogStore = log.LogStore;

const Mutex = log.Mutex;
const fd_t = bpf.fd_t;
const socklen_t = bpf.socklen_t;

extern "c" fn strerror(errnum: c_int) [*:0]u8;

/// Errno text for the most recent failed bpf.zig syscall on this thread.
fn errnoDescription() []const u8 {
    return std.mem.span(strerror(@intCast(@intFromEnum(bpf.lastErrno))));
}

// ---------------------------------------------------------------------------
// UDP association budget
// ---------------------------------------------------------------------------

/// Global association counter shared by all engine threads of a listener so
/// the configured limit stays a global bound. Acquire/release must stay
/// paired; releasing more than acquired trips a debug assertion.
pub const UdpAssociationBudget = struct {
    used: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn tryAcquire(self: *UdpAssociationBudget, limit: u64) bool {
        while (true) {
            const current = self.used.load(.monotonic);
            if (current >= limit) return false;
            if (self.used.cmpxchgWeak(current, current + 1, .monotonic, .monotonic) == null) return true;
        }
    }

    pub fn release(self: *UdpAssociationBudget, n: u64) void {
        if (n == 0) return;
        const previous = self.used.fetchSub(n, .monotonic);
        std.debug.assert(previous >= n); // UDP association budget released more than acquired
    }

    pub fn count(self: *const UdpAssociationBudget) u64 {
        return self.used.load(.monotonic);
    }
};

// ---------------------------------------------------------------------------
// RuntimeConfiguration: thread-safe configuration snapshot
// ---------------------------------------------------------------------------

/// Locked snapshot of the current resolved configuration. The stored value borrows its slices (listen
/// addresses, host strings, protocols); the caller guarantees that backing
/// memory outlives this object (e.g. the configuration arena).
pub const RuntimeConfiguration = struct {
    mutex: Mutex = .{},
    snapshot: ResolvedConfiguration,

    pub fn init(snapshot: ResolvedConfiguration) RuntimeConfiguration {
        return .{ .snapshot = snapshot };
    }

    pub fn current(self: *RuntimeConfiguration) ResolvedConfiguration {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.snapshot;
    }

    pub fn update(self: *RuntimeConfiguration, snapshot: ResolvedConfiguration) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.snapshot = snapshot;
    }
};

// ---------------------------------------------------------------------------
// Sockmap runtime loader (injectable, mirrors loadSockmapAccelerator)
// ---------------------------------------------------------------------------

/// Factory for the per-engine UDP sockmap runtime. The default is
/// `bpf.SockmapRuntime.createUdp`; tests inject a failing or counting fake.
pub const SockmapRuntimeLoader = *const fn (max_entries: u32, verifier_log: ?[]u8) bpf.Error!bpf.SockmapRuntime;

pub const default_sockmap_runtime_loader: SockmapRuntimeLoader = bpf.SockmapRuntime.createUdp;

/// Optional upstream-selection hook (rules plugin). When set, each new
/// association asks the selector for its upstream address instead of using
/// the configured one, and upstream socket errors/successes are reported
/// back for passive health tracking. When null the listener behaves exactly
/// as a single-upstream forwarder.
pub const UpstreamSelector = struct {
    context: *anyopaque,
    pick_fn: *const fn (context: *anyopaque, client: SocketAddr, now_ns: u64) SocketAddr,
    report_success_fn: *const fn (context: *anyopaque, upstream: SocketAddr) void,
    report_failure_fn: *const fn (context: *anyopaque, upstream: SocketAddr, now_ns: u64) void,

    pub fn pick(self: UpstreamSelector, client: SocketAddr, now_ns: u64) SocketAddr {
        return self.pick_fn(self.context, client, now_ns);
    }

    pub fn reportSuccess(self: UpstreamSelector, upstream: SocketAddr) void {
        self.report_success_fn(self.context, upstream);
    }

    pub fn reportFailure(self: UpstreamSelector, upstream: SocketAddr, now_ns: u64) void {
        self.report_failure_fn(self.context, upstream, now_ns);
    }
};

// ---------------------------------------------------------------------------
// UdpListener
// ---------------------------------------------------------------------------

pub const UdpListener = struct {
    pub const Error = bpf.Error || Allocator.Error || std.Thread.SpawnError;

    const EngineSlot = struct {
        /// Concrete addresses this engine bound at start (engines 1..n only;
        /// engine 0 shares the listener's runtime snapshot instead).
        listen_addresses: []SocketAddr = &.{},
        runtime: RuntimeConfiguration = undefined,
        engine: UdpRelayEngine = undefined,
    };

    allocator: Allocator,
    runtime: RuntimeConfiguration,
    log: *LogStore,
    enable_sockmap_override: ?bool,
    loader: ?SockmapRuntimeLoader,
    upstream_selector: ?UpstreamSelector = null,
    /// Shared across all engine threads so the configured association limit
    /// stays a global bound rather than a per-thread one.
    budget: UdpAssociationBudget = .{},
    engines: std.ArrayList(*EngineSlot) = .empty,

    /// `enable_sockmap_acceleration` overrides the resolved configuration
    /// decision when set (test hook).
    pub fn init(
        allocator: Allocator,
        configuration: ResolvedConfiguration,
        log_store: *LogStore,
        enable_sockmap_acceleration: ?bool,
        load_sockmap_runtime: ?SockmapRuntimeLoader,
    ) UdpListener {
        return initWithSelector(allocator, configuration, log_store, enable_sockmap_acceleration, load_sockmap_runtime, null);
    }

    /// init plus the rules plugin upstream-selection hook.
    pub fn initWithSelector(
        allocator: Allocator,
        configuration: ResolvedConfiguration,
        log_store: *LogStore,
        enable_sockmap_acceleration: ?bool,
        load_sockmap_runtime: ?SockmapRuntimeLoader,
        upstream_selector: ?UpstreamSelector,
    ) UdpListener {
        return .{
            .allocator = allocator,
            .runtime = RuntimeConfiguration.init(configuration),
            .log = log_store,
            .enable_sockmap_override = enable_sockmap_acceleration,
            .loader = load_sockmap_runtime,
            .upstream_selector = upstream_selector,
        };
    }

    pub fn start(self: *UdpListener) Error!void {
        const snapshot = self.runtime.current();
        const thread_count: u32 = @intCast(@max(1, autotune.workerThreads(
            snapshot.configuration.performance.udp_io_threads,
            .system(),
        )));
        errdefer self.stop();

        // The first engine binds the configured addresses; the rest bind the
        // addresses it actually got (relevant when the configured port is 0),
        // sharing each port through SO_REUSEPORT.
        try self.startEngine(&self.runtime, &.{}, thread_count, true);
        const bound = try self.engines.items[0].engine.localAddressesCopy(self.allocator);
        defer self.allocator.free(bound);
        for (1..thread_count) |_| {
            try self.startEngine(null, bound, thread_count, false);
        }
        if (thread_count > 1) {
            self.log.info("udp relay io_threads={d}", .{thread_count});
        }
    }

    fn startEngine(
        self: *UdpListener,
        runtime: ?*RuntimeConfiguration,
        listen_addresses: []const SocketAddr,
        engine_count: u32,
        announce_listen: bool,
    ) Error!void {
        const slot = try self.allocator.create(EngineSlot);
        errdefer self.allocator.destroy(slot);
        slot.* = .{};

        var runtime_ptr = runtime;
        if (runtime_ptr == null) {
            slot.listen_addresses = try self.allocator.dupe(SocketAddr, listen_addresses);
            errdefer self.allocator.free(slot.listen_addresses);
            const snapshot = self.runtime.current();
            slot.runtime = RuntimeConfiguration.init(.{
                .configuration = snapshot.configuration,
                .listen_addresses = slot.listen_addresses,
                .upstream_address = snapshot.upstream_address,
            });
            runtime_ptr = &slot.runtime;
        }
        slot.engine = UdpRelayEngine.init(
            runtime_ptr.?,
            self.log,
            &self.budget,
            self.allocator,
            engine_count,
            self.enable_sockmap_override,
            self.loader,
            announce_listen,
            self.upstream_selector,
        );
        errdefer slot.engine.destroy();
        try slot.engine.start();
        try self.engines.append(self.allocator, slot);
    }

    pub fn updateConfiguration(self: *UdpListener, configuration: ResolvedConfiguration, reset_associations: bool) void {
        // Timeout changes apply on each engine's next expiry sweep, which reads
        // the current snapshot; only upstream changes need association resets.
        self.runtime.update(configuration);
        for (self.engines.items, 0..) |slot, index| {
            if (index > 0) {
                // Keep the concrete addresses this engine bound at start; the
                // candidate may still carry the configured wildcard port 0.
                slot.runtime.update(.{
                    .configuration = configuration.configuration,
                    .listen_addresses = slot.listen_addresses,
                    .upstream_address = configuration.upstream_address,
                });
            }
            slot.engine.updateAccelerator();
            if (reset_associations) {
                slot.engine.resetAssociations();
            }
        }
    }

    /// Bound listen addresses of the first engine, allocated with `allocator`;
    /// the caller owns the returned slice.
    pub fn localAddresses(self: *UdpListener, allocator: Allocator) Allocator.Error![]SocketAddr {
        if (self.engines.items.len == 0) return allocator.alloc(SocketAddr, 0);
        return self.engines.items[0].engine.localAddressesCopy(allocator);
    }

    pub fn associationCount(self: *const UdpListener) u64 {
        return self.budget.count();
    }

    pub fn stop(self: *UdpListener) void {
        for (self.engines.items) |slot| {
            slot.engine.stop();
            slot.engine.destroy();
            if (slot.listen_addresses.len > 0) self.allocator.free(slot.listen_addresses);
            self.allocator.destroy(slot);
        }
        self.engines.clearRetainingCapacity();
    }

    pub fn deinit(self: *UdpListener) void {
        self.stop();
        self.engines.deinit(self.allocator);
    }
};

// ---------------------------------------------------------------------------
// UdpRelayEngine
// ---------------------------------------------------------------------------

pub const UdpRelayEngine = struct {
    pub const Error = bpf.Error || Allocator.Error || std.Thread.SpawnError;

    const Command = enum {
        reset_associations,
        reload_accelerator,
    };

    const Association = struct {
        client: SocketAddr,
        client_address: posix.sockaddr.storage,
        client_address_length: socklen_t,
        listen_fd: fd_t,
        upstream_fd: fd_t,
        /// Address the upstream socket is connected to; with a selector this
        /// is the picked address, otherwise the configured upstream.
        upstream_addr: SocketAddr,
        /// Set once the upstream answered, so reportSuccess fires once per
        /// association instead of per recv batch.
        reported_success: bool = false,
        /// Connected per-client socket and its kernel pairing; present only
        /// when this association is steered by the sockmap verdict program.
        client_fd: ?fd_t = null,
        pairing: ?bpf.SockmapRuntime.Pairing = null,
        last_activity_ms: u64,
        /// Next time a steered association's BPF activity timestamp must be
        /// consulted. BPF activity only moves the deadline later, so checks
        /// are scheduled by remaining idle time instead of every sweep —
        /// mirroring the TCP sockmap_next_check_ns scheme and avoiding two
        /// map lookups per session per sweep.
        sockmap_next_check_ms: u64 = 0,
    };

    const batch_size = bpf.udp_batch_capacity;
    const sweep_interval_ms: i32 = 50;
    /// Cap on recvmmsg batches drained per readiness event so one hot socket
    /// cannot starve the other ready fds on this engine.
    const max_batches_per_drain: usize = 16;
    /// After a sockmap pairing failure (typically a full map), skip further
    /// acceleration attempts for this long instead of paying the failed
    /// socket+pair cost for every new association.
    const accelerate_failure_cooldown_ms: u64 = 60_000;
    const send_error_log_interval_ms: u64 = 1_000;

    /// Hashes SocketAddr by its significant bytes only (matching
    /// SocketAddr.eql) instead of field-by-field autoHash.
    const SocketAddrContext = struct {
        pub fn hash(_: SocketAddrContext, key: SocketAddr) u64 {
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(switch (key.family) {
                .v4 => key.addr[0..4],
                .v6 => &key.addr,
            });
            var tail: [7]u8 = undefined;
            tail[0] = @intFromEnum(key.family);
            std.mem.writeInt(u16, tail[1..3], key.port, .little);
            std.mem.writeInt(u32, tail[3..7], key.scope_id, .little);
            hasher.update(&tail);
            return hasher.final();
        }

        pub fn eql(_: SocketAddrContext, a: SocketAddr, b: SocketAddr) bool {
            return a.eql(b);
        }
    };

    const AssociationMap = std.HashMap(SocketAddr, Association, SocketAddrContext, std.hash_map.default_max_load_percentage);

    runtime: *RuntimeConfiguration,
    log: *LogStore,
    budget: *UdpAssociationBudget,
    allocator: Allocator,
    /// Number of engine threads sharing this listener; used to size the
    /// per-engine sockmap so all maps together match the configured limit.
    engine_count: u32,
    announce_listen: bool,
    enable_sockmap_override: ?bool,
    loader: SockmapRuntimeLoader,
    upstream_selector: ?UpstreamSelector,

    command_mutex: Mutex = .{},
    /// Fast path flag so processCommands skips the mutex when no command
    /// was ever enqueued.
    command_pending: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    pending_commands: std.ArrayList(Command) = .empty,
    drained_commands: std.ArrayList(Command) = .empty,
    /// Guards wake_fd signalling (enqueue/stop) against the close in stop(),
    /// so a signal write can never land on a closed or reused descriptor.
    signal_mutex: Mutex = .{},
    stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    bound_mutex: Mutex = .{},
    bound_addresses: []SocketAddr = &.{},

    // I/O-thread-confined state below; only touched from run() and its
    // callees, plus the fds created in start() before the thread spawns.
    epoll_fd: fd_t = -1,
    wake_fd: fd_t = -1,
    listen_fds: []fd_t = &.{},
    associations: AssociationMap,
    upstream_to_client: std.AutoHashMap(fd_t, SocketAddr),
    client_fd_to_client: std.AutoHashMap(fd_t, SocketAddr),
    listen_bound: std.AutoHashMap(fd_t, posix.sockaddr.storage),
    sockmap_runtime: ?bpf.SockmapRuntime = null,
    warned_at_limit: bool = false,
    sweep_buffer: std.ArrayList(SocketAddr) = .empty,
    last_sweep_ms: u64 = 0,
    accelerate_cooldown_until_ms: u64 = 0,
    send_error_drops: u64 = 0,
    last_send_error_log_ms: u64 = 0,

    pub fn init(
        runtime: *RuntimeConfiguration,
        log_store: *LogStore,
        budget: *UdpAssociationBudget,
        allocator: Allocator,
        engine_count: u32,
        enable_sockmap_acceleration: ?bool,
        loader: ?SockmapRuntimeLoader,
        announce_listen: bool,
        upstream_selector: ?UpstreamSelector,
    ) UdpRelayEngine {
        return .{
            .runtime = runtime,
            .log = log_store,
            .budget = budget,
            .allocator = allocator,
            .engine_count = @max(1, engine_count),
            .announce_listen = announce_listen,
            .enable_sockmap_override = enable_sockmap_acceleration,
            .loader = loader orelse default_sockmap_runtime_loader,
            .upstream_selector = upstream_selector,
            .associations = AssociationMap.init(allocator),
            .upstream_to_client = std.AutoHashMap(fd_t, SocketAddr).init(allocator),
            .client_fd_to_client = std.AutoHashMap(fd_t, SocketAddr).init(allocator),
            .listen_bound = std.AutoHashMap(fd_t, posix.sockaddr.storage).init(allocator),
        };
    }

    pub fn start(self: *UdpRelayEngine) Error!void {
        const snapshot = self.runtime.current();

        var addresses: std.ArrayList(SocketAddr) = .empty;
        defer addresses.deinit(self.allocator);
        var created_fds: std.ArrayList(fd_t) = .empty;
        defer created_fds.deinit(self.allocator);
        var owned_fds: []fd_t = &.{};
        var owned_addresses: []SocketAddr = &.{};
        var epoll_fd: fd_t = -1;
        var wake_fd: fd_t = -1;
        errdefer {
            for (created_fds.items) |fd| _ = linux.close(fd);
            for (owned_fds) |fd| _ = linux.close(fd);
            if (owned_fds.len > 0) self.allocator.free(owned_fds);
            if (owned_addresses.len > 0) self.allocator.free(owned_addresses);
            if (epoll_fd >= 0) _ = linux.close(epoll_fd);
            if (wake_fd >= 0) _ = linux.close(wake_fd);
            self.listen_bound.clearRetainingCapacity();
            if (self.sockmap_runtime) |*runtime| {
                runtime.destroy();
                self.sockmap_runtime = null;
            }
        }

        for (snapshot.listen_addresses) |listen_address| {
            var storage: posix.sockaddr.storage = undefined;
            const storage_len = listen_address.toSockaddrStorage(@ptrCast(&storage));
            var bound: bpf.BoundAddress = undefined;
            const fd = try bpf.udpListenSocket(@ptrCast(&storage), storage_len, &bound);
            errdefer _ = linux.close(fd);
            const bound_address = socketAddrFromStorage(&bound.address) orelse {
                bpf.lastErrno = .AFNOSUPPORT;
                return error.NotSupported;
            };
            try self.listen_bound.put(fd, bound.address);
            try created_fds.append(self.allocator, fd);
            try addresses.append(self.allocator, bound_address);
            self.applySocketBuffers(fd, "listen={f}", .{bound_address}, true);
            if (self.announce_listen) {
                self.log.info("udp listening on {f}", .{bound_address});
            }
        }

        epoll_fd = try bpf.epollCreate();
        wake_fd = try bpf.eventfdCreate();
        try bpf.epollAdd(epoll_fd, wake_fd);
        for (created_fds.items) |fd| {
            try bpf.epollAdd(epoll_fd, fd);
        }

        const should_enable_sockmap = self.enable_sockmap_override orelse snapshot.shouldEnableUDPSockmap();
        if (should_enable_sockmap) {
            if (self.tryLoadAccelerator(&snapshot)) {
                self.log.info("udp sockmap acceleration enabled", .{});
            }
        } else {
            self.log.info("udp sockmap acceleration disabled", .{});
        }

        // Pre-size the session maps so steady-state growth never rehashes
        // (and heap-allocates) on the I/O thread's first-datagram path.
        const per_engine_capacity: u32 = @intCast(@min(
            @divTrunc(@max(1, snapshot.configuration.limits.max_udp_associations), @as(i64, self.engine_count)) + 1,
            1 << 20,
        ));
        self.associations.ensureTotalCapacity(per_engine_capacity) catch {};
        self.upstream_to_client.ensureTotalCapacity(per_engine_capacity) catch {};
        self.client_fd_to_client.ensureTotalCapacity(per_engine_capacity) catch {};

        owned_fds = try created_fds.toOwnedSlice(self.allocator);
        owned_addresses = try addresses.toOwnedSlice(self.allocator);

        // Commit everything to the engine before spawning; from here on the
        // errdefer above must not touch the moved state, so the locals are
        // cleared and spawn failure tears down through the engine fields.
        self.epoll_fd = epoll_fd;
        self.wake_fd = wake_fd;
        self.listen_fds = owned_fds;
        self.bound_mutex.lock();
        self.bound_addresses = owned_addresses;
        self.bound_mutex.unlock();
        epoll_fd = -1;
        wake_fd = -1;
        owned_fds = &.{};
        owned_addresses = &.{};

        self.thread = std.Thread.spawn(.{}, UdpRelayEngine.run, .{self}) catch |err| {
            self.teardown();
            self.signal_mutex.lock();
            if (self.wake_fd >= 0) {
                _ = linux.close(self.wake_fd);
                self.wake_fd = -1;
            }
            self.signal_mutex.unlock();
            self.bound_mutex.lock();
            if (self.bound_addresses.len > 0) self.allocator.free(self.bound_addresses);
            self.bound_addresses = &.{};
            self.bound_mutex.unlock();
            return err;
        };
    }

    /// Bound listen addresses, allocated with `allocator`; caller owns them.
    pub fn localAddressesCopy(self: *UdpRelayEngine, allocator: Allocator) Allocator.Error![]SocketAddr {
        self.bound_mutex.lock();
        defer self.bound_mutex.unlock();
        return allocator.dupe(SocketAddr, self.bound_addresses);
    }

    pub fn associationCount(self: *const UdpRelayEngine) u64 {
        return self.budget.count();
    }

    pub fn resetAssociations(self: *UdpRelayEngine) void {
        self.enqueue(.reset_associations);
    }

    pub fn updateAccelerator(self: *UdpRelayEngine) void {
        self.enqueue(.reload_accelerator);
    }

    pub fn stop(self: *UdpRelayEngine) void {
        const was_running = self.stop_requested.swap(true, .acq_rel);
        if (was_running) return;
        // The wake fd stays open until the thread is joined below, so this
        // signal can never land on a closed or reused descriptor.
        self.signal_mutex.lock();
        if (self.wake_fd >= 0) bpf.eventfdSignal(self.wake_fd);
        self.signal_mutex.unlock();
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
            self.signal_mutex.lock();
            if (self.wake_fd >= 0) {
                _ = linux.close(self.wake_fd);
                self.wake_fd = -1;
            }
            self.signal_mutex.unlock();
        }
        self.bound_mutex.lock();
        if (self.bound_addresses.len > 0) self.allocator.free(self.bound_addresses);
        self.bound_addresses = &.{};
        self.bound_mutex.unlock();
    }

    /// Frees resources still owned after stop(); call exactly once, after
    /// stop() has joined the I/O thread (or after a failed start()).
    pub fn destroy(self: *UdpRelayEngine) void {
        self.associations.deinit();
        self.upstream_to_client.deinit();
        self.client_fd_to_client.deinit();
        self.listen_bound.deinit();
        self.pending_commands.deinit(self.allocator);
        self.drained_commands.deinit(self.allocator);
        self.sweep_buffer.deinit(self.allocator);
        if (self.bound_addresses.len > 0) {
            self.allocator.free(self.bound_addresses);
            self.bound_addresses = &.{};
        }
        if (self.listen_fds.len > 0) {
            for (self.listen_fds) |fd| _ = linux.close(fd);
            self.allocator.free(self.listen_fds);
            self.listen_fds = &.{};
        }
        if (self.epoll_fd >= 0) {
            _ = linux.close(self.epoll_fd);
            self.epoll_fd = -1;
        }
        if (self.wake_fd >= 0) {
            _ = linux.close(self.wake_fd);
            self.wake_fd = -1;
        }
        if (self.sockmap_runtime) |*runtime| {
            runtime.destroy();
            self.sockmap_runtime = null;
        }
    }

    fn enqueue(self: *UdpRelayEngine, command: Command) void {
        self.command_mutex.lock();
        self.pending_commands.append(self.allocator, command) catch {
            self.command_mutex.unlock();
            return;
        };
        self.command_pending.store(true, .release);
        self.command_mutex.unlock();
        self.signal_mutex.lock();
        if (self.wake_fd >= 0) bpf.eventfdSignal(self.wake_fd);
        self.signal_mutex.unlock();
    }

    fn run(self: *UdpRelayEngine) void {
        setThreadName();
        defer self.teardown();

        // Slot capacity is configurable: smaller buffers improve cache/TLB
        // locality for small-datagram workloads.
        const slot_capacity: usize = @intCast(self.runtime.current().configuration.performance.udp_datagram_buffer_bytes);
        const buffer = self.allocator.alloc(u8, batch_size * slot_capacity) catch {
            self.log.critical("udp relay buffer allocation failed", .{});
            return;
        };
        defer self.allocator.free(buffer);

        var recv_slots: [batch_size]bpf.UdpSlot = undefined;
        for (&recv_slots, 0..) |*slot, index| {
            slot.* = .{
                .data = buffer[index * slot_capacity ..].ptr,
                .capacity = @intCast(slot_capacity),
            };
        }
        var recv_io: bpf.UdpRecvBatchIo = undefined;
        recv_io.init(&recv_slots);
        var send_slots: [batch_size]bpf.UdpSlot = undefined;
        var ready_fds: [batch_size + 1]fd_t = undefined;

        while (!self.stop_requested.load(.acquire)) {
            const ready = bpf.epollWait(self.epoll_fd, &ready_fds, sweep_interval_ms) catch {
                self.log.err("udp event wait failed error={s}", .{errnoDescription()});
                continue;
            };

            // One timestamp per epoll wake, reused by every drain/forward.
            const now_ms = monotonicMilliseconds();

            self.processCommands();

            for (ready_fds[0..ready]) |fd| {
                if (fd == self.wake_fd) {
                    bpf.eventfdDrain(self.wake_fd);
                } else if (self.client_fd_to_client.get(fd)) |client| {
                    self.drainClient(fd, client, &recv_slots, &recv_io, now_ms);
                } else if (self.upstream_to_client.get(fd)) |client| {
                    self.drainUpstream(fd, client, &recv_slots, &recv_io, now_ms);
                } else {
                    self.drainListen(fd, &recv_slots, &send_slots, &recv_io, now_ms);
                }
            }
            // The 50 ms sweep is throttled by elapsed time, not by wake
            // count: busy engines would otherwise rescan all sessions after
            // every batch.
            if (now_ms -% self.last_sweep_ms >= sweep_interval_ms) {
                self.last_sweep_ms = now_ms;
                self.sweepExpiredAssociations(now_ms);
            }
        }
    }

    fn processCommands(self: *UdpRelayEngine) void {
        if (!self.command_pending.load(.acquire)) return;
        self.command_mutex.lock();
        std.mem.swap(std.ArrayList(Command), &self.pending_commands, &self.drained_commands);
        self.command_pending.store(false, .monotonic);
        self.command_mutex.unlock();
        for (self.drained_commands.items) |command| {
            switch (command) {
                .reset_associations => self.closeAllAssociations(),
                .reload_accelerator => self.reloadAccelerator(),
            }
        }
        self.drained_commands.clearRetainingCapacity();
    }

    fn teardown(self: *UdpRelayEngine) void {
        self.closeAllAssociations();
        for (self.listen_fds) |fd| _ = linux.close(fd);
        if (self.listen_fds.len > 0) self.allocator.free(self.listen_fds);
        self.listen_fds = &.{};
        self.listen_bound.clearRetainingCapacity();
        if (self.epoll_fd >= 0) {
            _ = linux.close(self.epoll_fd);
            self.epoll_fd = -1;
        }
        if (self.sockmap_runtime) |*runtime| {
            runtime.destroy();
            self.sockmap_runtime = null;
        }
        // wake_fd deliberately stays open: stop() closes it after joining
        // this thread, so a racing enqueue can never signal a closed or
        // reused descriptor.
    }

    fn sockmapMaxEntries(snapshot: *const ResolvedConfiguration, engine_count: u32) u32 {
        const associations = @divTrunc(snapshot.configuration.limits.max_udp_associations, @as(i64, engine_count));
        if (associations > std.math.maxInt(u32) / 2) {
            return std.math.maxInt(u32);
        }
        return @intCast(@max(1024, associations * 2));
    }

    fn tryLoadAccelerator(self: *UdpRelayEngine, snapshot: *const ResolvedConfiguration) bool {
        var verifier_log: [4096]u8 = undefined;
        verifier_log[0] = 0;
        self.sockmap_runtime = self.loader(sockmapMaxEntries(snapshot, self.engine_count), &verifier_log) catch {
            self.log.warning(
                "udp sockmap acceleration unavailable; using userspace relay error={s} verifier={s}",
                .{ errnoDescription(), std.mem.sliceTo(&verifier_log, 0) },
            );
            return false;
        };
        return true;
    }

    // Oversized requests are silently clamped to the kernel rmem/wmem maxima,
    // so only genuine failures (not clamping) surface here.
    fn applySocketBuffers(
        self: *UdpRelayEngine,
        fd: fd_t,
        comptime context_fmt: []const u8,
        context_args: anytype,
        warn_on_failure: bool,
    ) void {
        const bytes = self.runtime.current().configuration.performance.udp_socket_buffer_bytes;
        if (bytes <= 0) return;
        bpf.udpSetSocketBuffers(fd, @intCast(bytes)) catch {
            if (warn_on_failure) {
                self.log.warning(
                    "udp socket buffer setup failed " ++ context_fmt ++ " bytes={d} error={s}",
                    context_args ++ .{ bytes, errnoDescription() },
                );
            } else {
                self.log.debug(
                    "udp socket buffer setup failed " ++ context_fmt ++ " bytes={d} error={s}",
                    context_args ++ .{ bytes, errnoDescription() },
                );
            }
        };
    }

    fn reloadAccelerator(self: *UdpRelayEngine) void {
        const snapshot = self.runtime.current();
        const requested = self.enable_sockmap_override orelse snapshot.shouldEnableUDPSockmap();
        if (requested and self.sockmap_runtime == null) {
            if (self.tryLoadAccelerator(&snapshot)) {
                self.log.info("udp sockmap acceleration enabled", .{});
                // Only newly established associations are steered.
                self.closeAllAssociations();
            }
        } else if (!requested and self.sockmap_runtime != null) {
            self.log.info("udp sockmap acceleration disabled", .{});
            // Close first so existing sessions fall back to the userspace
            // relay before the runtime is destroyed.
            self.closeAllAssociations();
            self.sockmap_runtime.?.destroy();
            self.sockmap_runtime = null;
        }
    }

    fn drainListen(
        self: *UdpRelayEngine,
        fd: fd_t,
        recv_slots: *[batch_size]bpf.UdpSlot,
        send_slots: *[batch_size]bpf.UdpSlot,
        recv_io: *bpf.UdpRecvBatchIo,
        now_ms: u64,
    ) void {
        var batches: usize = 0;
        while (batches < max_batches_per_drain) : (batches += 1) {
            const received = recv_io.recv(fd, recv_slots) catch {
                self.log.err("udp listener read failed error={s}", .{errnoDescription()});
                return;
            };
            if (received == 0) return;
            self.forwardClientDatagrams(received, fd, recv_slots, send_slots, now_ms);
        }
    }

    fn forwardClientDatagrams(
        self: *UdpRelayEngine,
        count: usize,
        listen_fd: fd_t,
        recv_slots: *[batch_size]bpf.UdpSlot,
        send_slots: *[batch_size]bpf.UdpSlot,
        now_ms: u64,
    ) void {
        var run_fd: fd_t = -1;
        var run_length: usize = 0;
        for (recv_slots[0..count]) |*slot| {
            const client = socketAddrFromStorage(&slot.address) orelse continue;
            const upstream_fd: fd_t = blk: {
                if (self.associations.getPtr(client)) |existing| {
                    existing.last_activity_ms = now_ms;
                    break :blk existing.upstream_fd;
                }
                break :blk self.openAssociation(
                    client,
                    slot.address,
                    slot.address_length,
                    listen_fd,
                    now_ms,
                ) orelse continue;
            };
            if (upstream_fd != run_fd) {
                if (run_length > 0) {
                    _ = self.sendAllDatagrams(run_fd, null, 0, send_slots[0..run_length], "direction=client_to_upstream", now_ms);
                }
                run_fd = upstream_fd;
                run_length = 0;
            }
            send_slots[run_length].data = slot.data;
            send_slots[run_length].length = slot.length;
            run_length += 1;
        }
        if (run_length > 0) {
            _ = self.sendAllDatagrams(run_fd, null, 0, send_slots[0..run_length], "direction=client_to_upstream", now_ms);
        }
    }

    // Fallback path for an accelerated association: datagrams queued on the
    // connected client socket before pairing completed (or passed through via
    // SK_PASS) are relayed by userspace like ordinary listen-socket traffic.
    fn drainClient(
        self: *UdpRelayEngine,
        fd: fd_t,
        client: SocketAddr,
        recv_slots: *[batch_size]bpf.UdpSlot,
        recv_io: *bpf.UdpRecvBatchIo,
        now_ms: u64,
    ) void {
        const association = self.associations.getPtr(client) orelse return;
        var batches: usize = 0;
        while (batches < max_batches_per_drain) : (batches += 1) {
            const received = recv_io.recv(fd, recv_slots) catch {
                self.log.err("udp client socket read failed client={f} error={s}", .{ client, errnoDescription() });
                self.closeAssociation(client);
                return;
            };
            if (received == 0) return;
            association.last_activity_ms = now_ms;
            _ = self.sendAllDatagrams(
                association.upstream_fd,
                null,
                0,
                recv_slots[0..received],
                "direction=client_to_upstream",
                now_ms,
            );
        }
    }

    fn drainUpstream(
        self: *UdpRelayEngine,
        fd: fd_t,
        client: SocketAddr,
        recv_slots: *[batch_size]bpf.UdpSlot,
        recv_io: *bpf.UdpRecvBatchIo,
        now_ms: u64,
    ) void {
        const association = self.associations.getPtr(client) orelse return;
        var batches: usize = 0;
        while (batches < max_batches_per_drain) : (batches += 1) {
            const received = recv_io.recv(fd, recv_slots) catch {
                self.log.err("udp upstream error client={f} error={s}", .{ client, errnoDescription() });
                if (self.upstream_selector) |selector| {
                    selector.reportFailure(association.upstream_addr, now_ms * std.time.ns_per_ms);
                }
                self.closeAssociation(client);
                return;
            };
            if (received == 0) return;
            association.last_activity_ms = now_ms;
            if (!association.reported_success) {
                association.reported_success = true;
                if (self.upstream_selector) |selector| selector.reportSuccess(association.upstream_addr);
            }
            const address: *const posix.sockaddr = @ptrCast(&association.client_address);
            _ = self.sendAllDatagrams(
                association.listen_fd,
                address,
                association.client_address_length,
                recv_slots[0..received],
                "direction=upstream_to_client",
                now_ms,
            );
        }
    }

    fn sendAllDatagrams(
        self: *UdpRelayEngine,
        fd: fd_t,
        address: ?*const posix.sockaddr,
        address_length: socklen_t,
        slots: []const bpf.UdpSlot,
        comptime context: []const u8,
        now_ms: u64,
    ) bool {
        if (slots.len == 0) return true;
        var sent_total: usize = 0;
        while (sent_total < slots.len) {
            const sent = bpf.udpSendBatch(fd, address, address_length, slots[sent_total..]) catch {
                self.noteSendError(slots.len - sent_total, context, errnoDescription(), now_ms);
                return false;
            };
            if (sent == 0) {
                self.noteSendError(slots.len - sent_total, context, "sendmmsg made no progress", now_ms);
                return false;
            }
            sent_total += sent;
        }
        return true;
    }

    /// Drop logging is rate-limited per engine: sustained backpressure would
    /// otherwise serialize all engine threads on the shared log mutex once
    /// per failed batch.
    fn noteSendError(self: *UdpRelayEngine, dropped: usize, comptime context: []const u8, error_text: []const u8, now_ms: u64) void {
        self.send_error_drops += dropped;
        if (now_ms -% self.last_send_error_log_ms < send_error_log_interval_ms) return;
        self.last_send_error_log_ms = now_ms;
        self.log.warning("udp datagrams dropped {s} dropped={d} total_dropped={d} error={s}", .{
            context,
            dropped,
            self.send_error_drops,
            error_text,
        });
    }

    fn openAssociation(
        self: *UdpRelayEngine,
        client: SocketAddr,
        client_address: posix.sockaddr.storage,
        client_address_length: socklen_t,
        listen_fd: fd_t,
        now_ms: u64,
    ) ?fd_t {
        const snapshot = self.runtime.current();
        const limit: u64 = @intCast(snapshot.configuration.limits.max_udp_associations);
        if (!self.budget.tryAcquire(limit)) {
            if (!self.warned_at_limit) {
                self.warned_at_limit = true;
                self.log.warning("udp association limit reached limit={d}", .{limit});
            }
            return null;
        }
        return self.establishAssociation(client, client_address, client_address_length, listen_fd, &snapshot, now_ms) catch |err| {
            self.budget.release(1);
            self.log.err("udp association failed client={f} error={s}", .{ client, @errorName(err) });
            return null;
        };
    }

    fn establishAssociation(
        self: *UdpRelayEngine,
        client: SocketAddr,
        client_address: posix.sockaddr.storage,
        client_address_length: socklen_t,
        listen_fd: fd_t,
        snapshot: *const ResolvedConfiguration,
        now_ms: u64,
    ) Error!fd_t {
        // The selector (rules plugin) picks the upstream per association;
        // without one the configured upstream is used.
        const upstream_address = if (self.upstream_selector) |selector|
            selector.pick(client, now_ms * std.time.ns_per_ms)
        else
            snapshot.upstream_address;

        var upstream_storage: posix.sockaddr.storage = undefined;
        const upstream_len = upstream_address.toSockaddrStorage(@ptrCast(&upstream_storage));
        const upstream_fd = try bpf.udpUpstreamSocket(@ptrCast(&upstream_storage), upstream_len);
        errdefer _ = linux.close(upstream_fd);
        try bpf.epollAdd(self.epoll_fd, upstream_fd);
        self.applySocketBuffers(upstream_fd, "direction=upstream client={f}", .{client}, false);

        var client_fd: ?fd_t = null;
        var pairing: ?bpf.SockmapRuntime.Pairing = null;
        errdefer {
            if (pairing) |p| {
                if (self.sockmap_runtime) |*runtime| runtime.unpair(p.client_cookie, p.upstream_cookie);
            }
            if (client_fd) |fd| _ = linux.close(fd);
        }
        if (self.sockmap_runtime != null and now_ms >= self.accelerate_cooldown_until_ms) {
            if (self.listen_bound.get(listen_fd)) |bind_storage| {
                if (self.accelerateAssociation(bind_storage, client_address, client_address_length, upstream_fd)) |accelerated| {
                    client_fd = accelerated.fd;
                    pairing = accelerated.pairing;
                } else |err| {
                    // Kernel steering is best-effort per association; fall
                    // back to the userspace relay for this client. Repeated
                    // failures (e.g. a full sockhash) pause further attempts
                    // so every new session does not pay the failed pair cost.
                    self.accelerate_cooldown_until_ms = now_ms + accelerate_failure_cooldown_ms;
                    self.log.debug("udp sockmap pairing failed client={f} error={s}", .{ client, @errorName(err) });
                }
            }
        }

        const association = Association{
            .client = client,
            .client_address = client_address,
            .client_address_length = client_address_length,
            .listen_fd = listen_fd,
            .upstream_fd = upstream_fd,
            .upstream_addr = upstream_address,
            .client_fd = client_fd,
            .pairing = pairing,
            .last_activity_ms = now_ms,
        };
        try self.associations.put(client, association);
        errdefer _ = self.associations.remove(client);
        try self.upstream_to_client.put(upstream_fd, client);
        errdefer _ = self.upstream_to_client.remove(upstream_fd);
        if (client_fd) |fd| {
            try self.client_fd_to_client.put(fd, client);
        }
        self.warned_at_limit = false;
        self.log.debug("udp association opened client={f} upstream={f}", .{ client, upstream_address });
        return upstream_fd;
    }

    const Acceleration = struct {
        fd: fd_t,
        pairing: bpf.SockmapRuntime.Pairing,
    };

    // Creates the connected per-client socket and pairs it with the upstream
    // socket in the sockmap. Once bound, the kernel demux prefers this
    // four-tuple socket over the wildcard listener, so subsequent datagrams
    // from the client are steered by the verdict program.
    fn accelerateAssociation(
        self: *UdpRelayEngine,
        bind_storage: posix.sockaddr.storage,
        client_address: posix.sockaddr.storage,
        client_address_length: socklen_t,
        upstream_fd: fd_t,
    ) Error!Acceleration {
        const bind_length: socklen_t = switch (bind_storage.family) {
            linux.AF.INET => @sizeOf(posix.sockaddr.in),
            linux.AF.INET6 => @sizeOf(posix.sockaddr.in6),
            else => return error.NotSupported,
        };
        const bind_address: *const posix.sockaddr = @ptrCast(&bind_storage);
        const peer_address: *const posix.sockaddr = @ptrCast(&client_address);
        const fd = try bpf.udpConnectedClientSocket(bind_address, bind_length, peer_address, client_address_length);
        errdefer _ = linux.close(fd);
        self.applySocketBuffers(fd, "direction=client", .{}, false);
        if (self.sockmap_runtime == null) return error.NotSupported;
        const runtime = &self.sockmap_runtime.?;
        const pairing = try runtime.pair(fd, upstream_fd);
        errdefer runtime.unpair(pairing.client_cookie, pairing.upstream_cookie);
        try bpf.epollAdd(self.epoll_fd, fd);
        return .{ .fd = fd, .pairing = pairing };
    }

    fn closeAssociation(self: *UdpRelayEngine, client: SocketAddr) void {
        const removed = self.associations.fetchRemove(client) orelse return;
        const association = removed.value;
        // Stop kernel steering first; further datagrams then fall back to the
        // userspace relay (or to the listener once the sockets are gone).
        if (association.pairing) |p| {
            if (self.sockmap_runtime) |*runtime| runtime.unpair(p.client_cookie, p.upstream_cookie);
        }
        _ = self.upstream_to_client.remove(association.upstream_fd);
        if (association.client_fd) |fd| {
            _ = self.client_fd_to_client.remove(fd);
            _ = linux.close(fd);
        }
        _ = linux.close(association.upstream_fd);
        self.budget.release(1);
        self.warned_at_limit = false;
    }

    fn closeAllAssociations(self: *UdpRelayEngine) void {
        self.sweep_buffer.clearRetainingCapacity();
        var iterator = self.associations.keyIterator();
        while (iterator.next()) |key| {
            self.sweep_buffer.append(self.allocator, key.*) catch break;
        }
        for (self.sweep_buffer.items) |client| {
            self.closeAssociation(client);
        }
        self.sweep_buffer.clearRetainingCapacity();
    }

    fn sweepExpiredAssociations(self: *UdpRelayEngine, now_ms: u64) void {
        const timeout_seconds = self.runtime.current().configuration.timeouts.udp_session_seconds;
        const timeout_ms = @as(u64, @intCast(@max(1, timeout_seconds))) * 1_000;
        const timeout_ns = timeout_ms * 1_000_000;

        self.sweep_buffer.clearRetainingCapacity();
        defer self.sweep_buffer.clearRetainingCapacity();
        var iterator = self.associations.iterator();
        while (iterator.next()) |entry| {
            const association = entry.value_ptr;
            const expired = blk: {
                if (association.pairing) |p| {
                    // Steered traffic never reaches userspace; the BPF peer
                    // state holds the last-activity timestamp instead. The
                    // check is due only when the remaining idle time from the
                    // previous lookup has elapsed.
                    if (now_ms < association.sockmap_next_check_ms) break :blk false;
                    if (self.sockmap_runtime) |*runtime| {
                        const remaining = runtime.idleRemainingNs(p.client_cookie, p.upstream_cookie, timeout_ns) catch break :blk true;
                        if (remaining == 0) break :blk true;
                        association.sockmap_next_check_ms = now_ms + @max(1, remaining / 1_000_000);
                        break :blk false;
                    }
                    break :blk true;
                }
                break :blk now_ms -% association.last_activity_ms >= timeout_ms;
            };
            if (expired) {
                self.log.debug("udp association expired client={f}", .{entry.key_ptr.*});
                self.sweep_buffer.append(self.allocator, entry.key_ptr.*) catch break;
            }
        }
        for (self.sweep_buffer.items) |client| {
            self.closeAssociation(client);
        }
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn monotonicMilliseconds() u64 {
    var time: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &time);
    return @as(u64, @intCast(time.sec)) * 1_000 + @as(u64, @intCast(time.nsec)) / 1_000_000;
}

fn setThreadName() void {
    const name = "curtsy-udp-io";
    _ = linux.prctl(@intFromEnum(linux.PR.SET_NAME), @intFromPtr(name.ptr), 0, 0, 0);
}

fn socketAddrFromStorage(storage: *const posix.sockaddr.storage) ?SocketAddr {
    switch (storage.family) {
        linux.AF.INET => {
            const in: *const posix.sockaddr.in = @ptrCast(@alignCast(storage));
            return SocketAddr.initV4(@bitCast(in.addr), std.mem.bigToNative(u16, in.port));
        },
        linux.AF.INET6 => {
            const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(storage));
            var address = SocketAddr.initV6(in6.addr, std.mem.bigToNative(u16, in6.port));
            address.scope_id = in6.scope_id;
            return address;
        },
        else => return null,
    }
}

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

fn closeFd(fd: fd_t) void {
    _ = linux.close(fd);
}

/// Minimal threaded UDP echo server on 127.0.0.1:0.
const UdpEchoServer = struct {
    fd: fd_t,
    port: u16,
    thread: std.Thread = undefined,
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn start() !*UdpEchoServer {
        const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        try testing.expect(linux.errno(rc) == .SUCCESS);
        const fd: fd_t = @intCast(rc);
        errdefer closeFd(fd);

        var addr = linux.sockaddr.in{
            .port = 0,
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        try testing.expect(linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) == .SUCCESS);
        var bound = linux.sockaddr.in{ .port = 0, .addr = 0 };
        var bound_len: socklen_t = @sizeOf(linux.sockaddr.in);
        try testing.expect(linux.errno(linux.getsockname(fd, @ptrCast(&bound), &bound_len)) == .SUCCESS);

        const server = try testing.allocator.create(UdpEchoServer);
        errdefer testing.allocator.destroy(server);
        server.* = .{ .fd = fd, .port = std.mem.bigToNative(u16, bound.port) };
        server.thread = try std.Thread.spawn(.{}, UdpEchoServer.loop, .{server});
        return server;
    }

    fn loop(self: *UdpEchoServer) void {
        var buf: [2_048]u8 = undefined;
        while (!self.stopping.load(.acquire)) {
            var fds = [_]posix.pollfd{.{ .fd = self.fd, .events = linux.POLL.IN, .revents = 0 }};
            const ready = posix.poll(&fds, 50) catch return;
            if (ready == 0) continue;
            var src: posix.sockaddr.storage = undefined;
            var src_len: socklen_t = @sizeOf(posix.sockaddr.storage);
            const rc = linux.recvfrom(self.fd, &buf, buf.len, 0, @ptrCast(&src), &src_len);
            if (linux.errno(rc) != .SUCCESS) continue;
            const count: usize = @intCast(rc);
            _ = linux.sendto(self.fd, &buf, count, linux.MSG.NOSIGNAL, @ptrCast(&src), src_len);
        }
    }

    fn stop(self: *UdpEchoServer) void {
        self.stopping.store(true, .release);
        self.thread.join();
        closeFd(self.fd);
        testing.allocator.destroy(self);
    }
};

fn makeUdpTestResolved(gpa: Allocator, upstream_port: u16) !config.ResolvedConfiguration {
    const listen = try gpa.alloc(SocketAddr, 1);
    listen[0] = SocketAddr.parseIp("127.0.0.1", 0).?;
    return .{
        .configuration = .{
            .version = 1,
            .protocols = @constCast(&[_]config.ForwardProtocol{.udp}),
            .listen = .{ .host = "127.0.0.1", .port = 0 },
            .upstream = .{ .host = "127.0.0.1", .port = upstream_port },
            .timeouts = .{ .udp_session_seconds = 5 },
            .limits = .{
                .tcp_listen_backlog = 128,
                .max_tcp_buffered_bytes = 64 * 1_024 * 1_024,
                .max_udp_associations = 1_024,
                .max_udp_pending_datagrams = 64,
                .max_udp_pending_bytes = 256 * 1_024,
            },
            .performance = .{ .udp_io_threads = 1 },
        },
        .listen_addresses = listen,
        .upstream_address = SocketAddr.parseIp("127.0.0.1", upstream_port).?,
    };
}

/// UDP client socket on an ephemeral port with a 200ms receive timeout.
fn udpClient() !fd_t {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    try testing.expect(linux.errno(rc) == .SUCCESS);
    const fd: fd_t = @intCast(rc);
    errdefer closeFd(fd);
    var timeout = linux.timeval{ .sec = 0, .usec = 200_000 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&timeout), @sizeOf(linux.timeval));
    return fd;
}

fn udpSendTo(fd: fd_t, port: u16, bytes: []const u8) !void {
    var addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const rc = linux.sendto(fd, bytes.ptr, bytes.len, linux.MSG.NOSIGNAL, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    try testing.expect(linux.errno(rc) == .SUCCESS);
}

/// Null on receive timeout.
fn udpReceive(fd: fd_t, out: []u8) !?usize {
    const rc = linux.recvfrom(fd, out.ptr, out.len, 0, null, null);
    const errno = linux.errno(rc);
    if (errno != .SUCCESS) {
        try testing.expect(errno == .AGAIN);
        return null;
    }
    return @intCast(rc);
}

const MockUdpSelector = struct {
    addresses: []const SocketAddr,
    cursor: usize = 0,
    picks: std.ArrayList(SocketAddr) = .empty,
    failures: std.ArrayList(SocketAddr) = .empty,
    successes: std.ArrayList(SocketAddr) = .empty,

    fn selector(self: *MockUdpSelector) UpstreamSelector {
        return .{
            .context = self,
            .pick_fn = pick,
            .report_success_fn = reportSuccess,
            .report_failure_fn = reportFailure,
        };
    }

    fn deinit(self: *MockUdpSelector) void {
        self.picks.deinit(testing.allocator);
        self.failures.deinit(testing.allocator);
        self.successes.deinit(testing.allocator);
    }

    fn pick(context: *anyopaque, client: SocketAddr, now_ns: u64) SocketAddr {
        _ = client;
        _ = now_ns;
        const self: *MockUdpSelector = @ptrCast(@alignCast(context));
        const address = self.addresses[self.cursor % self.addresses.len];
        self.cursor += 1;
        self.picks.append(testing.allocator, address) catch {};
        return address;
    }

    fn reportSuccess(context: *anyopaque, upstream: SocketAddr) void {
        const self: *MockUdpSelector = @ptrCast(@alignCast(context));
        self.successes.append(testing.allocator, upstream) catch {};
    }

    fn reportFailure(context: *anyopaque, upstream: SocketAddr, now_ns: u64) void {
        _ = now_ns;
        const self: *MockUdpSelector = @ptrCast(@alignCast(context));
        self.failures.append(testing.allocator, upstream) catch {};
    }
};

fn waitForEcho(fd: fd_t, port: u16, message: []const u8, timeout_ms: u64) !bool {
    var waited: u64 = 0;
    while (waited < timeout_ms) {
        try udpSendTo(fd, port, message);
        var buf: [64]u8 = undefined;
        if (try udpReceive(fd, &buf)) |count| {
            try testing.expectEqualStrings(message, buf[0..count]);
            return true;
        }
        waited += 200;
    }
    return false;
}

test "udp selector chooses the upstream per association" {
    var echo_a = try UdpEchoServer.start();
    defer echo_a.stop();
    var echo_b = try UdpEchoServer.start();
    defer echo_b.stop();
    const addr_a = SocketAddr.parseIp("127.0.0.1", echo_a.port).?;
    const addr_b = SocketAddr.parseIp("127.0.0.1", echo_b.port).?;

    var mock = MockUdpSelector{ .addresses = &.{ addr_a, addr_b } };
    defer mock.deinit();

    var logger = LogStore.init("critical");
    const resolved = try makeUdpTestResolved(testing.allocator, echo_a.port);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = UdpListener.initWithSelector(testing.allocator, resolved, &logger, false, null, mock.selector());
    defer listener.deinit();
    try listener.start();

    const bound = try listener.localAddresses(testing.allocator);
    defer testing.allocator.free(bound);
    const port = bound[0].port;

    // Two clients (two associations): alternating picks, both echoes work.
    const client_a = try udpClient();
    defer closeFd(client_a);
    try testing.expect(try waitForEcho(client_a, port, "hello-a", 2_000));
    const client_b = try udpClient();
    defer closeFd(client_b);
    try testing.expect(try waitForEcho(client_b, port, "hello-b", 2_000));

    try testing.expectEqual(@as(usize, 2), mock.picks.items.len);
    try testing.expect(mock.picks.items[0].eql(addr_a));
    try testing.expect(mock.picks.items[1].eql(addr_b));
    try testing.expect(mock.successes.items.len >= 1);
    try testing.expectEqual(@as(usize, 0), mock.failures.items.len);
}

test "udp selector reports failures and reroutes after eviction" {
    const pool_module = @import("upstream_pool.zig");

    var echo = try UdpEchoServer.start();
    defer echo.stop();
    const live = SocketAddr.parseIp("127.0.0.1", echo.port).?;
    const dead = SocketAddr.parseIp("127.0.0.1", 1).?; // ICMP port unreachable

    var pool = try pool_module.UpstreamPool.init(testing.allocator, &.{ dead, live }, &.{ 1, 1 }, .round_robin);
    defer pool.deinit();

    const PoolGlue = struct {
        fn pick(context: *anyopaque, client: SocketAddr, now_ns: u64) SocketAddr {
            const p: *pool_module.UpstreamPool = @ptrCast(@alignCast(context));
            return p.pick(client, now_ns);
        }
        fn reportSuccess(context: *anyopaque, upstream: SocketAddr) void {
            const p: *pool_module.UpstreamPool = @ptrCast(@alignCast(context));
            p.reportSuccess(upstream);
        }
        fn reportFailure(context: *anyopaque, upstream: SocketAddr, now_ns: u64) void {
            const p: *pool_module.UpstreamPool = @ptrCast(@alignCast(context));
            p.reportFailure(upstream, now_ns);
        }
    };
    const selector = UpstreamSelector{
        .context = &pool,
        .pick_fn = PoolGlue.pick,
        .report_success_fn = PoolGlue.reportSuccess,
        .report_failure_fn = PoolGlue.reportFailure,
    };

    var logger = LogStore.init("critical");
    const resolved = try makeUdpTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = UdpListener.initWithSelector(testing.allocator, resolved, &logger, false, null, selector);
    defer listener.deinit();
    try listener.start();

    const bound = try listener.localAddresses(testing.allocator);
    defer testing.allocator.free(bound);
    const port = bound[0].port;

    // Each round uses a fresh client (fresh association). Round-robin picks
    // alternate dead/live; datagrams to the dead upstream trigger ICMP errors
    // that fail the association, and after the failure threshold the dead
    // upstream is parked for good.
    var clients: std.ArrayList(fd_t) = .empty;
    defer {
        for (clients.items) |fd| closeFd(fd);
        clients.deinit(testing.allocator);
    }
    var got_echo = false;
    var round: usize = 0;
    while (round < 12) : (round += 1) {
        const client = try udpClient();
        try clients.append(testing.allocator, client);
        try udpSendTo(client, port, "probe");
        var buf: [64]u8 = undefined;
        if (try udpReceive(client, &buf)) |_| got_echo = true;
        sleepMs(50); // let the engine consume ICMP errors
    }
    try testing.expect(got_echo);

    try testing.expect(pool.pick(live, monotonicMilliseconds() * std.time.ns_per_ms).eql(live));
}
