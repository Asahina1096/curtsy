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
            const current = self.used.load(.acquire);
            if (current >= limit) return false;
            if (self.used.cmpxchgWeak(current, current + 1, .acq_rel, .acquire) == null) return true;
        }
    }

    pub fn release(self: *UdpAssociationBudget, n: u64) void {
        if (n == 0) return;
        const previous = self.used.fetchSub(n, .acq_rel);
        std.debug.assert(previous >= n); // UDP association budget released more than acquired
    }

    pub fn count(self: *const UdpAssociationBudget) u64 {
        return self.used.load(.acquire);
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
        return .{
            .allocator = allocator,
            .runtime = RuntimeConfiguration.init(configuration),
            .log = log_store,
            .enable_sockmap_override = enable_sockmap_acceleration,
            .loader = load_sockmap_runtime,
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
        /// Connected per-client socket and its kernel pairing; present only
        /// when this association is steered by the sockmap verdict program.
        client_fd: ?fd_t = null,
        pairing: ?bpf.SockmapRuntime.Pairing = null,
        last_activity_ms: u64,
    };

    const batch_size = bpf.udp_batch_capacity;
    const datagram_capacity = 65_536;
    const sweep_interval_ms: i32 = 50;

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

    command_mutex: Mutex = .{},
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
    associations: std.AutoHashMap(SocketAddr, Association),
    upstream_to_client: std.AutoHashMap(fd_t, SocketAddr),
    client_fd_to_client: std.AutoHashMap(fd_t, SocketAddr),
    listen_bound: std.AutoHashMap(fd_t, posix.sockaddr.storage),
    sockmap_runtime: ?bpf.SockmapRuntime = null,
    warned_at_limit: bool = false,
    sweep_buffer: std.ArrayList(SocketAddr) = .empty,

    pub fn init(
        runtime: *RuntimeConfiguration,
        log_store: *LogStore,
        budget: *UdpAssociationBudget,
        allocator: Allocator,
        engine_count: u32,
        enable_sockmap_acceleration: ?bool,
        loader: ?SockmapRuntimeLoader,
        announce_listen: bool,
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
            .associations = std.AutoHashMap(SocketAddr, Association).init(allocator),
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
        self.command_mutex.unlock();
        self.signal_mutex.lock();
        if (self.wake_fd >= 0) bpf.eventfdSignal(self.wake_fd);
        self.signal_mutex.unlock();
    }

    fn run(self: *UdpRelayEngine) void {
        setThreadName();
        defer self.teardown();

        const buffer = self.allocator.alloc(u8, batch_size * datagram_capacity) catch {
            self.log.critical("udp relay buffer allocation failed", .{});
            return;
        };
        defer self.allocator.free(buffer);

        var recv_slots: [batch_size]bpf.UdpSlot = undefined;
        for (&recv_slots, 0..) |*slot, index| {
            slot.* = .{
                .data = buffer[index * datagram_capacity ..].ptr,
                .capacity = datagram_capacity,
            };
        }
        var send_slots: [batch_size]bpf.UdpSlot = undefined;
        var ready_fds: [batch_size + 1]fd_t = undefined;

        while (!self.stop_requested.load(.acquire)) {
            const ready = bpf.epollWait(self.epoll_fd, &ready_fds, sweep_interval_ms) catch {
                self.log.err("udp event wait failed error={s}", .{errnoDescription()});
                continue;
            };

            self.processCommands();

            for (ready_fds[0..ready]) |fd| {
                if (fd == self.wake_fd) {
                    bpf.eventfdDrain(self.wake_fd);
                } else if (self.client_fd_to_client.contains(fd)) {
                    self.drainClient(fd, &recv_slots);
                } else if (self.upstream_to_client.contains(fd)) {
                    self.drainUpstream(fd, &recv_slots);
                } else {
                    self.drainListen(fd, &recv_slots, &send_slots);
                }
            }
            self.sweepExpiredAssociations();
        }
    }

    fn processCommands(self: *UdpRelayEngine) void {
        self.command_mutex.lock();
        std.mem.swap(std.ArrayList(Command), &self.pending_commands, &self.drained_commands);
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
    ) void {
        while (true) {
            const received = bpf.udpRecvBatch(fd, recv_slots) catch {
                self.log.err("udp listener read failed error={s}", .{errnoDescription()});
                return;
            };
            if (received == 0) return;
            self.forwardClientDatagrams(received, fd, recv_slots, send_slots);
        }
    }

    fn forwardClientDatagrams(
        self: *UdpRelayEngine,
        count: usize,
        listen_fd: fd_t,
        recv_slots: *[batch_size]bpf.UdpSlot,
        send_slots: *[batch_size]bpf.UdpSlot,
    ) void {
        var run_fd: fd_t = -1;
        var run_length: usize = 0;
        for (recv_slots[0..count]) |*slot| {
            const client = socketAddrFromStorage(&slot.address) orelse continue;
            const association: Association = blk: {
                if (self.associations.getPtr(client)) |existing| {
                    existing.last_activity_ms = monotonicMilliseconds();
                    break :blk existing.*;
                }
                break :blk self.openAssociation(
                    client,
                    slot.address,
                    slot.address_length,
                    listen_fd,
                ) orelse continue;
            };
            if (association.upstream_fd != run_fd) {
                if (run_length > 0) {
                    _ = self.sendAllDatagrams(run_fd, null, 0, send_slots[0..run_length], "direction=client_to_upstream");
                }
                run_fd = association.upstream_fd;
                run_length = 0;
            }
            send_slots[run_length].data = slot.data;
            send_slots[run_length].length = slot.length;
            run_length += 1;
        }
        if (run_length > 0) {
            _ = self.sendAllDatagrams(run_fd, null, 0, send_slots[0..run_length], "direction=client_to_upstream");
        }
    }

    // Fallback path for an accelerated association: datagrams queued on the
    // connected client socket before pairing completed (or passed through via
    // SK_PASS) are relayed by userspace like ordinary listen-socket traffic.
    fn drainClient(self: *UdpRelayEngine, fd: fd_t, recv_slots: *[batch_size]bpf.UdpSlot) void {
        const client = self.client_fd_to_client.get(fd) orelse return;
        const association = self.associations.getPtr(client) orelse return;
        while (true) {
            const received = bpf.udpRecvBatch(fd, recv_slots) catch {
                self.log.err("udp client socket read failed client={f} error={s}", .{ client, errnoDescription() });
                self.closeAssociation(client);
                return;
            };
            if (received == 0) return;
            association.last_activity_ms = monotonicMilliseconds();
            _ = self.sendAllDatagrams(
                association.upstream_fd,
                null,
                0,
                recv_slots[0..received],
                "direction=client_to_upstream",
            );
        }
    }

    fn drainUpstream(self: *UdpRelayEngine, fd: fd_t, recv_slots: *[batch_size]bpf.UdpSlot) void {
        const client = self.upstream_to_client.get(fd) orelse return;
        const association = self.associations.getPtr(client) orelse return;
        while (true) {
            const received = bpf.udpRecvBatch(fd, recv_slots) catch {
                self.log.err("udp upstream error client={f} error={s}", .{ client, errnoDescription() });
                self.closeAssociation(client);
                return;
            };
            if (received == 0) return;
            association.last_activity_ms = monotonicMilliseconds();
            const address: *const posix.sockaddr = @ptrCast(&association.client_address);
            _ = self.sendAllDatagrams(
                association.listen_fd,
                address,
                association.client_address_length,
                recv_slots[0..received],
                "direction=upstream_to_client",
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
    ) bool {
        if (slots.len == 0) return true;
        var sent_total: usize = 0;
        while (sent_total < slots.len) {
            const sent = bpf.udpSendBatch(fd, address, address_length, slots[sent_total..]) catch {
                self.log.warning("udp datagrams dropped {s} sent={d} dropped={d} error={s}", .{
                    context,
                    sent_total,
                    slots.len - sent_total,
                    errnoDescription(),
                });
                return false;
            };
            if (sent == 0) {
                self.log.warning("udp datagrams dropped {s} sent={d} dropped={d} error=sendmmsg made no progress", .{
                    context,
                    sent_total,
                    slots.len - sent_total,
                });
                return false;
            }
            sent_total += sent;
        }
        return true;
    }

    fn openAssociation(
        self: *UdpRelayEngine,
        client: SocketAddr,
        client_address: posix.sockaddr.storage,
        client_address_length: socklen_t,
        listen_fd: fd_t,
    ) ?Association {
        const snapshot = self.runtime.current();
        const limit: u64 = @intCast(snapshot.configuration.limits.max_udp_associations);
        if (!self.budget.tryAcquire(limit)) {
            if (!self.warned_at_limit) {
                self.warned_at_limit = true;
                self.log.warning("udp association limit reached limit={d}", .{limit});
            }
            return null;
        }
        return self.establishAssociation(client, client_address, client_address_length, listen_fd, &snapshot) catch |err| {
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
    ) Error!Association {
        var upstream_storage: posix.sockaddr.storage = undefined;
        const upstream_len = snapshot.upstream_address.toSockaddrStorage(@ptrCast(&upstream_storage));
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
        if (self.sockmap_runtime != null) {
            if (self.listen_bound.get(listen_fd)) |bind_storage| {
                if (self.accelerateAssociation(bind_storage, client_address, client_address_length, upstream_fd)) |accelerated| {
                    client_fd = accelerated.fd;
                    pairing = accelerated.pairing;
                } else |err| {
                    // Kernel steering is best-effort per association; fall
                    // back to the userspace relay for this client.
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
            .client_fd = client_fd,
            .pairing = pairing,
            .last_activity_ms = monotonicMilliseconds(),
        };
        try self.associations.put(client, association);
        errdefer _ = self.associations.remove(client);
        try self.upstream_to_client.put(upstream_fd, client);
        errdefer _ = self.upstream_to_client.remove(upstream_fd);
        if (client_fd) |fd| {
            try self.client_fd_to_client.put(fd, client);
        }
        self.warned_at_limit = false;
        self.log.debug("udp association opened client={f} upstream={f}", .{ client, snapshot.upstream_address });
        return association;
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

    fn sweepExpiredAssociations(self: *UdpRelayEngine) void {
        const timeout_seconds = self.runtime.current().configuration.timeouts.udp_session_seconds;
        const timeout_ms = @as(u64, @intCast(@max(1, timeout_seconds))) * 1_000;
        const timeout_ns = timeout_ms * 1_000_000;
        const now = monotonicMilliseconds();

        self.sweep_buffer.clearRetainingCapacity();
        defer self.sweep_buffer.clearRetainingCapacity();
        var iterator = self.associations.iterator();
        while (iterator.next()) |entry| {
            const association = entry.value_ptr;
            const expired = blk: {
                if (association.pairing) |p| {
                    // Steered traffic never reaches userspace; the BPF peer
                    // state holds the last-activity timestamp instead.
                    if (self.sockmap_runtime) |*runtime| {
                        const remaining = runtime.idleRemainingNs(p.client_cookie, p.upstream_cookie, timeout_ns) catch break :blk true;
                        break :blk remaining == 0;
                    }
                    break :blk true;
                }
                break :blk now -% association.last_activity_ms >= timeout_ms;
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
