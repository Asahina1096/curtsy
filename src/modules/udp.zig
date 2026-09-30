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
//! between engines. auto starts on the stable userspace batched relay and is
//! driven by a per-engine adaptive controller (`UdpSockmapPolicy`): the rule
//! must not use a loopback upstream and the relay must observe a sustained,
//! large-datagram workload over several consecutive windows before sockmap is
//! attempted, and every failure path lands in a cooldown before re-probing.
//! Loopback and small-packet workloads therefore stay on userspace; sockmap is
//! best-effort with no packet-ordering guarantees. enabled forces a
//! best-effort attempt; disabled always stays on userspace. Expiry for
//! steered sessions reads the BPF activity time via `idleRemainingNs`.
//! Expired or unpaired sessions fall back to the listener and re-establish;
//! pairing failures and SK_PASS datagrams are relayed by userspace. Changing
//! the mode via `updateConfiguration` clears existing sessions and rebuilds
//! under the new mode; an enabled-to-auto reload synchronously blocks new
//! associations from entering sockmap before the async teardown command runs.

const std = @import("std");
const config = @import("core.zig");
const performance = @import("performance.zig");
const upstream = @import("upstream.zig");
const log = @import("../log.zig");
const bpf = @import("../bpf.zig");

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
// Data-path counters
// ---------------------------------------------------------------------------

/// Listener-wide UDP data-path accounting. One counter set lives per engine
/// (`UdpEngineCounters`) so hot-path increments never contend on a shared
/// cache line; `UdpListener.countersSnapshot` aggregates them. Counters are
/// pure accounting and never influence a forwarding decision.
pub const UdpDataPathCounters = struct {
    /// recvmmsg syscalls on this engine, including EAGAIN and failed ones.
    recv_calls: u64 = 0,
    /// Datagrams received by the userspace relays on this engine.
    recv_datagrams: u64 = 0,
    /// Payload bytes received by the userspace relays on this engine.
    recv_bytes: u64 = 0,
    /// sendmmsg syscalls on this engine, including failed ones.
    send_calls: u64 = 0,
    /// Datagrams handed to the kernel by the userspace relays on this engine.
    send_datagrams: u64 = 0,
    /// Payload bytes handed to the kernel by the userspace relays on this engine.
    send_bytes: u64 = 0,
    /// Datagrams dropped because a sendmmsg batch could not make progress.
    send_error_drops: u64 = 0,
    /// Sockmap pairing attempts (once per association that tried to steer).
    sockmap_pair_attempts: u64 = 0,
    /// Sockmap pairings that succeeded (association steered by the kernel).
    sockmap_pair_successes: u64 = 0,
    /// Sockmap pairing attempts that failed and fell back to the userspace relay.
    sockmap_pair_failures: u64 = 0,
    /// Datagrams relayed by userspace on accelerated client sockets (queued
    /// before pairing completed or passed through by the verdict via SK_PASS).
    sockmap_pass_datagrams: u64 = 0,
    /// Payload bytes of those userspace-relayed accelerated-client datagrams.
    sockmap_pass_bytes: u64 = 0,

    /// Average receive batch fill: datagrams per recvmmsg syscall. 0 when idle.
    pub fn recvAvgBatchFill(self: UdpDataPathCounters) u64 {
        return if (self.recv_calls > 0) self.recv_datagrams / self.recv_calls else 0;
    }

    /// Average send batch fill: datagrams per sendmmsg syscall. 0 when idle.
    pub fn sendAvgBatchFill(self: UdpDataPathCounters) u64 {
        return if (self.send_calls > 0) self.send_datagrams / self.send_calls else 0;
    }
};

/// Per-engine atomic counter set. Increments use .monotonic atomics on the
/// owning I/O thread (one RMW per batched syscall, never per datagram), so a
/// snapshot may be read from any thread without locks and without shared
/// cache-line contention on the hot path.
const UdpEngineCounters = struct {
    recv_calls: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    recv_datagrams: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    recv_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    send_calls: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    send_datagrams: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    send_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    send_error_drops: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    sockmap_pair_attempts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    sockmap_pair_successes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    sockmap_pair_failures: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    sockmap_pass_datagrams: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    sockmap_pass_bytes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn snapshot(self: *const UdpEngineCounters) UdpDataPathCounters {
        return .{
            .recv_calls = self.recv_calls.load(.monotonic),
            .recv_datagrams = self.recv_datagrams.load(.monotonic),
            .recv_bytes = self.recv_bytes.load(.monotonic),
            .send_calls = self.send_calls.load(.monotonic),
            .send_datagrams = self.send_datagrams.load(.monotonic),
            .send_bytes = self.send_bytes.load(.monotonic),
            .send_error_drops = self.send_error_drops.load(.monotonic),
            .sockmap_pair_attempts = self.sockmap_pair_attempts.load(.monotonic),
            .sockmap_pair_successes = self.sockmap_pair_successes.load(.monotonic),
            .sockmap_pair_failures = self.sockmap_pair_failures.load(.monotonic),
            .sockmap_pass_datagrams = self.sockmap_pass_datagrams.load(.monotonic),
            .sockmap_pass_bytes = self.sockmap_pass_bytes.load(.monotonic),
        };
    }

    fn reset(self: *UdpEngineCounters) void {
        self.* = .{};
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
// Sockmap runtime interface (injectable, mirrors TCP's accelerator loader)
// ---------------------------------------------------------------------------

/// Type-erased UDP sockmap runtime. The engine only depends on this tiny
/// vtable, so tests inject a counting/failing fake without loading any BPF
/// object; the default backs it with a heap-allocated `bpf.SockmapRuntime`.
pub const UdpSockmapRuntime = struct {
    pub const Pairing = bpf.SockmapRuntime.Pairing;

    pub const VTable = struct {
        pair: *const fn (ctx: *anyopaque, client_fd: fd_t, upstream_fd: fd_t) bpf.Error!Pairing,
        unpair: *const fn (ctx: *anyopaque, client_cookie: u64, upstream_cookie: u64) void,
        idle_remaining_ns: *const fn (ctx: *anyopaque, client_cookie: u64, upstream_cookie: u64, idle_timeout_ns: u64) bpf.Error!u64,
        destroy: *const fn (ctx: *anyopaque) void,
    };

    context: *anyopaque,
    vtable: *const VTable,

    pub fn pair(self: *const UdpSockmapRuntime, client_fd: fd_t, upstream_fd: fd_t) bpf.Error!Pairing {
        return self.vtable.pair(self.context, client_fd, upstream_fd);
    }

    pub fn unpair(self: *const UdpSockmapRuntime, client_cookie: u64, upstream_cookie: u64) void {
        self.vtable.unpair(self.context, client_cookie, upstream_cookie);
    }

    pub fn idleRemainingNs(
        self: *const UdpSockmapRuntime,
        client_cookie: u64,
        upstream_cookie: u64,
        idle_timeout_ns: u64,
    ) bpf.Error!u64 {
        return self.vtable.idle_remaining_ns(self.context, client_cookie, upstream_cookie, idle_timeout_ns);
    }

    pub fn destroy(self: *UdpSockmapRuntime) void {
        self.vtable.destroy(self.context);
    }
};

/// Factory for the per-engine UDP sockmap runtime; the allocator backs the
/// default boxed `bpf.SockmapRuntime`, and the optional context lets tests
/// point fakes at their own state.
pub const SockmapRuntimeLoader = *const fn (context: ?*anyopaque, allocator: Allocator, max_entries: u32, verifier_log: ?[]u8) bpf.Error!UdpSockmapRuntime;

pub const default_sockmap_runtime_loader: SockmapRuntimeLoader = boxedSockmapRuntime;

/// Heap box pairing the real runtime with the allocator that must free it.
const RuntimeBox = struct {
    allocator: Allocator,
    runtime: bpf.SockmapRuntime,
};

fn boxedSockmapRuntime(context: ?*anyopaque, allocator: Allocator, max_entries: u32, verifier_log: ?[]u8) bpf.Error!UdpSockmapRuntime {
    _ = context;
    const box = allocator.create(RuntimeBox) catch return error.NoMemory;
    box.runtime = bpf.SockmapRuntime.createUdp(max_entries, verifier_log) catch |err| {
        allocator.destroy(box);
        return err;
    };
    box.allocator = allocator;
    return .{ .context = box, .vtable = &real_runtime_vtable };
}

const real_runtime_vtable = UdpSockmapRuntime.VTable{
    .pair = realPair,
    .unpair = realUnpair,
    .idle_remaining_ns = realIdleRemainingNs,
    .destroy = realDestroy,
};

fn realPair(ctx: *anyopaque, client_fd: fd_t, upstream_fd: fd_t) bpf.Error!UdpSockmapRuntime.Pairing {
    const box: *RuntimeBox = @ptrCast(@alignCast(ctx));
    return box.runtime.pair(client_fd, upstream_fd);
}

fn realUnpair(ctx: *anyopaque, client_cookie: u64, upstream_cookie: u64) void {
    const box: *RuntimeBox = @ptrCast(@alignCast(ctx));
    box.runtime.unpair(client_cookie, upstream_cookie);
}

fn realIdleRemainingNs(ctx: *anyopaque, client_cookie: u64, upstream_cookie: u64, idle_timeout_ns: u64) bpf.Error!u64 {
    const box: *RuntimeBox = @ptrCast(@alignCast(ctx));
    return box.runtime.idleRemainingNs(client_cookie, upstream_cookie, idle_timeout_ns);
}

fn realDestroy(ctx: *anyopaque) void {
    const box: *RuntimeBox = @ptrCast(@alignCast(ctx));
    box.runtime.destroy();
    box.allocator.destroy(box);
}

// ---------------------------------------------------------------------------
// UdpSockmapPolicy: conservative adaptive controller for auto mode
// ---------------------------------------------------------------------------

/// Conservative adaptive controller deciding when the per-engine UDP sockmap
/// runtime may steer associations under `auto`.
///
/// It starts on the userspace relay and only arms sockmap after stable
/// runtime evidence shows a workload where the verdict path is likely to
/// help: the rule must not use a loopback upstream, and the relay must
/// forward a sustained stream of large-enough datagrams over several
/// consecutive 1-second windows (this excludes loopback and small-packet
/// workloads, where the verdict path regresses throughput and reordering).
/// Every failure path — an unusable verifier/loader, sustained pairing
/// failures, or sustained userspace forwarding while supposedly steered —
/// sends the controller into a cooldown before it may re-probe, so it never
/// thrashes and always keeps a safe userspace fallback. Sockmap remains
/// best-effort: no packet-ordering guarantees are claimed.
///
/// The controller is pure state; the engine feeds one pre-aggregated window
/// per tick (`observeWindow`) and follows the returned `Action`. `enabled`
/// forces the attempt unconditionally; `disabled` never attempts.
pub const UdpSockmapPolicy = struct {
    pub const Mode = config.SockmapAccelerationMode;

    pub const State = enum(u8) {
        /// sockmap off; collecting userspace evidence (auto only).
        probing,
        /// runtime loaded and steering new associations.
        active,
        /// after a failure/regression; no steering until the cooldown elapses.
        cooling_down,
    };

    /// One pre-aggregated window of userspace activity.
    pub const WindowSample = struct {
        /// Datagrams forwarded by userspace in the window.
        datagrams: u64,
        /// Payload bytes forwarded by userspace in the window.
        bytes: u64,
        /// Rule eligibility (false when any upstream is loopback).
        eligible: bool,
    };

    pub const Action = enum {
        stay_off,
        load,
        keep_active,
        regress,
    };

    // ------------------------------------------------------------------
    // Internal policy constants. Conservative by design; the policy is
    // never enabled by traffic alone without these windows elapsing.
    // ------------------------------------------------------------------

    /// Evidence window length; the engine feeds one sample per window.
    pub const window_ms: u64 = 1_000;
    /// Consecutive qualifying windows required before auto arms.
    pub const probe_stable_windows: u32 = 5;
    /// Minimum sustained userspace datagrams per window to qualify.
    pub const min_datagrams_per_window: u64 = 200;
    /// Minimum average datagram size (bytes) — excludes small-packet loads.
    pub const min_avg_datagram_bytes: u64 = 256;
    /// Pairing failures (e.g. a full sockhash) tolerated while active before
    /// the controller regresses to userspace.
    pub const pairing_failure_threshold: u32 = 5;
    /// Userspace datagrams per window while active that indicate steering is
    /// not actually happening; sustained storms regress the controller.
    pub const active_storm_datagrams: u64 = 500;
    /// Consecutive storm windows required before regression (hysteresis).
    pub const active_storm_windows: u32 = 2;
    /// Cooldown after a load failure or regression before re-probing.
    pub const fallback_cooldown_ms: u64 = 30_000;

    mode: Mode = .auto,
    state: State = .probing,
    stable_windows: u32 = 0,
    storm_windows: u32 = 0,
    pairing_failures: u32 = 0,
    cooldown_until_ms: u64 = 0,

    /// Rebuilds the controller for `mode`; used on startup and whenever the
    /// configured mode changes across a reload. A reload that keeps the same
    /// mode leaves the controller (and any loaded runtime) in place, so e.g.
    /// a limits-only reload does not reset an auto decision.
    pub fn reset(self: *UdpSockmapPolicy, mode: Mode) void {
        self.* = .{};
        self.mode = mode;
    }

    /// auto: the controller currently allows new associations to be steered.
    pub fn steerAllowed(self: *const UdpSockmapPolicy) bool {
        return switch (self.mode) {
            .disabled => false,
            .enabled => true,
            .auto => self.state == .active,
        };
    }

    /// Feeds one window of userspace evidence at `now_ms`. The window is
    /// already pre-aggregated by the engine (which ticks on its own cadence);
    /// the sample's `datagrams`/`bytes` describe the whole window.
    pub fn observeWindow(self: *UdpSockmapPolicy, now_ms: u64, sample: WindowSample) Action {
        return switch (self.mode) {
            .enabled => .keep_active,
            .disabled => .stay_off,
            .auto => self.observeAuto(now_ms, sample),
        };
    }

    /// The engine loaded the runtime after `.load`; the controller becomes
    /// active and clears its failure history. Only the auto load path (a
    /// `.load` action from `observeAuto`) can reach this, so no mode check
    /// is needed.
    pub fn noteLoaded(self: *UdpSockmapPolicy) void {
        self.state = .active;
        self.pairing_failures = 0;
        self.stable_windows = 0;
    }

    /// The engine failed to load the runtime; enter the cooldown. Only the
    /// auto load path can reach this.
    pub fn noteLoadFailure(self: *UdpSockmapPolicy, now_ms: u64) void {
        self.state = .cooling_down;
        self.cooldown_until_ms = now_ms + fallback_cooldown_ms;
        self.pairing_failures = 0;
    }

    /// A pairing succeeded; steering works, so clear the failure streak.
    /// Steering under auto implies the controller is active (`steerAllowed`),
    /// so only the enabled-mode no-op guard is needed.
    pub fn notePairingSuccess(self: *UdpSockmapPolicy) void {
        if (self.mode != .auto) return;
        self.pairing_failures = 0;
    }

    /// A pairing failed (typically a full sockhash). Sustained failures
    /// regress the controller to a cooldown so a persistently broken map
    /// falls back to the userspace relay instead of paying the pair cost for
    /// every new association.
    pub fn notePairingFailure(self: *UdpSockmapPolicy, now_ms: u64) void {
        if (self.mode != .auto) return;
        self.pairing_failures += 1;
        if (self.pairing_failures >= pairing_failure_threshold) {
            self.state = .cooling_down;
            self.cooldown_until_ms = now_ms + fallback_cooldown_ms;
            self.pairing_failures = 0;
        }
    }

    fn observeAuto(self: *UdpSockmapPolicy, now_ms: u64, sample: WindowSample) Action {
        switch (self.state) {
            // The engine loads the runtime synchronously when `.load` is
            // returned, transitioning straight to active or cooling_down, so
            // no separate armed state with re-verification is needed.
            .probing => {
                if (sample.eligible and qualifies(sample)) {
                    self.stable_windows += 1;
                    if (self.stable_windows >= probe_stable_windows) return .load;
                } else {
                    self.stable_windows = 0;
                }
                return .stay_off;
            },
            .active => {
                if (!sample.eligible) {
                    self.regress(now_ms);
                    return .regress;
                }
                if (sample.datagrams >= active_storm_datagrams) {
                    self.storm_windows += 1;
                    if (self.storm_windows >= active_storm_windows) {
                        self.regress(now_ms);
                        return .regress;
                    }
                } else {
                    self.storm_windows = 0;
                }
                return .keep_active;
            },
            .cooling_down => {
                if (now_ms >= self.cooldown_until_ms) {
                    self.state = .probing;
                    self.stable_windows = 0;
                    self.storm_windows = 0;
                    self.pairing_failures = 0;
                }
                return .stay_off;
            },
        }
    }

    fn regress(self: *UdpSockmapPolicy, now_ms: u64) void {
        self.state = .cooling_down;
        self.cooldown_until_ms = now_ms + fallback_cooldown_ms;
        self.storm_windows = 0;
        self.pairing_failures = 0;
    }

    fn qualifies(sample: WindowSample) bool {
        return sample.datagrams >= min_datagrams_per_window and
            (sample.bytes / @max(1, sample.datagrams)) >= min_avg_datagram_bytes;
    }
};

/// Optional upstream-selection hook (upstream module). When set, each new
/// association asks the selector for its upstream address, and upstream
/// socket errors/successes are reported back for passive health tracking.
pub const UpstreamSelector = upstream.Selector;

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
        /// Pending generation word returned by beginSteeringUpdate while the
        /// listener publishes this slot's new runtime snapshot.
        gate_update: u64 = 0,
    };

    allocator: Allocator,
    runtime: RuntimeConfiguration,
    log: *LogStore,
    enable_sockmap_override: ?bool,
    loader: ?SockmapRuntimeLoader,
    loader_context: ?*anyopaque = null,
    upstream_selector: ?UpstreamSelector = null,
    /// Reload-prepared listeners bind sockets but do not process datagrams
    /// until the core commit calls activate().
    start_paused: bool = false,
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

    /// init plus the rules module upstream-selection hook.
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
        const thread_count: u32 = @intCast(snapshot.configuration.performance.udp_io_threads);
        errdefer self.stop();

        // The first engine binds the configured addresses; the rest bind the
        // addresses it actually got (relevant when the configured port is 0),
        // sharing each port through SO_REUSEPORT.
        try self.startEngine(&self.runtime, &.{}, thread_count, true, 0);
        const bound = try self.engines.items[0].engine.localAddressesCopy(self.allocator);
        defer self.allocator.free(bound);
        for (1..thread_count) |index| {
            try self.startEngine(null, bound, thread_count, false, @intCast(index));
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
        index: u32,
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
                .upstream_has_loopback = snapshot.upstream_has_loopback,
            });
            runtime_ptr = &slot.runtime;
        }
        slot.engine = UdpRelayEngine.init(
            runtime_ptr.?,
            self.log,
            &self.budget,
            self.allocator,
            engine_count,
            index,
            self.enable_sockmap_override,
            self.loader,
            self.loader_context,
            announce_listen,
            self.upstream_selector,
        );
        slot.engine.activated.store(!self.start_paused, .release);
        errdefer slot.engine.destroy();
        try slot.engine.start();
        try self.engines.append(self.allocator, slot);
    }

    pub fn updateConfiguration(self: *UdpListener, configuration: ResolvedConfiguration, reset_associations: bool) void {
        // A reload that moves the mode away from enabled must stop new
        // associations from entering sockmap synchronously: the engines only
        // process the teardown command on their next I/O wake, so without
        // this guard a datagram arriving in that window could still be
        // steered under a configuration that now disallows it.
        const old_mode = sockmapMode(self.enable_sockmap_override, &self.runtime.current());
        const new_mode = sockmapMode(self.enable_sockmap_override, &configuration);
        const blocks_steering = new_mode == .disabled or
            (new_mode == .auto and (old_mode == .enabled or configuration.upstreamLoopback()));

        // Begin a generation-tagged publication before changing any runtime
        // snapshot. A stale engine reload may observe this pending generation,
        // but it cannot clear its block or claim the update has been applied.
        for (self.engines.items) |slot| {
            slot.gate_update = slot.engine.beginSteeringUpdate(blocks_steering);
        }

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
                    .upstream_has_loopback = configuration.upstream_has_loopback,
                });
            }
            slot.engine.finishSteeringUpdate(slot.gate_update);
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
    /// Aggregate data-path counters across all engines. Each engine's atomic
    /// counters are loaded and summed, so the snapshot is safe to read from
    /// any thread; before start() (no engines) it is all zeros.
    pub fn countersSnapshot(self: *const UdpListener) UdpDataPathCounters {
        var total = bpf.counters.zero(UdpDataPathCounters);
        for (self.engines.items) |slot| {
            total = bpf.counters.add(UdpDataPathCounters, total, slot.engine.counters.snapshot());
        }
        return total;
    }

    pub fn activate(self: *UdpListener) void {
        self.start_paused = false;
        for (self.engines.items) |slot| {
            if (slot.engine.activated.swap(true, .acq_rel)) continue;
            slot.engine.signal_mutex.lock();
            if (slot.engine.wake_fd >= 0) bpf.eventfdSignal(slot.engine.wake_fd);
            slot.engine.signal_mutex.unlock();
        }
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
// Protocol module registration (core orchestrator entry point)
// ---------------------------------------------------------------------------

pub const protocol_module = config.ProtocolModule{
    .name = "udp",
    .protocol = .udp,
    .drains_connections = false,
    .create = createProtocolListener,
};

fn createProtocolListener(
    context: ?*anyopaque,
    outer_allocator: Allocator,
    resolved: ResolvedConfiguration,
    logger: *LogStore,
    selector: ?upstream.Selector,
    start_paused: bool,
) anyerror!*config.Listener {
    _ = context;
    const listener = try outer_allocator.create(UdpListener);
    errdefer outer_allocator.destroy(listener);
    listener.* = UdpListener.initWithSelector(outer_allocator, resolved, logger, null, null, selector);
    listener.start_paused = start_paused;
    errdefer listener.deinit();
    try listener.start();

    const wrapper = try outer_allocator.create(config.Listener);
    wrapper.* = .{
        .allocator = outer_allocator,
        .context = listener,
        .activate_fn = listenerActivate,
        .stop_accepting_fn = listenerStopImmediate,
        .destroy_fn = listenerDestroy,
        .update_configuration_fn = listenerUpdateConfiguration,
        .update_backlog_fn = null,
        .force_close_fn = listenerNoopForceClose,
        .active_count_fn = listenerZeroActive,
    };
    return wrapper;
}

fn listenerActivate(context: *anyopaque) void {
    const listener: *UdpListener = @ptrCast(@alignCast(context));
    listener.activate();
}

/// UDP associations expire on their own timers; retiring a UDP listener
/// destroys it immediately (the core orchestrator relies on this).
fn listenerStopImmediate(context: *anyopaque) void {
    _ = context;
}

fn listenerDestroy(listener_allocator: Allocator, context: *anyopaque) void {
    const listener: *UdpListener = @ptrCast(@alignCast(context));
    listener.deinit();
    listener_allocator.destroy(listener);
}

fn listenerUpdateConfiguration(context: *anyopaque, resolved: ResolvedConfiguration, reset_sessions: bool) void {
    const listener: *UdpListener = @ptrCast(@alignCast(context));
    listener.updateConfiguration(resolved, reset_sessions);
}

fn listenerNoopForceClose(context: *anyopaque) void {
    _ = context;
}

fn listenerZeroActive(context: *anyopaque) usize {
    _ = context;
    return 0;
}

// ---------------------------------------------------------------------------
// UdpRelayEngine
// ---------------------------------------------------------------------------

pub const UdpRelayEngine = struct {
    pub const Error = bpf.Error || Allocator.Error || std.Thread.SpawnError;

    const Command = enum {
        reset_associations,
        reload_accelerator,

        fn bit(self: Command) u8 {
            return @as(u8, 1) << @intFromEnum(self);
        }
    };

    const steering_blocked_bit: u64 = 1;
    const steering_publishing_bit: u64 = 2;
    const steering_generation_step: u64 = 4;

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
    pub const max_batches_per_drain: usize = 16;
    /// After a sockmap pairing failure (typically a full map), skip further
    /// acceleration attempts for this long instead of paying the failed
    /// socket+pair cost for every new association.
    const accelerate_failure_cooldown_ms: u64 = 60_000;
    const send_error_log_interval_ms: u64 = 1_000;
    /// Batch statistics are accumulated per engine and emitted at debug level
    /// on a fixed cadence; the counters are plain fields confined to the
    /// engine's I/O thread, so logging costs no per-datagram synchronization.
    const stats_log_interval_ms: u64 = 10_000;

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
    /// Index of this engine among the listener's engine threads; selects the
    /// affinity CPU when `performance.threadCpuAffinity` is set.
    engine_index: u32,
    announce_listen: bool,
    enable_sockmap_override: ?bool,
    loader: SockmapRuntimeLoader,
    loader_context: ?*anyopaque,
    upstream_selector: ?UpstreamSelector,
    /// Conservative adaptive controller for auto mode; only touched by this
    /// engine's I/O thread, so the fast path never takes a lock.
    policy: UdpSockmapPolicy = .{},
    /// Generation-tagged steering gate. Bit 0 blocks new sockmap pairings;
    /// bit 1 marks a runtime snapshot publication in progress; upper bits are
    /// a monotonically increasing generation. Only the engine clears a block,
    /// using compare-exchange against the exact generation it applied.
    steering_gate: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    /// Allocation-free, coalescing command bits. Both commands are idempotent;
    /// processCommands handles reload before reset when both are pending.
    command_flags: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),
    /// Guards wake_fd signalling (enqueue/stop) against the close in stop(),
    /// so a signal write can never land on a closed or reused descriptor.
    signal_mutex: Mutex = .{},
    stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    activated: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
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
    sockmap_runtime: ?UdpSockmapRuntime = null,
    warned_at_limit: bool = false,
    sweep_buffer: std.ArrayList(SocketAddr) = .empty,
    last_sweep_ms: u64 = 0,
    accelerate_cooldown_until_ms: u64 = 0,
    last_send_error_log_ms: u64 = 0,
    /// Cached auto eligibility (no loopback upstream); refreshed on startup
    /// and reload so the I/O thread never locks the runtime snapshot.
    sockmap_eligible: bool = false,
    last_policy_tick_ms: u64 = 0,
    /// Userspace receive totals accumulated for the policy window; reset by
    /// the policy tick in run().
    policy_recv_datagrams: u64 = 0,
    policy_recv_bytes: u64 = 0,
    /// Reusable sendmmsg header/iovec storage, confined to this engine's I/O
    /// thread like the rest of the state below; avoids rebuilding the header
    /// set on the stack for every send batch.
    send_io: bpf.UdpSendBatchIo = undefined,
    /// Contiguous staging buffer for the UDP GSO fast path. Datagrams of a
    /// uniformly sized batch are copied here so they can be handed to the
    /// kernel as one send per up-to-64 KiB chunk with UDP_SEGMENT set to the
    /// datagram size, replacing a 64-entry sendmmsg with a handful of GSO
    /// sends. Confined to the engine's I/O thread.
    gso_staging: [bpf.udp_gso_max_bytes]u8 = undefined,
    /// Data-path accounting incremented on this engine's I/O thread; atomics
    /// make the aggregate snapshot readable from any thread. The counters are
    /// strictly cumulative and never reset, so `countersSnapshot` stays
    /// coherent; `logBatchStats` derives its per-interval batch fill by
    /// diffing successive snapshots instead.
    counters: UdpEngineCounters = .{},
    /// Cumulative counter snapshot at the previous stats tick; lets
    /// `logBatchStats` report per-interval deltas without resetting the
    /// exported atomic counters. Only the I/O thread touches it.
    last_stats_snapshot: ?UdpDataPathCounters = null,
    last_stats_log_ms: u64 = 0,

    pub fn init(
        runtime: *RuntimeConfiguration,
        log_store: *LogStore,
        budget: *UdpAssociationBudget,
        allocator: Allocator,
        engine_count: u32,
        engine_index: u32,
        enable_sockmap_acceleration: ?bool,
        loader: ?SockmapRuntimeLoader,
        loader_context: ?*anyopaque,
        announce_listen: bool,
        upstream_selector: ?UpstreamSelector,
    ) UdpRelayEngine {
        return .{
            .runtime = runtime,
            .log = log_store,
            .budget = budget,
            .allocator = allocator,
            .engine_count = @max(1, engine_count),
            .engine_index = engine_index,
            .announce_listen = announce_listen,
            .enable_sockmap_override = enable_sockmap_acceleration,
            .loader = loader orelse default_sockmap_runtime_loader,
            .loader_context = loader_context,
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

        self.sockmap_eligible = !snapshot.upstreamLoopback();
        const now_ms = monotonicMilliseconds();
        self.last_policy_tick_ms = now_ms;
        const mode = sockmapMode(self.enable_sockmap_override, &snapshot);
        self.policy.reset(mode);
        switch (mode) {
            .enabled => {
                if (self.tryLoadAccelerator(&snapshot)) {
                    self.log.info("udp sockmap acceleration enabled", .{});
                }
            },
            .auto, .disabled => {
                self.log.info("udp sockmap acceleration disabled", .{});
            },
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

    /// This engine's data-path counter snapshot; safe to read from any thread.
    pub fn countersSnapshot(self: *const UdpRelayEngine) UdpDataPathCounters {
        return self.counters.snapshot();
    }

    pub fn resetAssociations(self: *UdpRelayEngine) void {
        self.enqueue(.reset_associations);
    }

    pub fn updateAccelerator(self: *UdpRelayEngine) void {
        self.enqueue(.reload_accelerator);
    }

    /// Publishes a new pending gate generation before its runtime snapshot is
    /// updated. Existing blocks are preserved even for an allowing update;
    /// only the engine that applies the completed generation may clear them.
    fn beginSteeringUpdate(self: *UdpRelayEngine, blocks_steering: bool) u64 {
        while (true) {
            const current = self.steering_gate.load(.acquire);
            const blocked = (current & steering_blocked_bit) != 0 or blocks_steering;
            const next = (current & ~@as(u64, 3)) + steering_generation_step |
                steering_publishing_bit |
                @as(u64, @intFromBool(blocked));
            if (self.steering_gate.cmpxchgWeak(current, next, .acq_rel, .acquire) == null) return next;
        }
    }

    /// Completes publication of the generation returned by beginSteeringUpdate.
    /// A superseding update makes the compare-exchange fail, leaving its newer
    /// gate untouched.
    fn finishSteeringUpdate(self: *UdpRelayEngine, pending: u64) void {
        _ = self.steering_gate.cmpxchgStrong(
            pending,
            pending & ~steering_publishing_bit,
            .release,
            .acquire,
        );
    }

    /// Clears the block for an applied generation only when it is fully
    /// published and still current. Returns whether the clear succeeded.
    fn clearAppliedSteeringGate(self: *UdpRelayEngine, applied: u64) bool {
        if (applied & steering_publishing_bit != 0) return false;
        return self.steering_gate.cmpxchgStrong(
            applied,
            applied & ~steering_blocked_bit,
            .release,
            .acquire,
        ) == null;
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
        _ = self.command_flags.fetchOr(command.bit(), .release);
        self.signal_mutex.lock();
        if (self.wake_fd >= 0) bpf.eventfdSignal(self.wake_fd);
        self.signal_mutex.unlock();
    }

    fn run(self: *UdpRelayEngine) void {
        setThreadName();
        // Pin this engine to its affinity CPU before the I/O loop. A failed
        // pin is non-fatal: the engine just stays on kernel scheduling.
        const affinity = self.runtime.current().configuration.performance.thread_cpu_affinity;
        performance.pinThread(affinity, self.engine_index) catch |err| {
            self.log.warning("udp engine cpu affinity failed index={d} error={s}", .{
                self.engine_index, @errorName(err),
            });
        };
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
                } else if (!self.activated.load(.acquire)) {
                    continue;
                } else if (self.client_fd_to_client.get(fd)) |client| {
                    self.drainClient(fd, client, &recv_slots, &recv_io, now_ms);
                } else if (self.upstream_to_client.get(fd)) |client| {
                    self.drainUpstream(fd, client, &recv_slots, &recv_io, now_ms);
                } else {
                    self.drainListen(fd, &recv_slots, &send_slots, &recv_io, now_ms);
                }
            }
            // One policy tick per evidence window: feed the userspace totals
            // accumulated during the window to the adaptive controller and act
            // on its decision (load, keep, or regress to userspace). Ticks are
            // throttled by elapsed time, and quiet windows simply reset the
            // totals, so the controller never sees traffic-doubled samples.
            if (now_ms -% self.last_policy_tick_ms >= UdpSockmapPolicy.window_ms) {
                self.last_policy_tick_ms = now_ms;
                self.handlePolicyTick(now_ms);
            }
            // The 50 ms sweep is throttled by elapsed time, not by wake
            // count: busy engines would otherwise rescan all sessions after
            // every batch.
            if (now_ms -% self.last_sweep_ms >= sweep_interval_ms) {
                self.last_sweep_ms = now_ms;
                self.sweepExpiredAssociations(now_ms);
            }
            if (now_ms -% self.last_stats_log_ms >= stats_log_interval_ms) {
                self.last_stats_log_ms = now_ms;
                self.logBatchStats();
            }
        }
    }

    /// Rate-limited debug view of aggregate batch utilization. Metadata only:
    /// never logs datagram contents. Averages are the per-syscall batch fill,
    /// i.e. datagrams divided by syscalls since the previous snapshot. Idle
    /// windows are skipped so silent engines never emit log lines.
    fn logBatchStats(self: *UdpRelayEngine) void {
        // Diff the cumulative counters since the last tick rather than reset
        // them: the exported countersSnapshot must stay cumulative for any
        // external aggregation, and the deltas are exactly the per-interval
        // batch-fill figures this log line reports.
        const current = self.counters.snapshot();
        defer self.last_stats_snapshot = current;
        const previous = self.last_stats_snapshot orelse return;
        const interval = bpf.counters.delta(UdpDataPathCounters, current, previous);
        const recv_calls = interval.recv_calls;
        const recv_datagrams = interval.recv_datagrams;
        const send_calls = interval.send_calls;
        const send_datagrams = interval.send_datagrams;
        if (recv_calls == 0 and send_calls == 0) return;
        if (!self.log.isEnabled(log.Level.debug)) return;
        const recv_avg: u64 = if (recv_calls > 0) recv_datagrams / recv_calls else 0;
        const send_avg: u64 = if (send_calls > 0) send_datagrams / send_calls else 0;
        self.log.debug(
            "udp batch stats recv_calls={d} recv_datagrams={d} recv_avg={d} send_calls={d} send_datagrams={d} send_avg={d}",
            .{ recv_calls, recv_datagrams, recv_avg, send_calls, send_datagrams, send_avg },
        );
    }

    fn processCommands(self: *UdpRelayEngine) void {
        const flags = self.command_flags.swap(0, .acq_rel);
        if (flags & Command.reload_accelerator.bit() != 0) self.reloadAccelerator();
        if (flags & Command.reset_associations.bit() != 0) self.closeAllAssociations();
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
        self.sockmap_runtime = self.loader(self.loader_context, self.allocator, sockmapMaxEntries(snapshot, self.engine_count), &verifier_log) catch {
            self.log.warning(
                "udp sockmap acceleration unavailable; using userspace relay error={s} verifier={s}",
                .{ errnoDescription(), std.mem.sliceTo(&verifier_log, 0) },
            );
            return false;
        };
        return true;
    }

    /// One policy tick: feed the userspace totals accumulated over the window
    /// to the adaptive controller and act on its decision. Runs on the engine's
    /// I/O thread; the counter reset keeps every window's evidence disjoint.
    fn handlePolicyTick(self: *UdpRelayEngine, now_ms: u64) void {
        const action = self.policy.observeWindow(now_ms, .{
            .datagrams = self.policy_recv_datagrams,
            .bytes = self.policy_recv_bytes,
            .eligible = self.sockmap_eligible,
        });
        self.policy_recv_datagrams = 0;
        self.policy_recv_bytes = 0;
        switch (action) {
            .load => self.tryLoadFromPolicy(now_ms),
            .regress => {
                self.log.info("udp sockmap acceleration disabled", .{});
                self.syncSockmapToPolicy();
            },
            .stay_off, .keep_active => {},
        }
    }

    /// The controller asked for the runtime; load it once and record the
    /// outcome so the policy knows whether it is active or in a cooldown.
    fn tryLoadFromPolicy(self: *UdpRelayEngine, now_ms: u64) void {
        if (self.sockmap_runtime != null) {
            self.policy.noteLoaded();
            return;
        }
        const snapshot = self.runtime.current();
        if (self.tryLoadAccelerator(&snapshot)) {
            self.policy.noteLoaded();
            self.log.info("udp sockmap acceleration enabled", .{});
        } else {
            self.policy.noteLoadFailure(now_ms);
        }
    }

    /// Tear the runtime down unless the policy still allows steering. Called
    /// after any policy transition (regression, pairing-failure storm) so a
    /// runtime never survives its policy; associations are unpaired first,
    /// then the runtime is destroyed, preserving the teardown ordering.
    fn syncSockmapToPolicy(self: *UdpRelayEngine) void {
        if (self.sockmap_runtime == null) return;
        if (self.policy.steerAllowed()) return;
        self.closeAllAssociations();
        self.sockmap_runtime.?.destroy();
        self.sockmap_runtime = null;
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
        const applied_gate = self.steering_gate.load(.acquire);
        const snapshot = self.runtime.current();
        const mode = sockmapMode(self.enable_sockmap_override, &snapshot);
        self.sockmap_eligible = !snapshot.upstreamLoopback();

        switch (mode) {
            .enabled => {
                // Explicit enabled always forces the runtime; the controller is
                // rebuilt only if it was not already enabled.
                if (self.policy.mode != .enabled) self.policy.reset(.enabled);
                if (self.sockmap_runtime == null) {
                    if (self.tryLoadAccelerator(&snapshot)) {
                        self.log.info("udp sockmap acceleration enabled", .{});
                        // Only newly established associations are steered.
                        self.closeAllAssociations();
                    }
                }
            },
            .auto => {
                // An unchanged auto mode with a still-eligible rule (e.g. a
                // routine limits-only reload) keeps the adaptive
                // runtime and policy exactly as they are. Teardown is only for
                // transitions that revoke acceleration: coming from explicit
                // enabled, or the rule becoming loopback-ineligible. In both
                // cases the controller resets to probing so eligible traffic
                // can re-arm it later (never "active" with a null runtime).
                const came_from_forced = self.policy.mode == .enabled;
                const now_ineligible = !self.sockmap_eligible;
                if (self.sockmap_runtime != null and (came_from_forced or now_ineligible)) {
                    // Close first so existing sessions fall back to the
                    // userspace relay before the runtime is destroyed.
                    self.log.info("udp sockmap acceleration disabled", .{});
                    self.closeAllAssociations();
                    self.sockmap_runtime.?.destroy();
                    self.sockmap_runtime = null;
                }
                if (self.policy.mode != .auto or now_ineligible) {
                    self.policy.reset(.auto);
                }
            },
            .disabled => {
                if (self.policy.mode != .disabled) self.policy.reset(.disabled);
                if (self.sockmap_runtime != null) {
                    self.log.info("udp sockmap acceleration disabled", .{});
                    self.closeAllAssociations();
                    self.sockmap_runtime.?.destroy();
                    self.sockmap_runtime = null;
                }
            },
        }

        // Clear the synchronous block only for the exact, fully-published
        // generation applied above. A concurrent or still-publishing update
        // changes the word, so this stale completion cannot clear its block.
        _ = self.clearAppliedSteeringGate(applied_gate);
    }

    const RecvBatchResult = struct {
        /// Datagrams buffered in slots[0..count]; forward these first.
        count: usize,
        /// recvmmsg syscalls consumed by this call, including the EAGAIN or
        /// failed one; the caller subtracts this from its remaining budget.
        calls: usize,
        /// The socket reported EAGAIN (nothing more is queued); drain no
        /// further.
        would_block: bool,
        /// A recvmmsg syscall failed after possibly buffering count
        /// datagrams; the caller should log the failure and tear the socket
        /// down after forwarding the partial batch (never drop received data).
        read_failed: bool,
    };

    /// Aggregates datagrams from one ready socket: repeatedly receives into
    /// the unused suffix of the 64-slot array with nonblocking recvmmsg until
    /// the array is full or the socket reports EAGAIN, counting every syscall
    /// (including EAGAIN and errors) against the caller's remaining
    /// `max_batches_per_drain` fairness budget so one hot socket cannot
    /// starve the other ready fds on this engine. Returns a consolidated
    /// batch of up to `batch_size` datagrams in slots[0..], the exact syscall
    /// count consumed, and how the drain ended; the caller forwards each
    /// returned batch, subtracts `calls`, and continues only while the batch
    /// filled and budget remains, so a hot source can produce several
    /// 64-datagram batches per readiness while never exceeding 16 recvmmsg
    /// calls total.
    fn drainRecvBatch(
        self: *UdpRelayEngine,
        fd: fd_t,
        recv_slots: *[batch_size]bpf.UdpSlot,
        recv_io: anytype,
        remaining_calls: usize,
        count_policy: bool,
    ) RecvBatchResult {
        var offset: usize = 0;
        var calls: usize = 0;
        var would_block = false;
        while (calls < remaining_calls and offset < batch_size) {
            const received = recv_io.recvInto(fd, &recv_slots.*, offset) catch {
                _ = self.counters.recv_calls.fetchAdd(1, .monotonic);
                return .{ .count = offset, .calls = calls + 1, .would_block = false, .read_failed = true };
            };
            calls += 1;
            _ = self.counters.recv_calls.fetchAdd(1, .monotonic);
            _ = self.counters.recv_datagrams.fetchAdd(received, .monotonic);
            if (received > 0) {
                var bytes: u64 = 0;
                for (recv_slots[offset .. offset + received]) |*slot| bytes += slot.length;
                _ = self.counters.recv_bytes.fetchAdd(bytes, .monotonic);
                // The adaptive policy's evidence is the client-side workload
                // only: datagrams arriving on the listener (client ingress)
                // and the accelerated client fallback socket. Upstream
                // responses are excluded so a chatty upstream cannot arm the
                // accelerator on the relay's reply volume.
                if (count_policy) {
                    self.policy_recv_datagrams += received;
                    self.policy_recv_bytes += bytes;
                }
            }
            if (received == 0) { // EAGAIN: the socket has nothing more
                would_block = true;
                break;
            }
            offset += received;
        }
        return .{ .count = offset, .calls = calls, .would_block = would_block, .read_failed = false };
    }

    fn drainListen(
        self: *UdpRelayEngine,
        fd: fd_t,
        recv_slots: *[batch_size]bpf.UdpSlot,
        send_slots: *[batch_size]bpf.UdpSlot,
        recv_io: *bpf.UdpRecvBatchIo,
        now_ms: u64,
    ) void {
        var remaining = max_batches_per_drain;
        while (remaining > 0) {
            const result = self.drainRecvBatch(fd, recv_slots, recv_io, remaining, true);
            remaining -= result.calls;
            if (result.count > 0) {
                self.forwardClientDatagrams(result.count, fd, recv_slots, send_slots, now_ms);
            }
            if (result.read_failed) {
                self.log.err("udp listener read failed error={s}", .{errnoDescription()});
                return;
            }
            if (result.would_block or result.count < batch_size) return;
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
        const CachedClient = struct {
            client: SocketAddr,
            upstream_fd: fd_t,
        };
        var run_fd: fd_t = -1;
        var run_length: usize = 0;
        var cached: ?CachedClient = null;
        for (recv_slots[0..count]) |*slot| {
            const client = socketAddrFromStorage(&slot.address) orelse continue;
            const upstream_fd: fd_t = blk: {
                // A datagram from the same client as the previous valid slot
                // reuses the upstream fd already resolved for this batch run,
                // skipping the association hash lookup (and its per-datagram
                // last_activity write) for every further datagram of the run.
                // The cache never survives across forwardClientDatagrams calls
                // and holds no association pointers, only a SocketAddr + fd.
                if (cached != null and cached.?.client.eql(client)) break :blk cached.?.upstream_fd;
                if (self.associations.getPtr(client)) |existing| {
                    existing.last_activity_ms = now_ms;
                    cached = .{ .client = client, .upstream_fd = existing.upstream_fd };
                    break :blk existing.upstream_fd;
                }
                const opened = self.openAssociation(
                    client,
                    slot.address,
                    slot.address_length,
                    listen_fd,
                    now_ms,
                ) orelse {
                    // No fd to reuse; force a fresh resolve for the next
                    // datagram of this client (baseline retried the open).
                    cached = null;
                    continue;
                };
                cached = .{ .client = client, .upstream_fd = opened };
                break :blk opened;
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
        var remaining = max_batches_per_drain;
        while (remaining > 0) {
            const result = self.drainRecvBatch(fd, recv_slots, recv_io, remaining, true);
            remaining -= result.calls;
            if (result.count > 0) {
                association.last_activity_ms = now_ms;
                var pass_bytes: u64 = 0;
                for (recv_slots[0..result.count]) |*slot| pass_bytes += slot.length;
                _ = self.counters.sockmap_pass_datagrams.fetchAdd(result.count, .monotonic);
                _ = self.counters.sockmap_pass_bytes.fetchAdd(pass_bytes, .monotonic);
                _ = self.sendAllDatagrams(
                    association.upstream_fd,
                    null,
                    0,
                    recv_slots[0..result.count],
                    "direction=client_to_upstream",
                    now_ms,
                );
            }
            if (result.read_failed) {
                self.log.err("udp client socket read failed client={f} error={s}", .{ client, errnoDescription() });
                self.closeAssociation(client);
                return;
            }
            if (result.would_block or result.count < batch_size) return;
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
        var remaining = max_batches_per_drain;
        while (remaining > 0) {
            const result = self.drainRecvBatch(fd, recv_slots, recv_io, remaining, false);
            remaining -= result.calls;
            if (result.count > 0) {
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
                    recv_slots[0..result.count],
                    "direction=upstream_to_client",
                    now_ms,
                );
            }
            if (result.read_failed) {
                self.log.err("udp upstream error client={f} error={s}", .{ client, errnoDescription() });
                if (self.upstream_selector) |selector| {
                    selector.reportFailure(association.upstream_addr, now_ms * std.time.ns_per_ms);
                }
                self.closeAssociation(client);
                return;
            }
            if (result.would_block or result.count < batch_size) return;
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
        var sent_total: usize = 0;
        while (sent_total < slots.len) {
            const remaining = slots[sent_total..];
            // GSO applies only to connected upstream sockets (address == null):
            // the reverse direction shares the listen socket across clients and
            // cannot carry a per-association segment size. When the fast path
            // does apply it replaces the whole sendmmsg for that run.
            if (address == null) {
                if (self.gsoSendBatch(fd, remaining, context, now_ms)) |sent| {
                    if (sent == 0) return false;
                    sent_total += sent;
                    if (sent == remaining.len) return true;
                    continue;
                }
            }
            const sent = self.send_io.send(fd, address, address_length, remaining) catch {
                _ = self.counters.send_calls.fetchAdd(1, .monotonic);
                self.noteSendError(remaining.len, context, errnoDescription(), now_ms);
                return false;
            };
            _ = self.counters.send_calls.fetchAdd(1, .monotonic);
            _ = self.counters.send_datagrams.fetchAdd(sent, .monotonic);
            var sent_bytes: u64 = 0;
            for (remaining[0..sent]) |*slot| sent_bytes += slot.length;
            _ = self.counters.send_bytes.fetchAdd(sent_bytes, .monotonic);
            if (sent == 0) {
                self.noteSendError(remaining.len, context, "sendmmsg made no progress", now_ms);
                return false;
            }
            sent_total += sent;
        }
        return true;
    }

    /// UDP GSO fast path for a uniformly sized send batch to a connected
    /// socket. Payloads are copied into the engine's staging buffer and handed
    /// to the kernel as one send per up-to-64 KiB chunk with UDP_SEGMENT set to
    /// the datagram size, so the kernel emits exactly one UDP datagram per
    /// segment and amortizes the per-datagram route/skb/xmit cost over a GSO
    /// skb. Returns null when GSO does not apply (mixed sizes, tiny batches,
    /// empty datagrams); otherwise the number of datagrams handed to the
    /// kernel, 0 only on a send error (the caller drops the batch like a failed
    /// sendmmsg). Partial GSO progress is reported so the caller forwards the
    /// remainder through the ordinary path.
    fn gsoSendBatch(
        self: *UdpRelayEngine,
        fd: fd_t,
        slots: []const bpf.UdpSlot,
        comptime context: []const u8,
        now_ms: u64,
    ) ?usize {
        // A handful of datagrams is too few to pay the staging copy and the
        // UDP_SEGMENT toggle; sendmmsg already handles those cheaply.
        if (slots.len < 4) return null;
        const gso_size: usize = slots[0].length;
        if (gso_size == 0) return null;
        for (slots) |*slot| {
            if (slot.length != gso_size) return null;
        }
        const sent = bpf.udpSendGso(fd, slots, &self.gso_staging) catch {
            _ = self.counters.send_calls.fetchAdd(1, .monotonic);
            self.noteSendError(slots.len, context, errnoDescription(), now_ms);
            return 0;
        };
        const per_send = @max(@as(usize, 1), bpf.udp_gso_max_bytes / gso_size);
        // udpSendGso advances whole chunks, so the datagrams it handed to the
        // kernel are exactly ceil(sent/per_send) full chunks; counting from
        // `sent` keeps the send_calls figure accurate on partial progress
        // instead of assuming the whole batch was sent.
        const calls = (sent + per_send - 1) / per_send;
        _ = self.counters.send_calls.fetchAdd(calls, .monotonic);
        _ = self.counters.send_datagrams.fetchAdd(sent, .monotonic);
        var bytes: u64 = 0;
        for (slots[0..sent]) |*slot| bytes += slot.length;
        _ = self.counters.send_bytes.fetchAdd(bytes, .monotonic);
        return sent;
    }

    /// Drop logging is rate-limited per engine: sustained backpressure would
    /// otherwise serialize all engine threads on the shared log mutex once
    /// per failed batch.
    fn noteSendError(self: *UdpRelayEngine, dropped: usize, comptime context: []const u8, error_text: []const u8, now_ms: u64) void {
        _ = self.counters.send_error_drops.fetchAdd(dropped, .monotonic);
        if (now_ms -% self.last_send_error_log_ms < send_error_log_interval_ms) return;
        self.last_send_error_log_ms = now_ms;
        self.log.warning("udp datagrams dropped {s} dropped={d} total_dropped={d} error={s}", .{
            context,
            dropped,
            self.counters.send_error_drops.load(.monotonic),
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
        // The selector (rules module) picks the upstream per association;
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
        var pairing: ?UdpSockmapRuntime.Pairing = null;
        errdefer {
            if (pairing) |p| {
                if (self.sockmap_runtime) |*runtime| runtime.unpair(p.client_cookie, p.upstream_cookie);
            }
            if (client_fd) |fd| _ = linux.close(fd);
        }
        // Steering is gated by the adaptive controller AND the synchronous
        // reload guard: once updateConfiguration has made the snapshot
        // disallow sockmap, no newly established association may enter the map
        // even while the async teardown command is still pending.
        if (self.sockmap_runtime != null and
            self.steering_gate.load(.acquire) & steering_blocked_bit == 0 and
            self.policy.steerAllowed() and
            now_ms >= self.accelerate_cooldown_until_ms)
        {
            if (self.listen_bound.get(listen_fd)) |bind_storage| {
                _ = self.counters.sockmap_pair_attempts.fetchAdd(1, .monotonic);
                if (self.accelerateAssociation(bind_storage, client_address, client_address_length, upstream_fd)) |accelerated| {
                    client_fd = accelerated.fd;
                    pairing = accelerated.pairing;
                    _ = self.counters.sockmap_pair_successes.fetchAdd(1, .monotonic);
                    self.policy.notePairingSuccess();
                } else |err| {
                    _ = self.counters.sockmap_pair_failures.fetchAdd(1, .monotonic);
                    // Kernel steering is best-effort per association; fall
                    // back to the userspace relay for this client. Repeated
                    // failures (e.g. a full sockhash) pause further attempts
                    // so every new session does not pay the failed pair cost,
                    // and sustained failures regress the auto controller.
                    self.accelerate_cooldown_until_ms = now_ms + accelerate_failure_cooldown_ms;
                    self.policy.notePairingFailure(now_ms);
                    self.syncSockmapToPolicy();
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
        // The sole caller only invokes this under `sockmap_runtime != null`,
        // and the runtime is never destroyed on this I/O thread meanwhile.
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
        // Allocation-free teardown: removing the first key repeatedly cannot
        // fail, so an OOM can never leave paired associations alive while the
        // runtime is destroyed underneath them. Each removal unpairs first
        // (kernel steering stops before the sockets are closed) and releases
        // the association budget exactly once.
        while (self.associations.count() > 0) {
            var iterator = self.associations.keyIterator();
            self.closeAssociation(iterator.next().?.*);
        }
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

/// The sockmap mode for a resolved configuration, honoring the listener/engine
/// test override when set.
fn sockmapMode(override: ?bool, resolved: *const ResolvedConfiguration) config.SockmapAccelerationMode {
    if (override) |forced| return if (forced) .enabled else .disabled;
    return resolved.configuration.performance.udp_sockmap_acceleration;
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
            .is_multi_fn = isMulti,
            .pick_fn = pick,
            .report_success_fn = reportSuccess,
            .report_failure_fn = reportFailure,
        };
    }

    fn isMulti(context: *anyopaque) bool {
        const self: *MockUdpSelector = @ptrCast(@alignCast(context));
        return self.addresses.len > 1;
    }

    fn deinit(self: *MockUdpSelector) void {
        self.picks.deinit(testing.allocator);
        self.failures.deinit(testing.allocator);
        self.successes.deinit(testing.allocator);
    }

    fn pick(context: *anyopaque, client: ?SocketAddr, now_ns: u64) SocketAddr {
        _ = client;
        _ = now_ns;
        const self: *MockUdpSelector = @ptrCast(@alignCast(context));
        const address = self.addresses[self.cursor % self.addresses.len];
        self.cursor += 1;
        self.picks.append(testing.allocator, address) catch {};
        return address;
    }

    fn reportSuccess(context: *anyopaque, upstream_addr: SocketAddr) void {
        const self: *MockUdpSelector = @ptrCast(@alignCast(context));
        self.successes.append(testing.allocator, upstream_addr) catch {};
    }

    fn reportFailure(context: *anyopaque, upstream_addr: SocketAddr, now_ns: u64) void {
        _ = now_ns;
        const self: *MockUdpSelector = @ptrCast(@alignCast(context));
        self.failures.append(testing.allocator, upstream_addr) catch {};
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

test "udp prepared listener does not forward until activated" {
    var echo = try UdpEchoServer.start();
    defer echo.stop();

    var logger = LogStore.init("critical");
    const resolved = try makeUdpTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = UdpListener.init(testing.allocator, resolved, &logger, false, null);
    listener.start_paused = true;
    defer listener.deinit();
    try listener.start();

    const bound = try listener.localAddresses(testing.allocator);
    defer testing.allocator.free(bound);
    const client = try udpClient();
    defer closeFd(client);

    try udpSendTo(client, bound[0].port, "paused");
    var buf: [64]u8 = undefined;
    try testing.expect(try udpReceive(client, &buf) == null);

    listener.activate();
    try testing.expect(try waitForEcho(client, bound[0].port, "paused", 2_000));
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
    const pool_module = @import("upstream.zig");

    var echo = try UdpEchoServer.start();
    defer echo.stop();
    const live = SocketAddr.parseIp("127.0.0.1", echo.port).?;
    const dead = SocketAddr.parseIp("127.0.0.1", 1).?; // ICMP port unreachable

    var pool = try pool_module.UpstreamPool.init(testing.allocator, &.{ dead, live }, &.{ 1, 1 }, pool_module.defaultBalancer());
    defer pool.deinit();

    const selector = pool_module.poolSelector(&pool);

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

/// Never-started engine shell used to drive drainRecvBatch against a real
/// UDP socket. Only the batch-statistics fields are exercised; no I/O thread
/// spawns and no listener resources are bound, so destroy() is a pure teardown
/// of the empty session maps. Allocated so the engine's runtime/budget
/// pointers stay valid for the harness lifetime.
const DrainHarness = struct {
    engine: UdpRelayEngine,
    runtime: RuntimeConfiguration,
    budget: UdpAssociationBudget,
    logger: LogStore,
    resolved_listen: []SocketAddr,
    buffer: [bpf.udp_batch_capacity * 16]u8 = undefined,
    recv_slots: [bpf.udp_batch_capacity]bpf.UdpSlot = undefined,
    recv_io: bpf.UdpRecvBatchIo = undefined,

    fn init() !*DrainHarness {
        const self = try testing.allocator.create(DrainHarness);
        errdefer testing.allocator.destroy(self);
        const resolved = try makeUdpTestResolved(testing.allocator, 9);
        errdefer testing.allocator.free(resolved.listen_addresses);
        self.logger = LogStore.init("critical");
        self.resolved_listen = resolved.listen_addresses;
        self.budget = .{};
        self.runtime = RuntimeConfiguration.init(resolved);
        self.engine = UdpRelayEngine.init(&self.runtime, &self.logger, &self.budget, testing.allocator, 1, 0, null, null, null, false, null);
        for (&self.recv_slots, 0..) |*slot, i| {
            slot.* = .{ .data = self.buffer[i * 16 ..][0..16].ptr, .capacity = 16 };
        }
        self.recv_io.init(&self.recv_slots);
        return self;
    }

    fn deinit(self: *DrainHarness) void {
        self.engine.destroy();
        testing.allocator.free(self.resolved_listen);
        testing.allocator.destroy(self);
    }
};

fn loopbackV4Socket(port: u16) posix.sockaddr {
    const addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    return @bitCast(addr);
}

test "udp drain budget counts eagain and error recvmmsg syscalls" {
    const listen_address = loopbackV4Socket(0);
    var bound: bpf.BoundAddress = undefined;
    const fd = try bpf.udpListenSocket(&listen_address, @sizeOf(posix.sockaddr.in), &bound);
    defer closeFd(fd);

    const harness = try DrainHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;
    const recv_slots = &harness.recv_slots;
    const recv_io = &harness.recv_io;

    // Empty socket: the single recvmmsg reports EAGAIN and is counted, so a
    // readiness event that turns out to be spurious still bills its syscall.
    const eagain = engine.drainRecvBatch(fd, recv_slots, recv_io, UdpRelayEngine.max_batches_per_drain, true);
    try testing.expectEqual(@as(usize, 0), eagain.count);
    try testing.expectEqual(@as(usize, 1), eagain.calls);
    try testing.expect(eagain.would_block);
    try testing.expect(!eagain.read_failed);
    try testing.expectEqual(@as(u64, 1), engine.counters.snapshot().recv_calls);
    try testing.expectEqual(@as(u64, 0), engine.counters.snapshot().recv_datagrams);

    // A non-socket fd makes recvmmsg fail (ENOTSOCK): the failed syscall is
    // counted exactly once and the drain ends with read_failed so the caller
    // tears the socket down after forwarding any partial batch.
    const event_fd = try bpf.eventfdCreate();
    defer closeFd(event_fd);
    const failed = engine.drainRecvBatch(event_fd, recv_slots, recv_io, UdpRelayEngine.max_batches_per_drain, true);
    try testing.expectEqual(@as(usize, 0), failed.count);
    try testing.expectEqual(@as(usize, 1), failed.calls);
    try testing.expect(!failed.would_block);
    try testing.expect(failed.read_failed);
    try testing.expectEqual(@as(u64, 2), engine.counters.snapshot().recv_calls);
    try testing.expectEqual(@as(u64, 0), engine.counters.snapshot().recv_datagrams);
}

test "udp drain budget yields multiple consolidated batches within one readiness" {
    const listen_address = loopbackV4Socket(0);
    var bound: bpf.BoundAddress = undefined;
    const fd = try bpf.udpListenSocket(&listen_address, @sizeOf(posix.sockaddr.in), &bound);
    defer closeFd(fd);

    const bound_in: *const posix.sockaddr.in = @ptrCast(&bound.address);
    const destination = loopbackV4Socket(std.mem.bigToNative(u16, bound_in.port));
    const send_fd = try bpf.udpUpstreamSocket(&destination, @sizeOf(posix.sockaddr.in));
    defer closeFd(send_fd);

    const harness = try DrainHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;
    const recv_slots = &harness.recv_slots;
    const recv_io = &harness.recv_io;

    // Queue 200 datagrams (three full 64-datagram batches plus a trailing 8)
    // before draining, then let loopback delivery settle.
    const payload = "drain-budget-datagram";
    for (0..200) |_| {
        const rc = linux.sendto(send_fd, payload.ptr, payload.len, linux.MSG.NOSIGNAL, null, 0);
        try testing.expect(linux.errno(rc) == .SUCCESS);
    }
    sleepMs(50);

    // Drive the production readiness loop (mirroring drainListen/drainUpstream):
    // forward each consolidated batch, subtract its exact syscall count, and
    // continue only while the batch filled and budget remains. A would_block
    // ends the round; a fresh readiness event gets a fresh 16-call budget.
    var total: usize = 0;
    var full_batches: usize = 0;
    var max_calls_in_round: usize = 0;
    var ended_on_eagain = false;
    while (total < 200) {
        var remaining = UdpRelayEngine.max_batches_per_drain;
        var round_calls: usize = 0;
        var round_full: usize = 0;
        while (remaining > 0) {
            const result = engine.drainRecvBatch(fd, recv_slots, recv_io, remaining, true);
            remaining -= result.calls;
            round_calls += result.calls;
            total += result.count;
            if (result.count == bpf.udp_batch_capacity) round_full += 1;
            if (result.read_failed) break;
            if (result.would_block) {
                ended_on_eagain = true;
                break;
            }
            if (result.count < bpf.udp_batch_capacity) break; // budget exhausted, not empty
        }
        max_calls_in_round = @max(max_calls_in_round, round_calls);
        full_batches += round_full;
        if (remaining > 0 and total < 200) sleepMs(1); // wait for the next wake
    }

    try testing.expectEqual(@as(usize, 200), total);
    try testing.expectEqual(@as(u64, 200), engine.counters.snapshot().recv_datagrams);
    try testing.expect(ended_on_eagain);
    // A hot source yields multiple 64-datagram forward batches.
    try testing.expect(full_batches >= 3);
    // No single readiness event exceeded the 16 recvmmsg fairness cap.
    try testing.expect(max_calls_in_round <= UdpRelayEngine.max_batches_per_drain);
    // 200 datagrams need at least ceil(200/64)=4 data syscalls plus at least
    // one EAGAIN; every attempted recvmmsg was counted, none dropped.
    try testing.expect(engine.counters.snapshot().recv_calls >= 5);
}

const ScriptedRecvResult = union(enum) {
    datagrams: usize,
    failed: bpf.Error,
};

/// Deterministic recvmmsg front-end for drainRecvBatch: drains issue no real
/// syscalls and replay a fixed outcome script, so a success-then-error drain
/// is reproducible regardless of kernel scheduling.
const ScriptedRecvIo = struct {
    results: []const ScriptedRecvResult,
    call_index: usize = 0,

    fn recvInto(self: *ScriptedRecvIo, fd: fd_t, slots: []bpf.UdpSlot, offset: usize) bpf.Error!usize {
        _ = fd;
        const result = self.results[self.call_index];
        self.call_index += 1;
        switch (result) {
            .datagrams => |count| {
                for (slots[offset .. offset + count]) |*slot| {
                    slot.length = 1;
                    slot.address_length = @sizeOf(posix.sockaddr.in);
                }
                return count;
            },
            .failed => |e| return e,
        }
    }
};

test "udp drain budget counts success then error without re-adding work" {
    var harness = try DrainHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;
    const recv_slots = &harness.recv_slots;

    var script = ScriptedRecvIo{ .results = &.{
        .{ .datagrams = 1 },
        .{ .datagrams = 1 },
        .{ .failed = bpf.Error.Unexpected },
    } };
    const result = engine.drainRecvBatch(-1, recv_slots, &script, UdpRelayEngine.max_batches_per_drain, true);
    try testing.expectEqual(@as(usize, 2), result.count);
    try testing.expectEqual(@as(usize, 3), result.calls);
    try testing.expect(!result.would_block);
    try testing.expect(result.read_failed);
    // Two successes plus the failing syscall: exactly three calls.
    try testing.expectEqual(@as(u64, 3), engine.counters.snapshot().recv_calls);
    // Only the two successfully received datagrams are counted.
    try testing.expectEqual(@as(u64, 2), engine.counters.snapshot().recv_datagrams);
}

test "udp policy evidence counts client-side receives only, not upstream responses" {
    var harness = try DrainHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;
    const recv_slots = &harness.recv_slots;

    // Upstream responses (count_policy=false) count toward the batch stats
    // but never feed the adaptive policy's userspace evidence.
    var upstream_script = ScriptedRecvIo{ .results = &.{
        .{ .datagrams = 2 },
        .{ .datagrams = 0 },
    } };
    _ = engine.drainRecvBatch(-1, recv_slots, &upstream_script, UdpRelayEngine.max_batches_per_drain, false);
    try testing.expectEqual(@as(u64, 2), engine.counters.snapshot().recv_datagrams);
    try testing.expectEqual(@as(u64, 0), engine.policy_recv_datagrams);
    try testing.expectEqual(@as(u64, 0), engine.policy_recv_bytes);

    // Client ingress and accelerated client fallback (count_policy=true) feed
    // the evidence; each scripted slot carries one byte.
    var client_script = ScriptedRecvIo{ .results = &.{
        .{ .datagrams = 2 },
        .{ .datagrams = 0 },
    } };
    _ = engine.drainRecvBatch(-1, recv_slots, &client_script, UdpRelayEngine.max_batches_per_drain, true);
    try testing.expectEqual(@as(u64, 4), engine.counters.snapshot().recv_datagrams);
    try testing.expectEqual(@as(u64, 2), engine.policy_recv_datagrams);
    try testing.expectEqual(@as(u64, 2), engine.policy_recv_bytes);
}

// ---------------------------------------------------------------------------
// UDP sockmap policy + reload race tests
// ---------------------------------------------------------------------------

/// Deterministic stand-in for a kernel sockmap runtime: no BPF is loaded;
/// pair/idle/destroy just record calls and their relative order, so the
/// engine's steering decisions and teardown ordering are observable without
/// privileges.
const FakeSockmapRuntime = struct {
    const Event = enum { pair, unpair, destroy };

    pair_calls: usize = 0,
    unpair_calls: usize = 0,
    destroy_calls: usize = 0,
    fail_pairs: bool = false,
    events: std.ArrayList(Event) = .empty,

    fn deinit(self: *FakeSockmapRuntime) void {
        self.events.deinit(testing.allocator);
    }

    fn loader(context: ?*anyopaque, allocator: Allocator, max_entries: u32, verifier_log: ?[]u8) bpf.Error!UdpSockmapRuntime {
        _ = allocator;
        _ = max_entries;
        _ = verifier_log;
        const self: *FakeSockmapRuntime = @ptrCast(@alignCast(context.?));
        return .{ .context = self, .vtable = &fake_sockmap_vtable };
    }

    fn pair(ctx: *anyopaque, client_fd: fd_t, upstream_fd: fd_t) bpf.Error!UdpSockmapRuntime.Pairing {
        _ = client_fd;
        _ = upstream_fd;
        const self: *FakeSockmapRuntime = @ptrCast(@alignCast(ctx));
        self.pair_calls += 1;
        self.events.append(testing.allocator, .pair) catch {};
        if (self.fail_pairs) return error.TableFull;
        return .{ .client_cookie = 1, .upstream_cookie = 2 };
    }

    fn unpair(ctx: *anyopaque, client_cookie: u64, upstream_cookie: u64) void {
        _ = client_cookie;
        _ = upstream_cookie;
        const self: *FakeSockmapRuntime = @ptrCast(@alignCast(ctx));
        self.unpair_calls += 1;
        self.events.append(testing.allocator, .unpair) catch {};
    }

    fn idleRemainingNs(ctx: *anyopaque, client_cookie: u64, upstream_cookie: u64, idle_timeout_ns: u64) bpf.Error!u64 {
        _ = ctx;
        _ = client_cookie;
        _ = upstream_cookie;
        return idle_timeout_ns; // never expires
    }

    fn destroy(ctx: *anyopaque) void {
        const self: *FakeSockmapRuntime = @ptrCast(@alignCast(ctx));
        self.destroy_calls += 1;
        self.events.append(testing.allocator, .destroy) catch {};
    }
};

const fake_sockmap_vtable = UdpSockmapRuntime.VTable{
    .pair = FakeSockmapRuntime.pair,
    .unpair = FakeSockmapRuntime.unpair,
    .idle_remaining_ns = FakeSockmapRuntime.idleRemainingNs,
    .destroy = FakeSockmapRuntime.destroy,
};

fn waitForCondition(condition: *const fn () bool, timeout_ms: u64) bool {
    var waited: u64 = 0;
    while (waited < timeout_ms) {
        if (condition()) return true;
        sleepMs(5);
        waited += 5;
    }
    return condition();
}

fn qualifyingSample() UdpSockmapPolicy.WindowSample {
    return .{
        .datagrams = UdpSockmapPolicy.min_datagrams_per_window,
        .bytes = UdpSockmapPolicy.min_datagrams_per_window * UdpSockmapPolicy.min_avg_datagram_bytes,
        .eligible = true,
    };
}

test "udp sockmap policy: auto starts in userspace; enabled and disabled are unconditional" {
    var policy = UdpSockmapPolicy{};
    policy.reset(.auto);
    try testing.expect(!policy.steerAllowed());
    // auto ignores evidence until the qualifying windows elapse.
    for (0..UdpSockmapPolicy.probe_stable_windows) |_| {
        try testing.expectEqual(UdpSockmapPolicy.Action.stay_off, policy.observeWindow(1_000, .{ .datagrams = 0, .bytes = 0, .eligible = true }));
    }
    try testing.expect(!policy.steerAllowed());

    var enabled = UdpSockmapPolicy{};
    enabled.reset(.enabled);
    try testing.expect(enabled.steerAllowed());
    try testing.expectEqual(
        UdpSockmapPolicy.Action.keep_active,
        enabled.observeWindow(1_000, .{ .datagrams = 0, .bytes = 0, .eligible = false }),
    );

    var disabled = UdpSockmapPolicy{};
    disabled.reset(.disabled);
    try testing.expect(!disabled.steerAllowed());
    try testing.expectEqual(
        UdpSockmapPolicy.Action.stay_off,
        disabled.observeWindow(1_000, .{ .datagrams = 0, .bytes = 0, .eligible = false }),
    );
}

test "udp sockmap policy: auto arms only after stable, eligible, large-datagram evidence" {
    var now: u64 = 1_000;
    var policy = UdpSockmapPolicy{};
    policy.reset(.auto);
    const good = qualifyingSample();

    // Small-packet workloads (average below the byte floor) never qualify.
    for (0..UdpSockmapPolicy.probe_stable_windows) |_| {
        now += UdpSockmapPolicy.window_ms;
        try testing.expectEqual(
            UdpSockmapPolicy.Action.stay_off,
            policy.observeWindow(now, .{ .datagrams = 500, .bytes = 100 * 500, .eligible = true }),
        );
    }
    try testing.expect(!policy.steerAllowed());

    // Loopback-ineligible workloads never qualify either.
    for (0..UdpSockmapPolicy.probe_stable_windows) |_| {
        now += UdpSockmapPolicy.window_ms;
        try testing.expectEqual(UdpSockmapPolicy.Action.stay_off, policy.observeWindow(now, .{
            .datagrams = good.datagrams,
            .bytes = good.bytes,
            .eligible = false,
        }));
    }
    try testing.expect(!policy.steerAllowed());

    // A single quiet window resets the streak (hysteresis), so a partially
    // accumulated run cannot arm.
    for (0..UdpSockmapPolicy.probe_stable_windows - 1) |_| {
        now += UdpSockmapPolicy.window_ms;
        try testing.expectEqual(UdpSockmapPolicy.Action.stay_off, policy.observeWindow(now, good));
    }
    now += UdpSockmapPolicy.window_ms;
    try testing.expectEqual(UdpSockmapPolicy.Action.stay_off, policy.observeWindow(now, .{ .datagrams = 0, .bytes = 0, .eligible = true }));
    for (0..UdpSockmapPolicy.probe_stable_windows - 1) |_| {
        now += UdpSockmapPolicy.window_ms;
        try testing.expectEqual(UdpSockmapPolicy.Action.stay_off, policy.observeWindow(now, good));
    }
    try testing.expect(!policy.steerAllowed());

    // The full stable run arms: the engine is asked to load, and only then
    // does the policy allow steering.
    now += UdpSockmapPolicy.window_ms;
    try testing.expectEqual(UdpSockmapPolicy.Action.load, policy.observeWindow(now, good));
    try testing.expect(!policy.steerAllowed());
    policy.noteLoaded();
    try testing.expect(policy.steerAllowed());
}

test "udp sockmap policy: load failure lands in cooldown then re-probes" {
    var now: u64 = 1_000;
    var policy = UdpSockmapPolicy{};
    policy.reset(.auto);
    const good = qualifyingSample();
    for (0..UdpSockmapPolicy.probe_stable_windows) |_| {
        now += UdpSockmapPolicy.window_ms;
        _ = policy.observeWindow(now, good);
    }
    policy.noteLoadFailure(now);
    try testing.expect(!policy.steerAllowed());

    // The cooldown blocks further attempts until it elapses.
    now += UdpSockmapPolicy.window_ms;
    try testing.expectEqual(UdpSockmapPolicy.Action.stay_off, policy.observeWindow(now, good));
    now += UdpSockmapPolicy.fallback_cooldown_ms;
    try testing.expectEqual(UdpSockmapPolicy.Action.stay_off, policy.observeWindow(now, good));

    // Evidence re-arms after the cooldown.
    for (0..UdpSockmapPolicy.probe_stable_windows) |_| {
        now += UdpSockmapPolicy.window_ms;
        _ = policy.observeWindow(now, good);
    }
    now += UdpSockmapPolicy.window_ms;
    try testing.expectEqual(UdpSockmapPolicy.Action.load, policy.observeWindow(now, good));
}

test "udp sockmap policy: sustained pairing failures regress; success resets the streak" {
    var now: u64 = 1_000;
    var policy = UdpSockmapPolicy{};
    policy.reset(.auto);
    const good = qualifyingSample();
    for (0..UdpSockmapPolicy.probe_stable_windows) |_| {
        now += UdpSockmapPolicy.window_ms;
        _ = policy.observeWindow(now, good);
    }
    policy.noteLoaded();
    try testing.expect(policy.steerAllowed());

    // Below the threshold the controller tolerates failures...
    for (0..UdpSockmapPolicy.pairing_failure_threshold - 1) |_| policy.notePairingFailure(now);
    try testing.expect(policy.steerAllowed());
    // ...a success clears the streak...
    policy.notePairingSuccess();
    for (0..UdpSockmapPolicy.pairing_failure_threshold - 1) |_| policy.notePairingFailure(now);
    try testing.expect(policy.steerAllowed());
    // ...and crossing it regresses to a cooldown (safe fallback).
    policy.notePairingFailure(now);
    try testing.expect(!policy.steerAllowed());
}

test "udp sockmap policy: sustained userspace storm while active regresses with hysteresis" {
    var now: u64 = 1_000;
    var policy = UdpSockmapPolicy{};
    policy.reset(.auto);
    const good = qualifyingSample();
    for (0..UdpSockmapPolicy.probe_stable_windows) |_| {
        now += UdpSockmapPolicy.window_ms;
        _ = policy.observeWindow(now, good);
    }
    policy.noteLoaded();
    try testing.expect(policy.steerAllowed());

    const storm = UdpSockmapPolicy.WindowSample{
        .datagrams = UdpSockmapPolicy.active_storm_datagrams,
        .bytes = 0,
        .eligible = true,
    };
    // A single storm window is tolerated (hysteresis)...
    now += UdpSockmapPolicy.window_ms;
    try testing.expectEqual(UdpSockmapPolicy.Action.keep_active, policy.observeWindow(now, storm));
    try testing.expect(policy.steerAllowed());
    // ...a second consecutive one regresses.
    now += UdpSockmapPolicy.window_ms;
    try testing.expectEqual(UdpSockmapPolicy.Action.regress, policy.observeWindow(now, storm));
    try testing.expect(!policy.steerAllowed());
}

/// Never-started engine shell used to drive the adaptive policy end to end:
/// no I/O thread spawns and no listener resources are bound, so the policy
/// tick/load/regress plumbing is exercised deterministically. Allocated so the
/// engine's runtime/budget pointers stay valid for the harness lifetime.
const PolicyHarness = struct {
    engine: UdpRelayEngine,
    runtime: RuntimeConfiguration,
    budget: UdpAssociationBudget,
    logger: LogStore,
    fake: FakeSockmapRuntime,
    resolved_listen: []SocketAddr,

    fn init() !*PolicyHarness {
        const self = try testing.allocator.create(PolicyHarness);
        errdefer testing.allocator.destroy(self);
        const resolved = try makeUdpTestResolved(testing.allocator, 9);
        errdefer testing.allocator.free(resolved.listen_addresses);
        self.logger = LogStore.init("critical");
        self.resolved_listen = resolved.listen_addresses;
        self.fake = FakeSockmapRuntime{};
        self.budget = .{};
        self.runtime = RuntimeConfiguration.init(resolved);
        self.engine = UdpRelayEngine.init(
            &self.runtime,
            &self.logger,
            &self.budget,
            testing.allocator,
            1,
            0,
            null,
            FakeSockmapRuntime.loader,
            &self.fake,
            false,
            null,
        );
        return self;
    }

    fn deinit(self: *PolicyHarness) void {
        self.engine.destroy();
        self.fake.deinit();
        testing.allocator.free(self.resolved_listen);
        testing.allocator.destroy(self);
    }
};

/// Feeds `probe_stable_windows` qualifying evidence windows so the policy
/// arms and the engine loads the (fake) runtime. Used by the harness tests.
fn driveActivePolicy(engine: *UdpRelayEngine, now: *u64) void {
    for (0..UdpSockmapPolicy.probe_stable_windows - 1) |_| {
        engine.policy_recv_datagrams = UdpSockmapPolicy.min_datagrams_per_window;
        engine.policy_recv_bytes = UdpSockmapPolicy.min_datagrams_per_window * UdpSockmapPolicy.min_avg_datagram_bytes;
        now.* += UdpSockmapPolicy.window_ms;
        engine.handlePolicyTick(now.*);
    }
    engine.policy_recv_datagrams = UdpSockmapPolicy.min_datagrams_per_window;
    engine.policy_recv_bytes = UdpSockmapPolicy.min_datagrams_per_window * UdpSockmapPolicy.min_avg_datagram_bytes;
    now.* += UdpSockmapPolicy.window_ms;
    engine.handlePolicyTick(now.*);
}

test "udp steering gate: stale reload cannot clear a newer block" {
    var harness = try PolicyHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;

    const first_pending = engine.beginSteeringUpdate(true);
    try testing.expect(first_pending & UdpRelayEngine.steering_blocked_bit != 0);
    try testing.expect(first_pending & UdpRelayEngine.steering_publishing_bit != 0);
    engine.finishSteeringUpdate(first_pending);
    const first_ready = engine.steering_gate.load(.acquire);
    try testing.expect(first_ready & UdpRelayEngine.steering_blocked_bit != 0);
    try testing.expect(first_ready & UdpRelayEngine.steering_publishing_bit == 0);

    // A later blocking publication supersedes the generation an older reload
    // captured. Completing the older reload must not clear the newer block.
    const newer_pending = engine.beginSteeringUpdate(true);
    engine.finishSteeringUpdate(newer_pending);
    const newer_ready = engine.steering_gate.load(.acquire);
    try testing.expect(!engine.clearAppliedSteeringGate(first_ready));
    try testing.expectEqual(newer_ready, engine.steering_gate.load(.acquire));
    try testing.expect(newer_ready & UdpRelayEngine.steering_blocked_bit != 0);

    // An allowing update advances the generation but preserves an outstanding
    // block until that exact, fully-published generation has been applied.
    const allowing_pending = engine.beginSteeringUpdate(false);
    try testing.expect(allowing_pending & UdpRelayEngine.steering_blocked_bit != 0);
    try testing.expect(!engine.clearAppliedSteeringGate(allowing_pending));
    engine.finishSteeringUpdate(allowing_pending);
    const allowing_ready = engine.steering_gate.load(.acquire);
    try testing.expect(engine.clearAppliedSteeringGate(allowing_ready));
    try testing.expect(engine.steering_gate.load(.acquire) & UdpRelayEngine.steering_blocked_bit == 0);
}

test "udp auto policy: engine loads the runtime after stable evidence and tears it down on regression" {
    var harness = try PolicyHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;
    engine.sockmap_eligible = true; // non-loopback rule
    var now: u64 = 1_000;
    engine.policy.reset(.auto);
    engine.last_policy_tick_ms = now;

    // Auto starts on userspace: no runtime, no steering.
    try testing.expect(engine.sockmap_runtime == null);
    try testing.expect(!engine.policy.steerAllowed());

    // Idle (quiet) windows never arm.
    engine.policy_recv_datagrams = 0;
    engine.policy_recv_bytes = 0;
    for (0..UdpSockmapPolicy.probe_stable_windows) |_| {
        now += UdpSockmapPolicy.window_ms;
        engine.handlePolicyTick(now);
    }
    try testing.expect(engine.sockmap_runtime == null);

    // Sustained qualifying windows load the runtime exactly once.
    for (0..UdpSockmapPolicy.probe_stable_windows - 1) |_| {
        engine.policy_recv_datagrams = UdpSockmapPolicy.min_datagrams_per_window;
        engine.policy_recv_bytes = UdpSockmapPolicy.min_datagrams_per_window * UdpSockmapPolicy.min_avg_datagram_bytes;
        now += UdpSockmapPolicy.window_ms;
        engine.handlePolicyTick(now);
        try testing.expect(engine.sockmap_runtime == null);
    }
    engine.policy_recv_datagrams = UdpSockmapPolicy.min_datagrams_per_window;
    engine.policy_recv_bytes = UdpSockmapPolicy.min_datagrams_per_window * UdpSockmapPolicy.min_avg_datagram_bytes;
    now += UdpSockmapPolicy.window_ms;
    engine.handlePolicyTick(now);
    try testing.expect(engine.sockmap_runtime != null);
    try testing.expect(engine.policy.steerAllowed());
    try testing.expectEqual(@as(usize, 0), harness.fake.destroy_calls);

    // Sustained pairing failures tear the runtime down (safe fallback): the
    // policy stops allowing steering, so the engine drops the runtime.
    for (0..UdpSockmapPolicy.pairing_failure_threshold) |_| {
        engine.policy.notePairingFailure(now);
    }
    try testing.expect(!engine.policy.steerAllowed());
    engine.syncSockmapToPolicy();
    try testing.expect(engine.sockmap_runtime == null);
    try testing.expectEqual(@as(usize, 1), harness.fake.destroy_calls);
}

test "udp auto reload: unchanged eligible auto keeps the adaptive runtime active" {
    var harness = try PolicyHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;
    var now: u64 = 1_000;

    // Eligible auto rule: upstream_has_loopback=false overrides the loopback
    // upstream so the policy can arm, and reloadAccelerator's own eligibility
    // recomputation agrees.
    var eligible = engine.runtime.current();
    eligible.upstream_has_loopback = false;
    engine.runtime.update(eligible);
    engine.sockmap_eligible = true;
    engine.policy.reset(.auto);
    engine.last_policy_tick_ms = now;
    driveActivePolicy(engine, &now);
    try testing.expect(engine.sockmap_runtime != null);
    try testing.expect(engine.policy.steerAllowed());

    // A routine limits-only auto reload must not tear
    // acceleration down: the runtime and active policy are preserved.
    var updated = engine.runtime.current();
    updated.configuration.limits.max_udp_associations = 512;
    engine.runtime.update(updated);
    engine.reloadAccelerator();

    try testing.expect(engine.sockmap_runtime != null);
    try testing.expect(engine.policy.steerAllowed());
    try testing.expectEqual(@as(usize, 0), harness.fake.destroy_calls);
}

test "udp auto reload: becoming loopback tears down in unpair-before-destroy order and can re-probe" {
    var harness = try PolicyHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;
    var now: u64 = 1_000;

    var eligible = engine.runtime.current();
    eligible.upstream_has_loopback = false;
    engine.runtime.update(eligible);
    engine.sockmap_eligible = true;
    engine.policy.reset(.auto);
    engine.last_policy_tick_ms = now;
    driveActivePolicy(engine, &now);
    try testing.expect(engine.sockmap_runtime != null);

    // Insert a steered association so the teardown exercises unpair before
    // destroy. The budget is acquired once to keep release pairing correct.
    const client = SocketAddr.parseIp("127.0.0.1", 40_000).?;
    try testing.expect(engine.budget.tryAcquire(1_024));
    engine.associations.put(client, .{
        .client = client,
        .client_address = std.mem.zeroes(posix.sockaddr.storage),
        .client_address_length = @sizeOf(posix.sockaddr.in),
        .listen_fd = -1,
        .upstream_fd = -1,
        .upstream_addr = SocketAddr.parseIp("127.0.0.1", 9_001).?,
        .pairing = .{ .client_cookie = 1, .upstream_cookie = 2 },
        .last_activity_ms = now,
    }) catch unreachable;

    // Reload to a loopback auto rule: the runtime must be torn down with
    // unpair-before-destroy ordering and the controller reset to probing so it
    // can re-arm later instead of staying "active" with a null runtime.
    var loopback = engine.runtime.current();
    loopback.upstream_has_loopback = true;
    engine.runtime.update(loopback);
    engine.reloadAccelerator();

    try testing.expect(engine.sockmap_runtime == null);
    try testing.expect(!engine.policy.steerAllowed());
    try testing.expectEqual(@as(usize, 1), harness.fake.destroy_calls);
    var saw_unpair = false;
    var saw_destroy = false;
    for (harness.fake.events.items) |event| {
        if (saw_destroy) try testing.expect(event != .unpair);
        if (event == .unpair) saw_unpair = true;
        if (event == .destroy) saw_destroy = true;
    }
    try testing.expect(saw_unpair);
    try testing.expect(saw_destroy);

    // Once eligible again, the controller re-probes and reloads the runtime.
    var eligible_again = engine.runtime.current();
    eligible_again.upstream_has_loopback = false;
    engine.runtime.update(eligible_again);
    engine.sockmap_eligible = true;
    engine.last_policy_tick_ms = now;
    driveActivePolicy(engine, &now);
    try testing.expect(engine.sockmap_runtime != null);
    try testing.expect(engine.policy.steerAllowed());
}

test "udp enabled to auto reload stops new sockmap associations and tears down in order" {
    var echo = try UdpEchoServer.start();
    defer echo.stop();

    var fake = FakeSockmapRuntime{};
    defer fake.deinit();

    var logger = LogStore.init("critical");
    var resolved = try makeUdpTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);
    resolved.configuration.performance.udp_sockmap_acceleration = .enabled;

    var listener = UdpListener.initWithSelector(testing.allocator, resolved, &logger, null, FakeSockmapRuntime.loader, null);
    listener.loader_context = &fake;
    defer listener.deinit();
    try listener.start();

    const bound = try listener.localAddresses(testing.allocator);
    defer testing.allocator.free(bound);
    const port = bound[0].port;

    // Client A establishes and is steered under enabled.
    const client_a = try udpClient();
    defer closeFd(client_a);
    try testing.expect(try waitForEcho(client_a, port, "hello-a", 2_000));
    try testing.expectEqual(@as(usize, 1), fake.pair_calls);

    // Reload to auto: the snapshot now disallows sockmap and updateConfiguration
    // synchronously blocks new steering before the async teardown command runs.
    var auto_resolved = resolved;
    auto_resolved.configuration.performance.udp_sockmap_acceleration = .auto;
    listener.updateConfiguration(auto_resolved, false);

    // Client B establishes during the pending teardown window and must NOT
    // enter sockmap, whether or not the reload command has processed: the
    // synchronous guard and the reset policy both refuse to steer.
    const client_b = try udpClient();
    defer closeFd(client_b);
    try testing.expect(try waitForEcho(client_b, port, "hello-b", 2_000));
    try testing.expectEqual(@as(usize, 1), fake.pair_calls);

    // The reload command tears the runtime down.
    const torn_down = struct {
        var fake_ptr: *FakeSockmapRuntime = undefined;
        fn check() bool {
            return fake_ptr.destroy_calls >= 1;
        }
    };
    torn_down.fake_ptr = &fake;
    try testing.expect(waitForCondition(torn_down.check, 2_000));

    // Teardown ordering: every unpair happened before the destroy event.
    var saw_destroy = false;
    for (fake.events.items) |event| {
        if (saw_destroy) try testing.expect(event != .unpair);
        if (event == .destroy) saw_destroy = true;
    }
    try testing.expect(saw_destroy);
}

test "udp mode-unchanged reloads keep steering (enabled stays enabled)" {
    var echo = try UdpEchoServer.start();
    defer echo.stop();

    var fake = FakeSockmapRuntime{};
    defer fake.deinit();

    var logger = LogStore.init("critical");
    var resolved = try makeUdpTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);
    resolved.configuration.performance.udp_sockmap_acceleration = .enabled;

    var listener = UdpListener.initWithSelector(testing.allocator, resolved, &logger, null, FakeSockmapRuntime.loader, null);
    listener.loader_context = &fake;
    defer listener.deinit();
    try listener.start();

    const bound = try listener.localAddresses(testing.allocator);
    defer testing.allocator.free(bound);
    const port = bound[0].port;

    const client_a = try udpClient();
    defer closeFd(client_a);
    try testing.expect(try waitForEcho(client_a, port, "hello-a", 2_000));
    try testing.expectEqual(@as(usize, 1), fake.pair_calls);

    // A limits-only reload keeps the mode; steering must not be interrupted.
    var same_mode = resolved;
    same_mode.configuration.limits.max_udp_associations = 512;
    listener.updateConfiguration(same_mode, false);

    const client_b = try udpClient();
    defer closeFd(client_b);
    try testing.expect(try waitForEcho(client_b, port, "hello-b", 2_000));
    try testing.expectEqual(@as(usize, 2), fake.pair_calls);
    try testing.expectEqual(@as(usize, 0), fake.destroy_calls);
}

/// Loader failures caused by missing privileges are graceful skips in the
/// default suite but must fail loudly under the dedicated `zig build test-ebpf`
/// step (which sets CURTSY_REQUIRE_EBPF_TESTS): silently passing there without
/// CAP_BPF/CAP_NET_ADMIN would hide a broken privileged environment.
fn ebpfLoaderUnavailable(err: anyerror) bool {
    if (std.c.getenv("CURTSY_REQUIRE_EBPF_TESTS") != null) return false;
    return switch (err) {
        error.PermissionDenied, error.AccessDenied, error.NotSupported, error.NoMemory => true,
        else => false,
    };
}

test "udp sockmap end-to-end with real BPF (gated: CURTSY_ENABLE_EBPF_TESTS)" {
    // Privileged integration test: a real UdpListener loads the actual UDP
    // sockmap runtime (verdict program + sockhash) and relays a real client
    // to a real echo server while steering is active, then tears the runtime
    // down cleanly on an enabled -> auto reload. Run as root (or with
    // CAP_BPF/CAP_NET_ADMIN): `sudo zig build test-ebpf`. Unprivileged runs
    // of the default suite skip gracefully; the dedicated test-ebpf step
    // fails loudly instead when privileges are missing.
    if (std.c.getenv("CURTSY_ENABLE_EBPF_TESTS") == null) return;

    // Probe privileges first so a missing gate capability is an explicit skip
    // in the default suite, and a hard failure under test-ebpf.
    var probe_log: [4096]u8 = undefined;
    var probe = default_sockmap_runtime_loader(null, testing.allocator, 1024, &probe_log) catch |err| {
        if (ebpfLoaderUnavailable(err)) return;
        return err;
    };
    probe.destroy();

    var echo = try UdpEchoServer.start();
    defer echo.stop();

    var logger = LogStore.init("critical");
    var resolved = try makeUdpTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);
    resolved.configuration.performance.udp_sockmap_acceleration = .enabled;

    var listener = UdpListener.initWithSelector(testing.allocator, resolved, &logger, null, null, null);
    defer listener.deinit();
    try listener.start();

    const bound = try listener.localAddresses(testing.allocator);
    defer testing.allocator.free(bound);
    const port = bound[0].port;

    // Real client -> relay -> echo while the verdict program steers.
    const client = try udpClient();
    defer closeFd(client);
    try testing.expect(try waitForEcho(client, port, "bpf-e2e", 2_000));
    try testing.expectEqual(@as(u64, 1), listener.budget.count());

    // enabled -> auto reload must tear the runtime down and keep relaying
    // through the userspace path without crashing.
    var auto_resolved = resolved;
    auto_resolved.configuration.performance.udp_sockmap_acceleration = .auto;
    listener.updateConfiguration(auto_resolved, false);
    try testing.expect(try waitForEcho(client, port, "bpf-e2e-after", 2_000));

    const settled = struct {
        var listener_ptr: *UdpListener = undefined;
        fn check() bool {
            return listener_ptr.budget.count() <= 1;
        }
    };
    settled.listener_ptr = &listener;
    try testing.expect(waitForCondition(settled.check, 2_000));
}

// ---------------------------------------------------------------------------
// Data-path counter tests
// ---------------------------------------------------------------------------

test "udp engine counters snapshot reset delta and batch fill" {
    var harness = try DrainHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;

    // Initial snapshot is all zeros.
    var snap = engine.countersSnapshot();
    try testing.expectEqual(@as(u64, 0), snap.recv_calls);
    try testing.expectEqual(@as(u64, 0), snap.recv_datagrams);
    try testing.expectEqual(@as(u64, 0), snap.recv_bytes);
    try testing.expectEqual(@as(u64, 0), snap.send_calls);
    try testing.expectEqual(@as(u64, 0), snap.send_datagrams);
    try testing.expectEqual(@as(u64, 0), snap.send_bytes);
    try testing.expectEqual(@as(u64, 0), snap.send_error_drops);
    try testing.expectEqual(@as(u64, 0), snap.sockmap_pair_attempts);
    try testing.expectEqual(@as(u64, 0), snap.sockmap_pair_successes);
    try testing.expectEqual(@as(u64, 0), snap.sockmap_pair_failures);
    try testing.expectEqual(@as(u64, 0), snap.sockmap_pass_datagrams);
    try testing.expectEqual(@as(u64, 0), snap.sockmap_pass_bytes);
    try testing.expectEqual(@as(u64, 0), snap.recvAvgBatchFill());
    try testing.expectEqual(@as(u64, 0), snap.sendAvgBatchFill());

    // A scripted drain of two datagrams (one byte each) counts calls,
    // datagrams and bytes, plus the terminating EAGAIN syscall.
    const recv_slots = &harness.recv_slots;
    var script = ScriptedRecvIo{ .results = &.{
        .{ .datagrams = 2 },
        .{ .datagrams = 0 },
    } };
    _ = engine.drainRecvBatch(-1, recv_slots, &script, UdpRelayEngine.max_batches_per_drain, false);

    snap = engine.countersSnapshot();
    try testing.expectEqual(@as(u64, 2), snap.recv_calls);
    try testing.expectEqual(@as(u64, 2), snap.recv_datagrams);
    try testing.expectEqual(@as(u64, 2), snap.recv_bytes); // 1 byte per scripted slot
    try testing.expectEqual(@as(u64, 1), snap.recvAvgBatchFill());
    // Upstream responses (count_policy=false) never feed the policy totals.
    try testing.expectEqual(@as(u64, 0), engine.policy_recv_datagrams);

    // delta reports only the growth since the previous snapshot.
    const before = engine.countersSnapshot();
    _ = engine.counters.recv_datagrams.fetchAdd(10, .monotonic);
    const after = engine.countersSnapshot();
    const d = bpf.counters.delta(UdpDataPathCounters, after, before);
    try testing.expectEqual(@as(u64, 10), d.recv_datagrams);
    try testing.expectEqual(@as(u64, 0), d.recv_calls);
    try testing.expectEqual(@as(u64, 0), d.recv_bytes);

    // reset zeroes every field in place.
    engine.counters.reset();
    const reset_snap = engine.countersSnapshot();
    try testing.expectEqual(@as(u64, 0), reset_snap.recv_calls);
    try testing.expectEqual(@as(u64, 0), reset_snap.recv_datagrams);
    try testing.expectEqual(@as(u64, 0), reset_snap.recv_bytes);
    try testing.expectEqual(@as(u64, 0), reset_snap.recvAvgBatchFill());
}

test "udp logBatchStats diffs cumulative counters without resetting them" {
    var harness = try DrainHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;

    // The exported counters stay cumulative across stats ticks; logBatchStats
    // derives its per-interval deltas from successive snapshots instead.
    _ = engine.counters.recv_calls.fetchAdd(10, .monotonic);
    _ = engine.counters.recv_datagrams.fetchAdd(30, .monotonic);

    // First tick establishes the baseline; nothing is reset or logged.
    engine.logBatchStats();
    try testing.expectEqual(@as(u64, 10), engine.counters.snapshot().recv_calls);
    try testing.expectEqual(@as(u64, 30), engine.counters.snapshot().recv_datagrams);

    // Second tick consumes the delta; the cumulative totals remain intact.
    _ = engine.counters.recv_calls.fetchAdd(5, .monotonic);
    _ = engine.counters.recv_datagrams.fetchAdd(15, .monotonic);
    engine.logBatchStats();
    try testing.expectEqual(@as(u64, 15), engine.counters.snapshot().recv_calls);
    try testing.expectEqual(@as(u64, 45), engine.counters.snapshot().recv_datagrams);
}

test "udp gso fast path forwards uniform batches and falls back on mixed sizes" {
    // Plain bound loopback receiver the engine forwards into.
    var addr = linux.sockaddr.in{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const recv_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    try testing.expect(linux.errno(recv_rc) == .SUCCESS);
    const recv_fd: fd_t = @intCast(recv_rc);
    defer closeFd(recv_fd);
    try testing.expect(linux.errno(linux.bind(recv_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in))) == .SUCCESS);
    var bound = linux.sockaddr.in{ .port = 0, .addr = 0 };
    var bound_len: socklen_t = @sizeOf(linux.sockaddr.in);
    try testing.expect(linux.errno(linux.getsockname(recv_fd, @ptrCast(&bound), &bound_len)) == .SUCCESS);

    var harness = try DrainHarness.init();
    defer harness.deinit();
    const engine = &harness.engine;
    engine.send_io = bpf.UdpSendBatchIo{};

    var upstream_addr = linux.sockaddr.in{
        .port = bound.port,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const upstream_fd = try bpf.udpUpstreamSocket(@ptrCast(&upstream_addr), @sizeOf(linux.sockaddr.in));
    defer closeFd(upstream_fd);

    // Uniform batch: the GSO fast path applies (connected socket, one size).
    var uniform: [5][100]u8 = undefined;
    var uniform_slots: [5]bpf.UdpSlot = undefined;
    for (&uniform, 0..) |*payload, i| {
        @memset(payload, @intCast(i + 1));
        uniform_slots[i] = .{ .data = &payload.*, .length = payload.len };
    }
    try testing.expect(engine.sendAllDatagrams(upstream_fd, null, 0, &uniform_slots, "direction=client_to_upstream", 0));

    // The receiver observes 5 datagrams of exactly 100 bytes in send order.
    var recv_buf: [5][128]u8 = undefined;
    var recv_slots: [5]bpf.UdpSlot = undefined;
    for (&recv_buf, 0..) |*region, i| recv_slots[i] = .{ .data = &region.*, .capacity = region.len };
    var received: usize = 0;
    for (0..200) |_| {
        received += try bpf.udpRecvBatch(recv_fd, recv_slots[received..]);
        if (received == 5) break;
        const delay = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&delay, null);
    }
    try testing.expectEqual(@as(usize, 5), received);
    for (recv_slots, 0..) |slot, i| {
        try testing.expectEqual(@as(u32, 100), slot.length);
        for (recv_buf[i][0..100]) |byte| try testing.expectEqual(@as(u8, @intCast(i + 1)), byte);
    }
    // 100*5 = 500 bytes fits one GSO send; the counters reflect a single call.
    try testing.expectEqual(@as(u64, 1), engine.countersSnapshot().send_calls);
    try testing.expectEqual(@as(u64, 5), engine.countersSnapshot().send_datagrams);
    try testing.expectEqual(@as(u64, 500), engine.countersSnapshot().send_bytes);

    // Mixed sizes disable the fast path; the ordinary sendmmsg must carry all
    // datagrams with their exact boundaries intact.
    var mixed_one = "aaa".*;
    var mixed_two = "bbbbbb".*;
    var mixed_three = "cccccccccc".*;
    var mixed_slots = [_]bpf.UdpSlot{
        .{ .data = &mixed_one, .length = mixed_one.len },
        .{ .data = &mixed_two, .length = mixed_two.len },
        .{ .data = &mixed_three, .length = mixed_three.len },
    };
    try testing.expect(engine.sendAllDatagrams(upstream_fd, null, 0, &mixed_slots, "direction=client_to_upstream", 0));

    var mixed_buf: [3][16]u8 = undefined;
    var mixed_recv: [3]bpf.UdpSlot = undefined;
    for (&mixed_buf, 0..) |*region, i| mixed_recv[i] = .{ .data = &region.*, .capacity = region.len };
    var mixed_received: usize = 0;
    for (0..200) |_| {
        mixed_received += try bpf.udpRecvBatch(recv_fd, mixed_recv[mixed_received..]);
        if (mixed_received == 3) break;
        const delay = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&delay, null);
    }
    try testing.expectEqual(@as(usize, 3), mixed_received);
    try testing.expectEqualStrings("aaa", mixed_buf[0][0..mixed_recv[0].length]);
    try testing.expectEqualStrings("bbbbbb", mixed_buf[1][0..mixed_recv[1].length]);
    try testing.expectEqualStrings("cccccccccc", mixed_buf[2][0..mixed_recv[2].length]);
    // One sendmmsg call for the mixed batch, not a GSO send.
    try testing.expectEqual(@as(u64, 2), engine.countersSnapshot().send_calls);
    try testing.expectEqual(@as(u64, 8), engine.countersSnapshot().send_datagrams);

    // A non-null destination (the upstream-to-client reverse direction) never
    // takes the GSO path even for a uniform batch: the shared listen socket
    // cannot carry a per-association segment size.
    const reverse_bind = linux.sockaddr.in{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    const reverse_fd = try bpf.udpListenSocket(@ptrCast(&reverse_bind), @sizeOf(linux.sockaddr.in), null);
    defer closeFd(reverse_fd);
    const reverse_dest = linux.sockaddr.in{
        .port = bound.port,
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
    var reverse_slots = [_]bpf.UdpSlot{
        .{ .data = &uniform[0], .length = uniform[0].len },
        .{ .data = &uniform[1], .length = uniform[1].len },
    };
    try testing.expect(engine.sendAllDatagrams(reverse_fd, @ptrCast(&reverse_dest), @sizeOf(linux.sockaddr.in), &reverse_slots, "direction=upstream_to_client", 0));
    // sendmmsg (one call) carried the reverse batch, so the call count went up
    // by exactly one while the datagram count grew by two.
    try testing.expectEqual(@as(u64, 3), engine.countersSnapshot().send_calls);
    try testing.expectEqual(@as(u64, 10), engine.countersSnapshot().send_datagrams);
}

test "udp listener counters snapshot is all zeros before start" {
    var logger = LogStore.init("critical");
    const resolved = try makeUdpTestResolved(testing.allocator, 9);
    defer testing.allocator.free(resolved.listen_addresses);

    var listener = UdpListener.init(testing.allocator, resolved, &logger, false, null);
    defer listener.deinit();

    const snapshot = listener.countersSnapshot();
    try testing.expectEqual(@as(u64, 0), snapshot.recv_calls);
    try testing.expectEqual(@as(u64, 0), snapshot.recv_datagrams);
    try testing.expectEqual(@as(u64, 0), snapshot.recv_bytes);
    try testing.expectEqual(@as(u64, 0), snapshot.send_datagrams);
    try testing.expectEqual(@as(u64, 0), snapshot.sockmap_pair_attempts);
    try testing.expectEqual(@as(u64, 0), snapshot.sockmap_pass_datagrams);
}

test "udp counters track userspace batches and sockmap steering with a fake runtime" {
    var echo = try UdpEchoServer.start();
    defer echo.stop();

    var fake = FakeSockmapRuntime{};
    defer fake.deinit();

    var logger = LogStore.init("critical");
    var resolved = try makeUdpTestResolved(testing.allocator, echo.port);
    defer testing.allocator.free(resolved.listen_addresses);
    resolved.configuration.performance.udp_sockmap_acceleration = .enabled;

    var listener = UdpListener.initWithSelector(testing.allocator, resolved, &logger, null, FakeSockmapRuntime.loader, null);
    listener.loader_context = &fake;
    defer listener.deinit();
    try listener.start();

    const bound = try listener.localAddresses(testing.allocator);
    defer testing.allocator.free(bound);
    const port = bound[0].port;

    const client = try udpClient();
    defer closeFd(client);

    // First round trip establishes the association and steers it through the
    // (fake) sockmap runtime.
    try testing.expect(try waitForEcho(client, port, "first-probe", 2_000));
    // A second datagram now lands on the connected accelerated client socket;
    // the fake kernel never redirects, so userspace relays it (SK_PASS path).
    try testing.expect(try waitForEcho(client, port, "second-probe", 2_000));

    const snapshot = listener.countersSnapshot();
    // Exactly one association was established and steered.
    try testing.expectEqual(@as(u64, 1), snapshot.sockmap_pair_attempts);
    try testing.expectEqual(@as(u64, 1), snapshot.sockmap_pair_successes);
    try testing.expectEqual(@as(u64, 0), snapshot.sockmap_pair_failures);
    // The client-side datagrams hit the accelerated fallback socket.
    try testing.expect(snapshot.sockmap_pass_datagrams >= 1);
    try testing.expect(snapshot.sockmap_pass_bytes >= 1);
    // The relay performed real userspace recv/send work with batch fill.
    try testing.expect(snapshot.recv_datagrams >= 1);
    try testing.expect(snapshot.recv_bytes >= 1);
    try testing.expect(snapshot.send_datagrams >= 1);
    try testing.expect(snapshot.send_bytes >= 1);
    try testing.expect(snapshot.sendAvgBatchFill() <= UdpRelayEngine.batch_size);
}
