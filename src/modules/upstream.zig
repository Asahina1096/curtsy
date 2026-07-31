//! upstream module: the ngx_upstream framework analogue.
//!
//! Owns the upstream pool (peer states: passive failure eviction with
//! exponential backoff), the Selector hook injected into the data planes
//! (peer.get/free/notify analogue) and the balancer registry. Selection
//! strategies are pluggable balancer modules (round_robin, source_hash,
//! weighted_round_robin) chosen by name through the `balance` directive;
//! the pool itself only tracks eligibility and generations.
//!
//! A pool is a stable per-rule object whose address is captured by the
//! TCP/UDP selector hooks; configuration reloads swap the internal
//! generation under a mutex (inheriting health state by address) so the
//! selector context never changes. A single-entry pool degrades to a
//! constant pick with no bookkeeping.
//!
//! Eviction is passive: consecutive failures at or above `failure_threshold`
//! park an upstream for a cooldown that backs off exponentially on repeated
//! evictions. There is no probing; after the cooldown the upstream becomes
//! eligible again and real traffic decides.

const std = @import("std");
const log = @import("../log.zig");
const net = @import("../net.zig");

const round_robin = @import("balancer/round_robin.zig");
const source_hash = @import("balancer/source_hash.zig");
const weighted_round_robin = @import("balancer/weighted_round_robin.zig");

const Allocator = std.mem.Allocator;

pub const failure_threshold: u32 = 3;
pub const base_evict_ns: u64 = 10 * std.time.ns_per_s;
pub const max_evict_ns: u64 = 5 * std.time.ns_per_min;
const max_backoff_shift: u6 = 5;

// ---------------------------------------------------------------------------
// Balancer: pluggable selection strategy (ngx upstream balancer modules)
// ---------------------------------------------------------------------------

pub const UpstreamState = struct {
    address: net.SocketAddr,
    consecutive_failures: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Monotonic timestamp until which the upstream is parked; 0 = eligible.
    evicted_until_ns: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    eviction_streak: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn eligible(self: *const UpstreamState, now_ns: u64) bool {
        const until = self.evicted_until_ns.load(.monotonic);
        return until == 0 or until <= now_ns;
    }
};

pub const Balancer = struct {
    name: []const u8,
    /// Build per-generation strategy state (e.g. an expanded pick sequence).
    /// Stateless strategies return null.
    build: *const fn (allocator: Allocator, addresses: []const net.SocketAddr, weights: []const u32) error{OutOfMemory}!?*anyopaque,
    destroy: *const fn (allocator: Allocator, state: ?*anyopaque) void,
    /// Choose an upstream index. Sequential strategies rotate through the
    /// shared `cursor`; all strategies skip ineligible upstreams and fall
    /// back to serving anyway when everything is evicted.
    pick: *const fn (state: ?*anyopaque, upstreams: []const UpstreamState, cursor: *std.atomic.Value(u32), client: ?net.SocketAddr, now_ns: u64) usize,
};

/// The registered balancer modules, in directive-display order.
pub const balancers: []const Balancer = &.{ round_robin.balancer, source_hash.balancer, weighted_round_robin.balancer };

pub fn balancerByName(name: []const u8) ?*const Balancer {
    for (balancers) |*balancer| {
        if (std.mem.eql(u8, balancer.name, name)) return balancer;
    }
    return null;
}

pub fn defaultBalancer() *const Balancer {
    return &balancers[0];
}

/// "round_robin, source_hash, weighted_round_robin" (for diagnostics).
pub fn balancerNames(buf: []u8) []const u8 {
    var fbs = std.Io.Writer.fixed(buf);
    for (balancers, 0..) |balancer, i| {
        if (i > 0) fbs.print(", ", .{}) catch return buf[0..fbs.end];
        fbs.print("{s}", .{balancer.name}) catch return buf[0..fbs.end];
    }
    return buf[0..fbs.end];
}

// ---------------------------------------------------------------------------
// Selector: the hook injected into the TCP/UDP data planes
// ---------------------------------------------------------------------------

/// When set, each new connection/association asks the selector for its
/// upstream address instead of using the configured one, immediate connect
/// failures fail over to the next pick, and outcomes are reported back for
/// passive health tracking. When null the listener behaves exactly as a
/// single-upstream forwarder.
pub const Selector = struct {
    context: *anyopaque,
    pick_fn: *const fn (context: *anyopaque, client: ?net.SocketAddr, now_ns: u64) net.SocketAddr,
    report_success_fn: *const fn (context: *anyopaque, upstream: net.SocketAddr) void,
    report_failure_fn: *const fn (context: *anyopaque, upstream: net.SocketAddr, now_ns: u64) void,

    pub fn pick(self: Selector, client: ?net.SocketAddr, now_ns: u64) net.SocketAddr {
        return self.pick_fn(self.context, client, now_ns);
    }

    pub fn reportSuccess(self: Selector, upstream: net.SocketAddr) void {
        self.report_success_fn(self.context, upstream);
    }

    pub fn reportFailure(self: Selector, upstream: net.SocketAddr, now_ns: u64) void {
        self.report_failure_fn(self.context, upstream, now_ns);
    }
};

fn poolPick(context: *anyopaque, client: ?net.SocketAddr, now_ns: u64) net.SocketAddr {
    const pool: *UpstreamPool = @ptrCast(@alignCast(context));
    return pool.pick(client, now_ns);
}

fn poolReportSuccess(context: *anyopaque, upstream_addr: net.SocketAddr) void {
    const pool: *UpstreamPool = @ptrCast(@alignCast(context));
    pool.reportSuccess(upstream_addr);
}

fn poolReportFailure(context: *anyopaque, upstream_addr: net.SocketAddr, now_ns: u64) void {
    const pool: *UpstreamPool = @ptrCast(@alignCast(context));
    pool.reportFailure(upstream_addr, now_ns);
}

/// Adapt a pool to the selector hook shape consumed by the data planes.
pub fn poolSelector(pool: *UpstreamPool) Selector {
    return .{
        .context = pool,
        .pick_fn = poolPick,
        .report_success_fn = poolReportSuccess,
        .report_failure_fn = poolReportFailure,
    };
}

// ---------------------------------------------------------------------------
// UpstreamPool: peer states and generation swapping
// ---------------------------------------------------------------------------

const Generation = struct {
    upstreams: []UpstreamState,
    /// Strategy state built by the balancer module (e.g. pick sequence).
    strategy: ?*anyopaque,

    fn indexOf(self: *const Generation, address: net.SocketAddr) ?usize {
        for (self.upstreams, 0..) |*upstream, i| {
            if (upstream.address.eql(address)) return i;
        }
        return null;
    }
};

pub const UpstreamPool = struct {
    allocator: Allocator,
    balancer: *const Balancer,
    /// Guards generation/retired; critical sections are per-connection
    /// picks and failure reports, never per-packet work.
    mutex: log.Mutex = .{},
    generation: *Generation,
    /// Previous generation, retired one swap late; any reader of it finished
    /// its critical section before the swap that replaced it completed.
    retired: ?*Generation = null,
    cursor: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// `addresses` and `weights` must have the same length and at least one
    /// entry. The pool copies both.
    pub fn init(
        allocator: Allocator,
        addresses: []const net.SocketAddr,
        weights: []const u32,
        balancer: *const Balancer,
    ) error{OutOfMemory}!UpstreamPool {
        const generation = try buildGeneration(allocator, addresses, weights, balancer, null);
        errdefer destroyGeneration(allocator, balancer, generation);
        return .{
            .allocator = allocator,
            .balancer = balancer,
            .generation = generation,
        };
    }

    pub fn deinit(self: *UpstreamPool) void {
        destroyGeneration(self.allocator, self.balancer, self.generation);
        if (self.retired) |retired| destroyGeneration(self.allocator, self.balancer, retired);
    }

    /// Number of upstreams in the current generation.
    pub fn count(self: *UpstreamPool) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.generation.upstreams.len;
    }

    /// Choose an upstream address. Single-upstream pools return immediately
    /// without touching any counters. Evicted upstreams are skipped; when all
    /// are evicted the eviction state is ignored rather than refusing traffic.
    pub fn pick(self: *UpstreamPool, client: ?net.SocketAddr, now_ns: u64) net.SocketAddr {
        self.mutex.lock();
        defer self.mutex.unlock();
        const generation = self.generation;
        if (generation.upstreams.len == 1) return generation.upstreams[0].address;
        const index = self.balancer.pick(generation.strategy, generation.upstreams, &self.cursor, client, now_ns);
        return generation.upstreams[index].address;
    }

    /// Record a successful exchange with an upstream: clears its failure
    /// count and eviction backoff.
    pub fn reportSuccess(self: *UpstreamPool, address: net.SocketAddr) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const index = self.generation.indexOf(address) orelse return;
        const upstream = &self.generation.upstreams[index];
        upstream.consecutive_failures.store(0, .monotonic);
        upstream.eviction_streak.store(0, .monotonic);
    }

    /// Record a failure; at `failure_threshold` consecutive failures the
    /// upstream is parked with exponential backoff. A single-upstream pool
    /// ignores reports (there is nowhere else to go).
    pub fn reportFailure(self: *UpstreamPool, address: net.SocketAddr, now_ns: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const generation = self.generation;
        if (generation.upstreams.len == 1) return;
        const index = generation.indexOf(address) orelse return;
        const upstream = &generation.upstreams[index];

        const failures = upstream.consecutive_failures.fetchAdd(1, .monotonic) + 1;
        if (failures < failure_threshold) return;

        upstream.consecutive_failures.store(0, .monotonic);
        const streak = upstream.eviction_streak.fetchAdd(1, .monotonic) + 1;
        const shift: u6 = @intCast(@min(streak - 1, max_backoff_shift));
        const backoff = @min(base_evict_ns << shift, max_evict_ns);
        const until = now_ns + backoff;
        // Never shorten an active eviction when failures race.
        const current = upstream.evicted_until_ns.load(.monotonic);
        upstream.evicted_until_ns.store(@max(current, until), .monotonic);
    }

    /// Swap the upstream set (configuration reload). Health state is carried
    /// over for addresses present in both generations. The pool object itself
    /// stays put, so selector contexts captured by listeners remain valid.
    pub fn rebind(
        self: *UpstreamPool,
        addresses: []const net.SocketAddr,
        weights: []const u32,
    ) error{OutOfMemory}!void {
        const replacement = try buildGeneration(self.allocator, addresses, weights, self.balancer, self.generation);
        self.mutex.lock();
        const old = self.generation;
        self.generation = replacement;
        if (self.retired) |retired| destroyGeneration(self.allocator, self.balancer, retired);
        self.retired = old;
        self.mutex.unlock();
    }

    /// Snapshot of the current upstream addresses (used to detect upstream
    /// set changes across reloads). Caller owns the returned slice.
    pub fn currentAddresses(self: *UpstreamPool, allocator: Allocator) error{OutOfMemory}![]net.SocketAddr {
        self.mutex.lock();
        defer self.mutex.unlock();
        const generation = self.generation;
        const addresses = try allocator.alloc(net.SocketAddr, generation.upstreams.len);
        for (generation.upstreams, 0..) |*upstream, i| addresses[i] = upstream.address;
        return addresses;
    }
};

/// Shared walk for sequential balancers (round robin and weighted round
/// robin): rotate through the strategy sequence from the shared cursor,
/// skipping evicted upstreams, serving the first entry when all are parked.
pub fn pickSequential(sequence: []const u32, upstreams: []const UpstreamState, cursor: *std.atomic.Value(u32), now_ns: u64) usize {
    const start = cursor.fetchAdd(1, .monotonic) % @as(u32, @intCast(sequence.len));
    var first: ?usize = null;
    var step: u32 = 0;
    while (step < sequence.len) : (step += 1) {
        const index = sequence[(start + step) % @as(u32, @intCast(sequence.len))];
        if (first == null) first = index;
        if (upstreams[index].eligible(now_ns)) return index;
    }
    return first.?;
}

fn buildGeneration(
    allocator: Allocator,
    addresses: []const net.SocketAddr,
    weights: []const u32,
    balancer: *const Balancer,
    previous: ?*const Generation,
) error{OutOfMemory}!*Generation {
    const upstreams = try allocator.alloc(UpstreamState, addresses.len);
    errdefer allocator.free(upstreams);
    for (addresses, 0..) |address, i| {
        upstreams[i] = .{ .address = address };
        if (previous) |old| {
            if (old.indexOf(address)) |old_index| {
                const state = &old.upstreams[old_index];
                upstreams[i].consecutive_failures.store(state.consecutive_failures.load(.monotonic), .monotonic);
                upstreams[i].evicted_until_ns.store(state.evicted_until_ns.load(.monotonic), .monotonic);
                upstreams[i].eviction_streak.store(state.eviction_streak.load(.monotonic), .monotonic);
            }
        }
    }

    const strategy = try balancer.build(allocator, addresses, weights);
    errdefer balancer.destroy(allocator, strategy);

    const generation = try allocator.create(Generation);
    generation.* = .{ .upstreams = upstreams, .strategy = strategy };
    return generation;
}

fn destroyGeneration(allocator: Allocator, balancer: *const Balancer, generation: *Generation) void {
    balancer.destroy(allocator, generation.strategy);
    allocator.free(generation.upstreams);
    allocator.destroy(generation);
}

pub fn monotonicNowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testAddresses(count: usize) [4]net.SocketAddr {
    var addresses: [4]net.SocketAddr = undefined;
    for (0..count) |i| {
        addresses[i] = net.SocketAddr.parseIp("127.0.0.1", @intCast(9000 + i)).?;
    }
    return addresses;
}

test "single upstream pool is a constant pick" {
    const addresses = testAddresses(1);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..1], &.{1}, defaultBalancer());
    defer pool.deinit();

    const picked = pool.pick(null, 0);
    try testing.expect(picked.eql(addresses[0]));

    // Failure reports are no-ops for single-upstream pools.
    pool.reportFailure(addresses[0], 0);
    pool.reportFailure(addresses[0], 0);
    pool.reportFailure(addresses[0], 0);
    try testing.expect(pool.pick(null, 0).eql(addresses[0]));
}

test "round robin rotates across upstreams" {
    const addresses = testAddresses(3);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..3], &.{ 1, 1, 1 }, defaultBalancer());
    defer pool.deinit();

    try testing.expect(pool.pick(null, 0).eql(addresses[0]));
    try testing.expect(pool.pick(null, 0).eql(addresses[1]));
    try testing.expect(pool.pick(null, 0).eql(addresses[2]));
    try testing.expect(pool.pick(null, 0).eql(addresses[0]));
}

test "round robin skips evicted upstreams and recovers after cooldown" {
    const addresses = testAddresses(2);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, defaultBalancer());
    defer pool.deinit();

    var now: u64 = 1_000;
    pool.reportFailure(addresses[0], now);
    pool.reportFailure(addresses[0], now);
    pool.reportFailure(addresses[0], now);

    // Parked: a burst of picks never touches upstream 0.
    for (0..6) |_| {
        try testing.expect(pool.pick(null, now).eql(addresses[1]));
    }

    // Past the cooldown upstream 0 is eligible and rotates back in.
    now += base_evict_ns + 1;
    var saw_first = false;
    for (0..4) |_| {
        if (pool.pick(null, now).eql(addresses[0])) saw_first = true;
    }
    try testing.expect(saw_first);
}

test "eviction backs off exponentially on repeated failures" {
    const addresses = testAddresses(2);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, defaultBalancer());
    defer pool.deinit();

    var now: u64 = 1_000;
    for (0..failure_threshold) |_| pool.reportFailure(addresses[0], now);

    // Recover after the base cooldown, then fail it again immediately.
    now += base_evict_ns + 1;
    for (0..failure_threshold) |_| pool.reportFailure(addresses[0], now);

    // Second eviction: 2 * base cooldown, so one base later it is still parked.
    now += base_evict_ns + 1;
    for (0..6) |_| {
        try testing.expect(!pool.pick(null, now).eql(addresses[0]));
    }
    // Past 2 * base total it rotates back in.
    now += base_evict_ns;
    var saw_first = false;
    for (0..4) |_| {
        if (pool.pick(null, now).eql(addresses[0])) saw_first = true;
    }
    try testing.expect(saw_first);
}

test "all evicted falls back to serving anyway" {
    const addresses = testAddresses(2);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, defaultBalancer());
    defer pool.deinit();

    const now: u64 = 1_000;
    for (0..failure_threshold) |_| pool.reportFailure(addresses[0], now);
    for (0..failure_threshold) |_| pool.reportFailure(addresses[1], now);
    const picked = pool.pick(null, now);
    try testing.expect(picked.eql(addresses[0]) or picked.eql(addresses[1]));
}

test "source hash is stable per client and skips evicted" {
    const addresses = testAddresses(3);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..3], &.{ 1, 1, 1 }, balancerByName("source_hash").?);
    defer pool.deinit();

    const client_a = net.SocketAddr.parseIp("10.0.0.1", 40000).?;
    const first_a = pool.pick(client_a, 0);
    try testing.expect(pool.pick(client_a, 0).eql(first_a));

    // The client port does not affect the hash: stickiness is per host.
    const client_a_other_port = net.SocketAddr.parseIp("10.0.0.1", 55555).?;
    try testing.expect(pool.pick(client_a_other_port, 0).eql(first_a));

    for (0..failure_threshold) |_| pool.reportFailure(first_a, 1_000);
    const rerouted = pool.pick(client_a, 1_000);
    try testing.expect(!rerouted.eql(first_a));
    try testing.expect(pool.pick(client_a, 1_000).eql(rerouted));
}

test "weighted round robin follows weights over a full cycle" {
    const addresses = testAddresses(2);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 3 }, balancerByName("weighted_round_robin").?);
    defer pool.deinit();

    var counts = [_]usize{ 0, 0 };
    for (0..8) |_| {
        const picked = pool.pick(null, 0);
        if (picked.eql(addresses[0])) counts[0] += 1;
        if (picked.eql(addresses[1])) counts[1] += 1;
    }
    try testing.expectEqual(@as(usize, 2), counts[0]);
    try testing.expectEqual(@as(usize, 6), counts[1]);
}

test "rebind swaps upstreams and inherits health by address" {
    const addresses = testAddresses(3);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, defaultBalancer());
    defer pool.deinit();

    const now: u64 = 1_000;
    for (0..failure_threshold) |_| pool.reportFailure(addresses[0], now);
    try testing.expect(pool.pick(null, now).eql(addresses[1]));

    // Replace upstream 1 with upstream 2; upstream 0 keeps its eviction.
    const new_weights = [_]u32{ 1, 1 };
    try pool.rebind(addresses[0..1], new_weights[0..]);
    try testing.expectEqual(@as(usize, 1), pool.count());
    try testing.expect(pool.pick(null, now).eql(addresses[0])); // single again

    try pool.rebind(addresses[0..3], &.{ 1, 1, 1 });
    try testing.expect(pool.pick(null, now).eql(addresses[1])); // 0 still parked
}

test "reports for unknown addresses are ignored" {
    const addresses = testAddresses(2);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, defaultBalancer());
    defer pool.deinit();

    const stranger = net.SocketAddr.parseIp("192.0.2.1", 9000).?;
    pool.reportFailure(stranger, 0);
    pool.reportSuccess(stranger);
    try testing.expect(pool.pick(null, 0).eql(addresses[0]));
}

test "balancer registry resolves names and rejects strangers" {
    try testing.expect(balancerByName("round_robin") == defaultBalancer());
    try testing.expect(balancerByName("source_hash") != null);
    try testing.expect(balancerByName("weighted_round_robin") != null);
    try testing.expect(balancerByName("least_conn") == null);

    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("round_robin, source_hash, weighted_round_robin", balancerNames(&buf));
}

test "pool selector adapts pick and reports" {
    const addresses = testAddresses(2);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, defaultBalancer());
    defer pool.deinit();

    const selector = poolSelector(&pool);
    try testing.expect(selector.pick(null, 0).eql(addresses[0]));
    for (0..failure_threshold) |_| selector.reportFailure(addresses[0], 1_000);
    try testing.expect(selector.pick(null, 1_000).eql(addresses[1]));
    selector.reportSuccess(addresses[1]);
}
