//! Upstream pool: multi-upstream selection with passive failure eviction.
//!
//! Part of the opt-in rules plugin. A pool is a stable per-rule object whose
//! address is captured by the TCP/UDP selector hooks; configuration reloads
//! swap the internal generation under a mutex (inheriting health state by
//! address) so the selector context never changes. A single-entry pool
//! degrades to a constant pick with no bookkeeping, which is what the legacy
//! single-rule mode would get if it ever used this module.
//!
//! Eviction is passive: consecutive failures at or above `failure_threshold`
//! park an upstream for a cooldown that backs off exponentially on repeated
//! evictions. There is no probing; after the cooldown the upstream becomes
//! eligible again and real traffic decides.

const std = @import("std");
const config = @import("config.zig");
const log = @import("log.zig");

const Allocator = std.mem.Allocator;

pub const failure_threshold: u32 = 3;
pub const base_evict_ns: u64 = 10 * std.time.ns_per_s;
pub const max_evict_ns: u64 = 5 * std.time.ns_per_min;
const max_backoff_shift: u6 = 5;

const UpstreamState = struct {
    address: config.SocketAddr,
    consecutive_failures: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Monotonic timestamp until which the upstream is parked; 0 = eligible.
    evicted_until_ns: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    eviction_streak: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn eligible(self: *const UpstreamState, now_ns: u64) bool {
        const until = self.evicted_until_ns.load(.monotonic);
        return until == 0 or until <= now_ns;
    }
};

const Generation = struct {
    upstreams: []UpstreamState,
    /// Selection sequence: indexes into upstreams. Identity for round_robin
    /// and source_hash; weight-expanded and interleaved for
    /// weighted_round_robin.
    sequence: []u32,

    fn indexOf(self: *const Generation, address: config.SocketAddr) ?usize {
        for (self.upstreams, 0..) |*upstream, i| {
            if (upstream.address.eql(address)) return i;
        }
        return null;
    }
};

pub const UpstreamPool = struct {
    allocator: Allocator,
    policy: config.BalancePolicy,
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
        addresses: []const config.SocketAddr,
        weights: []const u32,
        policy: config.BalancePolicy,
    ) error{OutOfMemory}!UpstreamPool {
        const generation = try buildGeneration(allocator, addresses, weights, policy, null);
        errdefer destroyGeneration(allocator, generation);
        return .{
            .allocator = allocator,
            .policy = policy,
            .generation = generation,
        };
    }

    pub fn deinit(self: *UpstreamPool) void {
        destroyGeneration(self.allocator, self.generation);
        if (self.retired) |retired| destroyGeneration(self.allocator, retired);
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
    pub fn pick(self: *UpstreamPool, client: ?config.SocketAddr, now_ns: u64) config.SocketAddr {
        self.mutex.lock();
        defer self.mutex.unlock();
        const generation = self.generation;
        if (generation.upstreams.len == 1) return generation.upstreams[0].address;

        return switch (self.policy) {
            .source_hash => self.pickSourceHash(generation, client, now_ns),
            else => self.pickSequential(generation, now_ns),
        };
    }

    /// Record a successful exchange with an upstream: clears its failure
    /// count and eviction backoff.
    pub fn reportSuccess(self: *UpstreamPool, address: config.SocketAddr) void {
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
    pub fn reportFailure(self: *UpstreamPool, address: config.SocketAddr, now_ns: u64) void {
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
        addresses: []const config.SocketAddr,
        weights: []const u32,
    ) error{OutOfMemory}!void {
        const replacement = try buildGeneration(self.allocator, addresses, weights, self.policy, self.generation);
        self.mutex.lock();
        const old = self.generation;
        self.generation = replacement;
        if (self.retired) |retired| destroyGeneration(self.allocator, retired);
        self.retired = old;
        self.mutex.unlock();
    }

    /// Snapshot of the current upstream addresses (used to detect upstream
    /// set changes across reloads). Caller owns the returned slice.
    pub fn currentAddresses(self: *UpstreamPool, allocator: Allocator) error{OutOfMemory}![]config.SocketAddr {
        self.mutex.lock();
        defer self.mutex.unlock();
        const generation = self.generation;
        const addresses = try allocator.alloc(config.SocketAddr, generation.upstreams.len);
        for (generation.upstreams, 0..) |*upstream, i| addresses[i] = upstream.address;
        return addresses;
    }

    fn pickSequential(self: *UpstreamPool, generation: *const Generation, now_ns: u64) config.SocketAddr {
        const sequence = generation.sequence;
        const start = self.cursor.fetchAdd(1, .monotonic) % @as(u32, @intCast(sequence.len));
        var first: ?usize = null;
        var step: u32 = 0;
        while (step < sequence.len) : (step += 1) {
            const index = sequence[(start + step) % @as(u32, @intCast(sequence.len))];
            if (first == null) first = index;
            if (generation.upstreams[index].eligible(now_ns)) {
                return generation.upstreams[index].address;
            }
        }
        return generation.upstreams[first.?].address;
    }

    fn pickSourceHash(self: *UpstreamPool, generation: *const Generation, client: ?config.SocketAddr, now_ns: u64) config.SocketAddr {
        const upstreams = generation.upstreams;
        const start: usize = if (client) |address| hashClient(address) % upstreams.len else blk: {
            break :blk self.cursor.fetchAdd(1, .monotonic) % @as(u32, @intCast(upstreams.len));
        };
        var step: usize = 0;
        while (step < upstreams.len) : (step += 1) {
            const index = (start + step) % upstreams.len;
            if (upstreams[index].eligible(now_ns)) return upstreams[index].address;
        }
        return upstreams[start].address;
    }
};

fn hashClient(address: config.SocketAddr) usize {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(&.{@intFromEnum(address.family)});
    switch (address.family) {
        .v4 => hasher.update(address.addr[0..4]),
        .v6 => hasher.update(&address.addr),
    }
    return @intCast(hasher.final());
}

fn buildGeneration(
    allocator: Allocator,
    addresses: []const config.SocketAddr,
    weights: []const u32,
    policy: config.BalancePolicy,
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

    var total_weight: usize = 0;
    for (weights) |weight| total_weight += weight;
    const sequence_len = switch (policy) {
        .weighted_round_robin => total_weight,
        else => addresses.len,
    };
    const sequence = try allocator.alloc(u32, sequence_len);
    errdefer allocator.free(sequence);
    switch (policy) {
        .weighted_round_robin => {
            // Interleave copies round by round so weights spread evenly
            // ([0,1,0,1,1] for weights 2,3) instead of bursting ([0,0,1,1,1]).
            var position: usize = 0;
            const max_weight = std.mem.max(u32, weights);
            var round: u32 = 0;
            while (round < max_weight) : (round += 1) {
                for (weights, 0..) |weight, i| {
                    if (weight > round) {
                        sequence[position] = @intCast(i);
                        position += 1;
                    }
                }
            }
        },
        else => {
            for (sequence, 0..) |*slot, i| slot.* = @intCast(i);
        },
    }

    const generation = try allocator.create(Generation);
    generation.* = .{ .upstreams = upstreams, .sequence = sequence };
    return generation;
}

fn destroyGeneration(allocator: Allocator, generation: *Generation) void {
    allocator.free(generation.upstreams);
    allocator.free(generation.sequence);
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

fn testAddresses(count: usize) [4]config.SocketAddr {
    var addresses: [4]config.SocketAddr = undefined;
    for (0..count) |i| {
        addresses[i] = config.SocketAddr.parseIp("127.0.0.1", @intCast(9000 + i)).?;
    }
    return addresses;
}

test "single upstream pool is a constant pick" {
    const addresses = testAddresses(1);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..1], &.{1}, .round_robin);
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
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..3], &.{ 1, 1, 1 }, .round_robin);
    defer pool.deinit();

    try testing.expect(pool.pick(null, 0).eql(addresses[0]));
    try testing.expect(pool.pick(null, 0).eql(addresses[1]));
    try testing.expect(pool.pick(null, 0).eql(addresses[2]));
    try testing.expect(pool.pick(null, 0).eql(addresses[0]));
}

test "round robin skips evicted upstreams and recovers after cooldown" {
    const addresses = testAddresses(2);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, .round_robin);
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
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, .round_robin);
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
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, .round_robin);
    defer pool.deinit();

    const now: u64 = 1_000;
    for (0..failure_threshold) |_| pool.reportFailure(addresses[0], now);
    for (0..failure_threshold) |_| pool.reportFailure(addresses[1], now);
    const picked = pool.pick(null, now);
    try testing.expect(picked.eql(addresses[0]) or picked.eql(addresses[1]));
}

test "source hash is stable per client and skips evicted" {
    const addresses = testAddresses(3);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..3], &.{ 1, 1, 1 }, .source_hash);
    defer pool.deinit();

    const client_a = config.SocketAddr.parseIp("10.0.0.1", 40000).?;
    const client_b = config.SocketAddr.parseIp("10.0.0.2", 40001).?;
    const first_a = pool.pick(client_a, 0);
    try testing.expect(pool.pick(client_a, 0).eql(first_a));

    // The client port does not affect the hash: stickiness is per host.
    const client_a_other_port = config.SocketAddr.parseIp("10.0.0.1", 55555).?;
    try testing.expect(pool.pick(client_a_other_port, 0).eql(first_a));

    for (0..failure_threshold) |_| pool.reportFailure(first_a, 1_000);
    const rerouted = pool.pick(client_a, 1_000);
    try testing.expect(!rerouted.eql(first_a));
    try testing.expect(pool.pick(client_a, 1_000).eql(rerouted));

    _ = client_b;
}

test "weighted round robin follows weights over a full cycle" {
    const addresses = testAddresses(2);
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 3 }, .weighted_round_robin);
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
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, .round_robin);
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
    var pool = try UpstreamPool.init(testing.allocator, addresses[0..2], &.{ 1, 1 }, .round_robin);
    defer pool.deinit();

    const stranger = config.SocketAddr.parseIp("192.0.2.1", 9000).?;
    pool.reportFailure(stranger, 0);
    pool.reportSuccess(stranger);
    try testing.expect(pool.pick(null, 0).eql(addresses[0]));
}
