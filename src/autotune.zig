//! Auto-tuning formulas.
//!
//! All formulas derive conservative defaults from the machine's processor
//! count and total memory. Snapshots are plain values so tests can inject
//! synthetic hardware configurations.

const std = @import("std");

const mib: i64 = 1_024 * 1_024;
const gib: i64 = 1_024 * mib;

/// Hardware snapshot used by the tuning formulas.
pub const AutoTuneSnapshot = struct {
    processor_count: i64 = 1,
    total_memory_bytes: ?i64 = null,

    /// Snapshot of the current machine: logical CPU count and MemTotal from
    /// /proc/meminfo (null when it cannot be read).
    pub fn system() AutoTuneSnapshot {
        return .{
            .processor_count = @intCast(std.Thread.getCpuCount() catch 1),
            .total_memory_bytes = readTotalMemoryBytes(),
        };
    }
};

pub const AutoTunedLimits = struct {
    tcp_listen_backlog: i64,
    max_tcp_buffered_bytes: i64,
    max_udp_associations: i64,
    max_udp_pending_datagrams: i64,
    max_udp_pending_bytes: i64,
};

/// Fallback used when total memory cannot be determined: 1 GiB.
pub const default_memory_bytes: i64 = 1 * gib;

/// Zero (or negative) means auto: min(max(1, cores), 32).
pub fn workerThreads(configured: i64, snapshot: AutoTuneSnapshot) i64 {
    std.debug.assert(configured >= 0);
    if (configured > 0) return configured;
    return @min(@max(1, snapshot.processor_count), 32);
}

pub fn limits(snapshot: AutoTuneSnapshot) AutoTunedLimits {
    const memory = snapshot.total_memory_bytes orelse default_memory_bytes;
    const cores = @max(1, snapshot.processor_count);
    const tcp_budget = clamp(@divTrunc(memory, 8), 64 * mib, 512 * mib);
    return .{
        .tcp_listen_backlog = clamp(cores * 1_024, 4_096, 65_535),
        .max_tcp_buffered_bytes = tcp_budget,
        .max_udp_associations = clamp(@divTrunc(memory, 512 * 1_024), 1_024, 65_536),
        .max_udp_pending_datagrams = 64,
        .max_udp_pending_bytes = @min(@max(256 * 1_024, @divTrunc(tcp_budget, 256)), 2 * mib),
    };
}

pub fn highTCPBufferBudget(snapshot: AutoTuneSnapshot) i64 {
    const memory = snapshot.total_memory_bytes orelse default_memory_bytes;
    return clamp(@divTrunc(memory, 4), 64 * mib, 2 * gib);
}

pub fn highUDPAssociationLimit(snapshot: AutoTuneSnapshot) i64 {
    const memory = snapshot.total_memory_bytes orelse default_memory_bytes;
    return clamp(@divTrunc(memory, 256 * 1_024), 1_024, 262_144);
}

fn clamp(value: i64, minimum: i64, maximum: i64) i64 {
    return @max(minimum, @min(maximum, value));
}

fn readTotalMemoryBytes() ?i64 {
    const fd = std.posix.openat(std.posix.AT.FDCWD, "/proc/meminfo", .{}, 0) catch return null;
    defer _ = std.os.linux.close(fd);
    var buf: [8192]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch return null;
        if (n == 0) break;
        total += n;
    }
    const text = buf[0..total];
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "MemTotal:")) continue;
        var it = std.mem.tokenizeAny(u8, line, " \t");
        _ = it.next(); // "MemTotal:"
        const kib_text = it.next() orelse return null;
        const kib = std.fmt.parseInt(i64, kib_text, 10) catch return null;
        return kib * 1_024;
    }
    return null;
}

test "limits match documented auto-tuning formulas" {
    const tiny = limits(.{ .processor_count = 1, .total_memory_bytes = 512 * mib });
    try std.testing.expectEqual(4_096, tiny.tcp_listen_backlog);
    try std.testing.expectEqual(64 * mib, tiny.max_tcp_buffered_bytes);
    try std.testing.expectEqual(1_024, tiny.max_udp_associations);
    try std.testing.expectEqual(64, tiny.max_udp_pending_datagrams);

    const large = limits(.{ .processor_count = 96, .total_memory_bytes = 256 * gib });
    try std.testing.expectEqual(65_535, large.tcp_listen_backlog);
    try std.testing.expectEqual(512 * mib, large.max_tcp_buffered_bytes);
    try std.testing.expectEqual(65_536, large.max_udp_associations);
    try std.testing.expectEqual(2 * mib, large.max_udp_pending_bytes);

    try std.testing.expectEqual(32, workerThreads(0, .{ .processor_count = 96 }));
    try std.testing.expectEqual(6, workerThreads(6, .{ .processor_count = 96 }));
    try std.testing.expectEqual(1, workerThreads(0, .{ .processor_count = 0 }));
}

test "memory fallback and high-water formulas" {
    const unknown = limits(.{ .processor_count = 4, .total_memory_bytes = null });
    try std.testing.expectEqual(clamp(@divTrunc(default_memory_bytes, 8), 64 * mib, 512 * mib), unknown.max_tcp_buffered_bytes);
    try std.testing.expectEqual(clamp(@divTrunc(default_memory_bytes, 4), 64 * mib, 2 * gib), highTCPBufferBudget(.{}));
    try std.testing.expectEqual(clamp(@divTrunc(default_memory_bytes, 256 * 1_024), 1_024, 262_144), highUDPAssociationLimit(.{}));
}

test "system snapshot reads machine values" {
    const snapshot = AutoTuneSnapshot.system();
    try std.testing.expect(snapshot.processor_count >= 1);
    if (snapshot.total_memory_bytes) |bytes| {
        try std.testing.expect(bytes > 0);
    }
}
