//! performance module: owns the `performance` directive (root context):
//! sockmap acceleration modes and UDP socket/relay buffer sizing.

const std = @import("std");
const conf = @import("../conf.zig");
const fw = @import("../module.zig");
const yaml = @import("../yaml.zig");
const linux = std.os.linux;

pub const SockmapAccelerationMode = enum { auto, enabled, disabled };

/// How relay threads (TCP workers, UDP I/O engines) are pinned to CPUs.
/// `none` leaves scheduling to the kernel; `sequential` binds thread i to the
/// i-th online (allowed) CPU, wrapping; an explicit list binds thread i to
/// list[i % list.len]. Pinning improves cache locality on multi-core/NUMA
/// hosts but can hurt on shared machines, so it is opt-in and defaults to
/// none. The explicit list and the config string live in the cycle arena.
pub const CpuAffinity = union(enum) {
    none,
    sequential,
    explicit: []const u16,
};

pub const max_udp_socket_buffer_bytes: i64 = 1 << 28; // 268435456
// 576 covers the minimum IPv4 MTU; 65536 is the maximum UDP payload size.
pub const min_udp_datagram_buffer_bytes: i64 = 576;
pub const max_udp_datagram_buffer_bytes: i64 = 65_536;

pub const PerformanceConfiguration = struct {
    pub const default_udp_socket_buffer_bytes: i64 = 4 * 1_024 * 1_024;
    pub const default_udp_datagram_buffer_bytes: i64 = 65_536;

    tcp_sockmap_acceleration: SockmapAccelerationMode = .auto,
    udp_sockmap_acceleration: SockmapAccelerationMode = .auto,
    // Zero keeps the kernel default socket buffers; any positive value is
    // silently clamped to net.core.rmem_max/wmem_max without CAP_NET_ADMIN.
    udp_socket_buffer_bytes: i64 = default_udp_socket_buffer_bytes,
    // Per-slot receive buffer size for the batched UDP relay. Smaller values
    // improve cache/TLB locality for small-datagram workloads; datagrams
    // larger than this are truncated.
    udp_datagram_buffer_bytes: i64 = default_udp_datagram_buffer_bytes,
    // Zero auto-tunes to the worker thread count.
    udp_io_threads: i64 = 0,
    /// CPU affinity for relay threads; see `CpuAffinity`. Default: no pinning.
    thread_cpu_affinity: CpuAffinity = .none,
};

pub const Conf = PerformanceConfiguration;

pub const module: fw.Module = .{
    .name = "performance",
    .directives = &directives,
    .create_conf = createConf,
    .validate = validate,
};

const directives = [_]fw.Directive{
    .{ .name = "performance", .root = true, .set = setPerformance },
};

fn createConf(cycle: *conf.Cycle) error{OutOfMemory}!*anyopaque {
    const c = try cycle.allocator().create(Conf);
    c.* = .{};
    return c;
}

fn decodeSockmapMode(cycle: *conf.Cycle, value: *yaml.Value, path: []const u8) yaml.LoadError!SockmapAccelerationMode {
    const text = try yaml.decodeString(cycle.gpa, cycle.diag, value, path);
    const map = std.StaticStringMap(SockmapAccelerationMode).initComptime(.{
        .{ "auto", .auto },
        .{ "enabled", .enabled },
        .{ "disabled", .disabled },
    });
    return map.get(text) orelse
        yaml.fail(cycle.gpa, cycle.diag, "{s}: expected one of auto, enabled, disabled", .{path});
}

fn decodeCpuAffinity(cycle: *conf.Cycle, value: *yaml.Value, path: []const u8) yaml.LoadError!CpuAffinity {
    switch (value.*) {
        .scalar => {
            const text = try yaml.decodeString(cycle.gpa, cycle.diag, value, path);
            if (std.mem.eql(u8, text, "none")) return .none;
            if (std.mem.eql(u8, text, "sequential")) return .sequential;
            return yaml.fail(cycle.gpa, cycle.diag, "{s}: expected none, sequential, or a list of cpu ids", .{path});
        },
        .sequence => {
            const items = value.sequence;
            const cpus = try cycle.allocator().alloc(u16, items.len);
            for (items, 0..) |entry, i| {
                const cpu = try yaml.decodeInt(cycle.gpa, cycle.diag, entry, path);
                if (cpu < 0) {
                    return yaml.fail(cycle.gpa, cycle.diag, "{s}[{d}]: cpu ids must be non-negative", .{ path, i });
                }
                // cpu_set_t cannot represent ids beyond CPU_SETSIZE; reject
                // them here instead of panicking on the u16 cast or silently
                // skipping them in pinThread.
                if (cpu >= linux.CPU_SETSIZE) {
                    return yaml.fail(cycle.gpa, cycle.diag, "{s}[{d}]: cpu ids must be below {d}", .{ path, i, linux.CPU_SETSIZE });
                }
                cpus[i] = @intCast(cpu);
            }
            return .{ .explicit = cpus };
        },
        else => return yaml.fail(cycle.gpa, cycle.diag, "{s}: expected none, sequential, or a list of cpu ids", .{path}),
    }
}

fn setPerformance(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c: *Conf = @ptrCast(@alignCast(slot));
    const map = try yaml.requireMapping(cycle.gpa, cycle.diag, value, "performance");
    try yaml.checkKeys(cycle.gpa, cycle.diag, map, &.{ "tcpSockmapAcceleration", "udpSockmapAcceleration", "udpSocketBufferBytes", "udpDatagramBufferBytes", "udpIOThreads", "threadCpuAffinity" }, "performance");
    if (yaml.mappingGet(map, "tcpSockmapAcceleration")) |v| {
        c.tcp_sockmap_acceleration = try decodeSockmapMode(cycle, v, "performance.tcpSockmapAcceleration");
    }
    if (yaml.mappingGet(map, "udpSockmapAcceleration")) |v| {
        c.udp_sockmap_acceleration = try decodeSockmapMode(cycle, v, "performance.udpSockmapAcceleration");
    }
    if (yaml.mappingGet(map, "udpSocketBufferBytes")) |v| {
        c.udp_socket_buffer_bytes = try yaml.decodeInt(cycle.gpa, cycle.diag, v, "performance.udpSocketBufferBytes");
    }
    if (yaml.mappingGet(map, "udpDatagramBufferBytes")) |v| {
        c.udp_datagram_buffer_bytes = try yaml.decodeInt(cycle.gpa, cycle.diag, v, "performance.udpDatagramBufferBytes");
    }
    const io_threads = try yaml.decodeAutoTunedInt(cycle.gpa, cycle.diag, map, "udpIOThreads", "performance.udpIOThreads", 0);
    c.udp_io_threads = io_threads.value;
    if (yaml.mappingGet(map, "threadCpuAffinity")) |v| {
        c.thread_cpu_affinity = try decodeCpuAffinity(cycle, v, "performance.threadCpuAffinity");
    }
}

fn validate(cycle: *conf.Cycle) yaml.LoadError!void {
    const c = cycle.conf(@This());
    if (c.udp_socket_buffer_bytes < 0 or c.udp_socket_buffer_bytes > max_udp_socket_buffer_bytes) {
        yaml.setDiag(cycle.gpa, cycle.diag, "performance.udpSocketBufferBytes must be between 0 (kernel default) and {d}", .{max_udp_socket_buffer_bytes});
        return error.InvalidConfiguration;
    }
    if (c.udp_io_threads < 0) {
        yaml.setDiag(cycle.gpa, cycle.diag, "performance.udpIOThreads must be zero for auto or positive", .{});
        return error.InvalidConfiguration;
    }
    if (c.udp_datagram_buffer_bytes < min_udp_datagram_buffer_bytes or
        c.udp_datagram_buffer_bytes > max_udp_datagram_buffer_bytes)
    {
        yaml.setDiag(cycle.gpa, cycle.diag, "performance.udpDatagramBufferBytes must be between {d} and {d}", .{ min_udp_datagram_buffer_bytes, max_udp_datagram_buffer_bytes });
        return error.InvalidConfiguration;
    }
    switch (c.thread_cpu_affinity) {
        .explicit => |list| if (list.len == 0) {
            yaml.setDiag(cycle.gpa, cycle.diag, "performance.threadCpuAffinity list must not be empty", .{});
            return error.InvalidConfiguration;
        },
        else => {},
    }
}

const testing = std.testing;

fn loadPerformanceForTest(text: []const u8) !conf.Cycle {
    var diag = conf.Diagnostics{};
    return conf.loadYaml(testing.allocator, text, &diag) catch |err| {
        if (diag.message) |message| testing.allocator.free(message);
        return err;
    };
}

test "threadCpuAffinity decodes none, sequential and explicit lists" {
    var cycle = try loadPerformanceForTest(
        \\listen: { port: 9000 }
        \\upstream: { host: "localhost", port: 9000 }
        \\
    );
    defer cycle.deinit();
    try testing.expect(cycle.conf(@This()).thread_cpu_affinity == .none);

    var cycle_seq = try loadPerformanceForTest(
        \\listen: { port: 9000 }
        \\upstream: { host: "localhost", port: 9000 }
        \\performance:
        \\  threadCpuAffinity: sequential
        \\
    );
    defer cycle_seq.deinit();
    try testing.expect(cycle_seq.conf(@This()).thread_cpu_affinity == .sequential);

    var cycle_list = try loadPerformanceForTest(
        \\listen: { port: 9000 }
        \\upstream: { host: "localhost", port: 9000 }
        \\performance:
        \\  threadCpuAffinity: [0, 2, 4]
        \\
    );
    defer cycle_list.deinit();
    const explicit = cycle_list.conf(@This()).thread_cpu_affinity;
    try testing.expect(explicit == .explicit);
    try testing.expectEqualSlices(u16, &.{ 0, 2, 4 }, explicit.explicit);
}

test "threadCpuAffinity rejects invalid values and empty lists" {
    var diag = conf.Diagnostics{};
    try testing.expectError(error.InvalidConfiguration, conf.loadYaml(
        testing.allocator,
        \\listen: { port: 9000 }
        \\upstream: { host: "localhost", port: 9000 }
        \\performance:
        \\  threadCpuAffinity: bogus
        \\
    , &diag));
    defer if (diag.message) |message| testing.allocator.free(message);

    var diag_empty = conf.Diagnostics{};
    try testing.expectError(error.InvalidConfiguration, conf.loadYaml(
        testing.allocator,
        \\listen: { port: 9000 }
        \\upstream: { host: "localhost", port: 9000 }
        \\performance:
        \\  threadCpuAffinity: []
        \\
    , &diag_empty));
    defer if (diag_empty.message) |message| testing.allocator.free(message);

    // Out-of-range ids are a config error, not an integer cast panic.
    var diag_neg = conf.Diagnostics{};
    try testing.expectError(error.InvalidConfiguration, conf.loadYaml(
        testing.allocator,
        \\listen: { port: 9000 }
        \\upstream: { host: "localhost", port: 9000 }
        \\performance:
        \\  threadCpuAffinity: [-1]
        \\
    , &diag_neg));
    defer if (diag_neg.message) |message| testing.allocator.free(message);

    var diag_big = conf.Diagnostics{};
    try testing.expectError(error.InvalidConfiguration, conf.loadYaml(
        testing.allocator,
        \\listen: { port: 9000 }
        \\upstream: { host: "localhost", port: 9000 }
        \\performance:
        \\  threadCpuAffinity: [1024]
        \\
    , &diag_big));
    defer if (diag_big.message) |message| testing.allocator.free(message);

    var diag_huge = conf.Diagnostics{};
    try testing.expectError(error.InvalidConfiguration, conf.loadYaml(
        testing.allocator,
        \\listen: { port: 9000 }
        \\upstream: { host: "localhost", port: 9000 }
        \\performance:
        \\  threadCpuAffinity: [70000]
        \\
    , &diag_huge));
    defer if (diag_huge.message) |message| testing.allocator.free(message);
}

test "affinityCpu selects the target cpu per policy" {
    const eight: []const u16 = &.{ 0, 1, 2, 3, 4, 5, 6, 7 };
    // none never pins.
    try testing.expect(affinityCpu(.none, 0, eight) == null);
    try testing.expect(affinityCpu(.none, 5, eight) == null);

    // sequential wraps over the allowed set.
    try testing.expectEqual(@as(?usize, 0), affinityCpu(.sequential, 0, eight));
    try testing.expectEqual(@as(?usize, 7), affinityCpu(.sequential, 7, eight));
    try testing.expectEqual(@as(?usize, 0), affinityCpu(.sequential, 8, eight));
    try testing.expectEqual(@as(?usize, 1), affinityCpu(.sequential, 9, eight));
    // A one-cpu cpuset pins everything to that cpu.
    const one: []const u16 = &.{5};
    try testing.expectEqual(@as(?usize, 5), affinityCpu(.sequential, 42, one));
    // A cpuset that does not start at cpu 0 still lands on allowed cpus.
    const restricted: []const u16 = &.{ 2, 3, 6 };
    try testing.expectEqual(@as(?usize, 2), affinityCpu(.sequential, 0, restricted));
    try testing.expectEqual(@as(?usize, 3), affinityCpu(.sequential, 1, restricted));
    try testing.expectEqual(@as(?usize, 6), affinityCpu(.sequential, 2, restricted));
    try testing.expectEqual(@as(?usize, 2), affinityCpu(.sequential, 3, restricted));
    // An unreadable/empty mask is a defensive no-op.
    try testing.expect(affinityCpu(.sequential, 0, &.{}) == null);

    // Explicit lists wrap; an empty list is a defensive no-op.
    const list: []const u16 = &.{ 0, 2, 4 };
    try testing.expectEqual(@as(?usize, 0), affinityCpu(.{ .explicit = list }, 0, eight));
    try testing.expectEqual(@as(?usize, 4), affinityCpu(.{ .explicit = list }, 2, eight));
    try testing.expectEqual(@as(?usize, 2), affinityCpu(.{ .explicit = list }, 4, eight));
    const empty: []const u16 = &.{};
    try testing.expect(affinityCpu(.{ .explicit = empty }, 0, eight) == null);
}

/// Enumerate the CPUs the calling process is currently allowed to run on,
/// from its own affinity mask (respects cpuset/cgroup restrictions), into
/// `buf` in ascending id order. Returns the populated prefix; an empty slice
/// when the mask cannot be read or is empty.
fn allowedCpus(buf: []u16) []const u16 {
    const set = std.posix.sched_getaffinity(std.os.linux.getpid()) catch return &.{};
    var count: usize = 0;
    for (0..linux.CPU_SETSIZE) |cpu| {
        if (count == buf.len) break;
        const word = cpu / @bitSizeOf(usize);
        const bit = cpu % @bitSizeOf(usize);
        if (set[word] & (@as(usize, 1) << @intCast(bit)) != 0) {
            buf[count] = @intCast(cpu);
            count += 1;
        }
    }
    return buf[0..count];
}

/// The CPU selected for the thread at `index` under `affinity`, or null when
/// no pinning applies. `allowed` is the process's allowed CPU list in
/// ascending order: `sequential` binds thread i to the i-th allowed CPU
/// (wrapping), so masks that do not start at cpu 0 (taskset, systemd
/// CPUAffinity, container cpusets) still land on legal CPUs. Pure and
/// testable; the syscall lives in `pinThread`.
pub fn affinityCpu(affinity: CpuAffinity, index: usize, allowed: []const u16) ?usize {
    return switch (affinity) {
        .none => null,
        .sequential => if (allowed.len == 0) null else allowed[index % allowed.len],
        .explicit => |list| if (list.len == 0) null else list[index % list.len],
    };
}

/// Pin the calling thread to the CPU selected by `affinity` for the thread at
/// `index`. No-op for `none`. A cpu beyond the 128-bit `cpu_set_t` range is
/// skipped (not representable). Returns an error only on a failed
/// sched_setaffinity syscall; callers treat any failure as non-fatal and
/// continue unpinned.
pub fn pinThread(affinity: CpuAffinity, index: usize) !void {
    var buf: [linux.CPU_SETSIZE]u16 = undefined;
    const cpu = affinityCpu(affinity, index, allowedCpus(&buf)) orelse return;
    if (cpu >= linux.CPU_SETSIZE) return;
    var set: linux.cpu_set_t = .{0} ** (linux.CPU_SETSIZE / @sizeOf(usize));
    const word = cpu / @bitSizeOf(usize);
    const bit = cpu % @bitSizeOf(usize);
    set[word] |= @as(usize, 1) << @intCast(bit);
    // gettid() addresses the calling thread; getpid() would touch the main
    // thread's affinity instead.
    try linux.sched_setaffinity(linux.gettid(), &set);
}
