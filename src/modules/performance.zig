//! performance module: owns the `performance` directive (root context):
//! sockmap acceleration modes and UDP socket/relay buffer sizing.

const std = @import("std");
const conf = @import("../conf.zig");
const fw = @import("../module.zig");
const yaml = @import("../yaml.zig");

pub const SockmapAccelerationMode = enum { auto, enabled, disabled };

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
};

pub const Conf = PerformanceConfiguration;

pub const module: fw.Module = .{
    .name = "performance",
    .index = .performance,
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

fn setPerformance(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c: *Conf = @ptrCast(@alignCast(slot));
    const map = try yaml.requireMapping(cycle.gpa, cycle.diag, value, "performance");
    try yaml.checkKeys(cycle.gpa, cycle.diag, map, &.{ "tcpSockmapAcceleration", "udpSockmapAcceleration", "udpSocketBufferBytes", "udpDatagramBufferBytes", "udpIOThreads" }, "performance");
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
}
