//! source_hash balancer module (ngx_http_upstream_hash analogue).
//!
//! Stateless: the pick hashes the client family + IP bytes (per-host
//! stickiness, port excluded) and linear-probes for an eligible upstream.
//! Without a client address it degrades to round-robin rotation.

const std = @import("std");
const net = @import("../../net.zig");
const upstream = @import("../upstream.zig");

const Allocator = std.mem.Allocator;

pub const balancer: upstream.Balancer = .{
    .name = "source_hash",
    .build = build,
    .destroy = destroy,
    .pick = pick,
};

fn build(allocator: Allocator, addresses: []const net.SocketAddr, weights: []const u32) error{OutOfMemory}!?*anyopaque {
    _ = allocator;
    _ = addresses;
    _ = weights;
    return null;
}

fn destroy(allocator: Allocator, state: ?*anyopaque) void {
    _ = allocator;
    _ = state;
}

fn pick(state: ?*anyopaque, upstreams: []const upstream.UpstreamState, cursor: *std.atomic.Value(u32), client: ?net.SocketAddr, now_ns: u64) usize {
    _ = state;
    const start: usize = if (client) |address| hashClient(address) % upstreams.len else blk: {
        break :blk cursor.fetchAdd(1, .monotonic) % @as(u32, @intCast(upstreams.len));
    };
    var step: usize = 0;
    while (step < upstreams.len) : (step += 1) {
        const index = (start + step) % upstreams.len;
        if (upstreams[index].eligible(now_ns)) return index;
    }
    return start;
}

fn hashClient(address: net.SocketAddr) usize {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(&.{@intFromEnum(address.family)});
    switch (address.family) {
        .v4 => hasher.update(address.addr[0..4]),
        .v6 => hasher.update(&address.addr),
    }
    return @intCast(hasher.final());
}
