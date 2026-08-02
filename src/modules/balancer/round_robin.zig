//! round_robin balancer module (ngx_http_upstream_round_robin analogue).
//!
//! Strategy state is the identity pick sequence; selection rotates through
//! the pool-global cursor, skipping evicted upstreams.

const std = @import("std");
const net = @import("../../net.zig");
const upstream = @import("../upstream.zig");

const Allocator = std.mem.Allocator;

pub const balancer: upstream.Balancer = .{
    .name = "round_robin",
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

fn destroy(allocator: Allocator, opaque_state: ?*anyopaque) void {
    _ = allocator;
    _ = opaque_state;
}

fn pick(opaque_state: ?*anyopaque, upstreams: []const upstream.UpstreamState, cursor: *std.atomic.Value(u32), client: ?net.SocketAddr, now_ns: u64) usize {
    _ = opaque_state;
    _ = client;
    const len: u32 = @intCast(upstreams.len);
    const start = cursor.fetchAdd(1, .monotonic) % len;
    var index = start;
    var remaining = upstreams.len;
    while (remaining > 0) : (remaining -= 1) {
        if (upstreams[index].eligible(now_ns)) return index;
        index += 1;
        if (index == len) index = 0;
    }
    return start;
}
