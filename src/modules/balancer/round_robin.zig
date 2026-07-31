//! round_robin balancer module (ngx_http_upstream_round_robin analogue).
//!
//! Strategy state is the identity pick sequence; selection rotates through
//! the pool-global cursor, skipping evicted upstreams.

const std = @import("std");
const net = @import("../../net.zig");
const upstream = @import("../upstream.zig");

const Allocator = std.mem.Allocator;

pub const State = struct {
    sequence: []u32,
};

pub const balancer: upstream.Balancer = .{
    .name = "round_robin",
    .build = build,
    .destroy = destroy,
    .pick = pick,
};

fn build(allocator: Allocator, addresses: []const net.SocketAddr, weights: []const u32) error{OutOfMemory}!?*anyopaque {
    _ = weights;
    const state = try allocator.create(State);
    errdefer allocator.destroy(state);
    state.sequence = try allocator.alloc(u32, addresses.len);
    for (state.sequence, 0..) |*slot, i| slot.* = @intCast(i);
    return state;
}

fn destroy(allocator: Allocator, opaque_state: ?*anyopaque) void {
    const state: *State = @ptrCast(@alignCast(opaque_state orelse return));
    allocator.free(state.sequence);
    allocator.destroy(state);
}

fn pick(opaque_state: ?*anyopaque, upstreams: []const upstream.UpstreamState, cursor: *std.atomic.Value(u32), client: ?net.SocketAddr, now_ns: u64) usize {
    _ = client;
    const state: *State = @ptrCast(@alignCast(opaque_state.?));
    return upstream.pickSequential(state.sequence, upstreams, cursor, now_ns);
}
