//! weighted_round_robin balancer module (nginx `weight=` server parameter).
//!
//! Strategy state is the weight-expanded pick sequence, interleaved round by
//! round so weights spread evenly ([0,1,0,1,1] for weights 2,3) instead of
//! bursting ([0,0,1,1,1]). Selection shares the sequential rotation walk
//! with round_robin.

const std = @import("std");
const net = @import("../../net.zig");
const upstream = @import("../upstream.zig");

const Allocator = std.mem.Allocator;

const State = struct {
    sequence: []u32,
};

pub const balancer: upstream.Balancer = .{
    .name = "weighted_round_robin",
    .build = build,
    .destroy = destroy,
    .pick = pick,
};

fn build(allocator: Allocator, addresses: []const net.SocketAddr, weights: []const u32) error{OutOfMemory}!?*anyopaque {
    var total_weight: usize = 0;
    for (weights) |weight| total_weight += weight;

    const state = try allocator.create(State);
    errdefer allocator.destroy(state);
    state.sequence = try allocator.alloc(u32, total_weight);
    errdefer allocator.free(state.sequence);

    var position: usize = 0;
    const max_weight = std.mem.max(u32, weights);
    var round: u32 = 0;
    while (round < max_weight) : (round += 1) {
        for (weights, 0..) |weight, i| {
            if (weight > round) {
                state.sequence[position] = @intCast(i);
                position += 1;
            }
        }
    }
    std.debug.assert(position == total_weight);
    std.debug.assert(addresses.len == weights.len);
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "weights interleave round by round" {
    const addresses = [_]net.SocketAddr{
        net.SocketAddr.parseIp("127.0.0.1", 9000).?,
        net.SocketAddr.parseIp("127.0.0.1", 9001).?,
    };
    const state = try build(testing.allocator, &addresses, &.{ 2, 3 });
    defer destroy(testing.allocator, state);
    const s: *State = @ptrCast(@alignCast(state.?));
    try testing.expectEqualSlices(u32, &.{ 0, 1, 0, 1, 1 }, s.sequence);
}
