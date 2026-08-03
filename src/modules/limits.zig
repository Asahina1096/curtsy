//! limits module: owns the `limits` directive in the root and rule contexts.
//!
//! Global limits default to the autotune formulas and track per-field
//! auto-tuning flags (the tuning daemon only adjusts fields still marked
//! auto). Rule confs hold explicit overrides only; merge() applies them over
//! the global limits, clearing the corresponding auto flags.

const std = @import("std");
const autotune = @import("../autotune.zig");
const conf = @import("../conf.zig");
const fw = @import("../module.zig");
const yaml = @import("../yaml.zig");

pub const max_udp_associations: i64 = std.math.maxInt(u32) / 2; // 2147483647

pub const LimitAutoTuning = struct {
    tcp_listen_backlog: bool = true,
    max_tcp_buffered_bytes: bool = true,
    max_udp_associations: bool = true,
    max_udp_pending_datagrams: bool = true,
    max_udp_pending_bytes: bool = true,
};

pub const LimitConfiguration = struct {
    tcp_listen_backlog: i64,
    max_tcp_buffered_bytes: i64,
    max_udp_associations: i64,
    max_udp_pending_datagrams: i64,
    max_udp_pending_bytes: i64,
    auto_tuning: LimitAutoTuning = .{},
};

/// Per-rule limit overrides; null inherits the global value (including its
/// auto-tuning flag).
pub const RuleLimitOverrides = struct {
    tcp_listen_backlog: ?i64 = null,
    max_tcp_buffered_bytes: ?i64 = null,
    max_udp_associations: ?i64 = null,
};

pub const Conf = LimitConfiguration;
pub const RuleConf = RuleLimitOverrides;

/// merge_conf analogue: rule overrides applied over the global limits;
/// an explicit override pins the field (no more tuning-daemon adjustment).
pub fn merge(global: LimitConfiguration, overrides: RuleLimitOverrides) LimitConfiguration {
    var limits = global;
    if (overrides.tcp_listen_backlog) |v| {
        limits.tcp_listen_backlog = v;
        limits.auto_tuning.tcp_listen_backlog = false;
    }
    if (overrides.max_tcp_buffered_bytes) |v| {
        limits.max_tcp_buffered_bytes = v;
        limits.auto_tuning.max_tcp_buffered_bytes = false;
    }
    if (overrides.max_udp_associations) |v| {
        limits.max_udp_associations = v;
        limits.auto_tuning.max_udp_associations = false;
    }
    return limits;
}

pub const module: fw.Module = .{
    .name = "limits",
    .directives = &directives,
    .create_conf = createConf,
    .create_rule_conf = createRuleConf,
    .validate = validate,
};

const directives = [_]fw.Directive{
    .{ .name = "limits", .root = true, .set = setLimits },
    .{ .name = "limits", .rule = true, .set = setRuleLimits },
};

fn createConf(cycle: *conf.Cycle) error{OutOfMemory}!*anyopaque {
    const auto_limits = autotune.limits(.system());
    const c = try cycle.allocator().create(Conf);
    c.* = .{
        .tcp_listen_backlog = auto_limits.tcp_listen_backlog,
        .max_tcp_buffered_bytes = auto_limits.max_tcp_buffered_bytes,
        .max_udp_associations = auto_limits.max_udp_associations,
        .max_udp_pending_datagrams = auto_limits.max_udp_pending_datagrams,
        .max_udp_pending_bytes = auto_limits.max_udp_pending_bytes,
    };
    return c;
}

fn createRuleConf(cycle: *conf.Cycle) error{OutOfMemory}!?*anyopaque {
    const c = try cycle.allocator().create(RuleConf);
    c.* = .{};
    return c;
}

fn setLimits(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c: *Conf = @ptrCast(@alignCast(slot));
    const map = try yaml.requireMapping(cycle.gpa, cycle.diag, value, "limits");
    try yaml.checkKeys(cycle.gpa, cycle.diag, map, &.{ "tcpListenBacklog", "maxTCPBufferedBytes", "maxUDPAssociations", "maxUDPPendingDatagrams", "maxUDPPendingBytes" }, "limits");
    const backlog = try yaml.decodeAutoTunedInt(cycle.gpa, cycle.diag, map, "tcpListenBacklog", "limits.tcpListenBacklog", c.tcp_listen_backlog);
    const tcp_bytes = try yaml.decodeAutoTunedInt(cycle.gpa, cycle.diag, map, "maxTCPBufferedBytes", "limits.maxTCPBufferedBytes", c.max_tcp_buffered_bytes);
    const udp_associations = try yaml.decodeAutoTunedInt(cycle.gpa, cycle.diag, map, "maxUDPAssociations", "limits.maxUDPAssociations", c.max_udp_associations);
    const pending_datagrams = try yaml.decodeAutoTunedInt(cycle.gpa, cycle.diag, map, "maxUDPPendingDatagrams", "limits.maxUDPPendingDatagrams", c.max_udp_pending_datagrams);
    const pending_bytes = try yaml.decodeAutoTunedInt(cycle.gpa, cycle.diag, map, "maxUDPPendingBytes", "limits.maxUDPPendingBytes", c.max_udp_pending_bytes);
    c.* = .{
        .tcp_listen_backlog = backlog.value,
        .max_tcp_buffered_bytes = tcp_bytes.value,
        .max_udp_associations = udp_associations.value,
        .max_udp_pending_datagrams = pending_datagrams.value,
        .max_udp_pending_bytes = pending_bytes.value,
        .auto_tuning = .{
            .tcp_listen_backlog = backlog.is_auto,
            .max_tcp_buffered_bytes = tcp_bytes.is_auto,
            .max_udp_associations = udp_associations.is_auto,
            .max_udp_pending_datagrams = pending_datagrams.is_auto,
            .max_udp_pending_bytes = pending_bytes.is_auto,
        },
    };
}

fn setRuleLimits(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    const c: *RuleConf = @ptrCast(@alignCast(slot));
    var path_buf: [80]u8 = undefined;
    const limits_path = std.fmt.bufPrint(&path_buf, "{s}.limits", .{path}) catch "rules.limits";
    const map = try yaml.requireMapping(cycle.gpa, cycle.diag, value, limits_path);
    try yaml.checkKeys(cycle.gpa, cycle.diag, map, &.{ "tcpListenBacklog", "maxTCPBufferedBytes", "maxUDPAssociations" }, limits_path);
    const backlog = try yaml.decodeAutoTunedInt(cycle.gpa, cycle.diag, map, "tcpListenBacklog", limits_path, 0);
    if (!backlog.is_auto) c.tcp_listen_backlog = backlog.value;
    const tcp_bytes = try yaml.decodeAutoTunedInt(cycle.gpa, cycle.diag, map, "maxTCPBufferedBytes", limits_path, 0);
    if (!tcp_bytes.is_auto) c.max_tcp_buffered_bytes = tcp_bytes.value;
    const udp_associations = try yaml.decodeAutoTunedInt(cycle.gpa, cycle.diag, map, "maxUDPAssociations", limits_path, 0);
    if (!udp_associations.is_auto) c.max_udp_associations = udp_associations.value;
}

fn validate(cycle: *conf.Cycle) yaml.LoadError!void {
    const c = cycle.conf(@This());
    if (c.tcp_listen_backlog < 1 or c.tcp_listen_backlog > std.math.maxInt(i32)) {
        yaml.setDiag(cycle.gpa, cycle.diag, "limits.tcpListenBacklog must be between 1 and {d}", .{std.math.maxInt(i32)});
        return error.InvalidConfiguration;
    }
    if (c.max_tcp_buffered_bytes <= 0) {
        yaml.setDiag(cycle.gpa, cycle.diag, "limits.maxTCPBufferedBytes must be positive", .{});
        return error.InvalidConfiguration;
    }
    if (c.max_udp_associations < 1 or c.max_udp_associations > max_udp_associations) {
        yaml.setDiag(cycle.gpa, cycle.diag, "limits.maxUDPAssociations must be between 1 and {d}", .{max_udp_associations});
        return error.InvalidConfiguration;
    }
    if (c.max_udp_pending_datagrams <= 0) {
        yaml.setDiag(cycle.gpa, cycle.diag, "limits.maxUDPPendingDatagrams must be positive", .{});
        return error.InvalidConfiguration;
    }
    if (c.max_udp_pending_bytes <= 0) {
        yaml.setDiag(cycle.gpa, cycle.diag, "limits.maxUDPPendingBytes must be positive", .{});
        return error.InvalidConfiguration;
    }

    for (cycle.rule_bundles.items) |*bundle| {
        const overrides = cycle.ruleConf(bundle, @This()).?.*;
        if (overrides.tcp_listen_backlog) |value| {
            if (value < 1 or value > std.math.maxInt(i32)) {
                yaml.setDiag(cycle.gpa, cycle.diag, "rules[{d}].limits.tcpListenBacklog must be between 1 and {d}", .{ bundle.index, std.math.maxInt(i32) });
                return error.InvalidConfiguration;
            }
        }
        if (overrides.max_tcp_buffered_bytes) |value| {
            if (value <= 0) {
                yaml.setDiag(cycle.gpa, cycle.diag, "rules[{d}].limits.maxTCPBufferedBytes must be positive", .{bundle.index});
                return error.InvalidConfiguration;
            }
        }
        if (overrides.max_udp_associations) |value| {
            if (value < 1 or value > max_udp_associations) {
                yaml.setDiag(cycle.gpa, cycle.diag, "rules[{d}].limits.maxUDPAssociations must be between 1 and {d}", .{ bundle.index, max_udp_associations });
                return error.InvalidConfiguration;
            }
        }
    }
}
