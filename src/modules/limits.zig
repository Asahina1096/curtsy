//! limits section: owns the `limits` key in the root and rule contexts.
//!
//! Global limits start from the fixed built-in defaults declared below and are
//! replaced by any explicitly configured integer. Rule confs hold explicit
//! overrides only; merge() applies them over the global limits.

const std = @import("std");
const conf = @import("../conf.zig");
const yaml = @import("../yaml.zig");

pub const max_udp_associations: i64 = std.math.maxInt(u32) / 2; // 2147483647

/// Fixed built-in global limit defaults. An omitted key always means exactly
/// this value; there is no host-derived default and no runtime adjustment.
pub const default_tcp_listen_backlog: i64 = 4_096;
pub const default_max_tcp_buffered_bytes: i64 = 128 * 1_024 * 1_024; // 128 MiB
pub const default_max_udp_associations: i64 = 2_048;
pub const default_max_udp_pending_datagrams: i64 = 64;
pub const default_max_udp_pending_bytes: i64 = 512 * 1_024; // 512 KiB

pub const LimitConfiguration = struct {
    tcp_listen_backlog: i64 = default_tcp_listen_backlog,
    max_tcp_buffered_bytes: i64 = default_max_tcp_buffered_bytes,
    max_udp_associations: i64 = default_max_udp_associations,
    max_udp_pending_datagrams: i64 = default_max_udp_pending_datagrams,
    max_udp_pending_bytes: i64 = default_max_udp_pending_bytes,
};

/// Per-rule limit overrides; null inherits the global value.
pub const RuleLimitOverrides = struct {
    tcp_listen_backlog: ?i64 = null,
    max_tcp_buffered_bytes: ?i64 = null,
    max_udp_associations: ?i64 = null,
};

pub const Conf = LimitConfiguration;
pub const RuleConf = RuleLimitOverrides;

/// merge_conf analogue: rule overrides applied over the global limits; an
/// explicit override replaces the global value for that rule.
pub fn merge(global: LimitConfiguration, overrides: RuleLimitOverrides) LimitConfiguration {
    var limits = global;
    if (overrides.tcp_listen_backlog) |v| limits.tcp_listen_backlog = v;
    if (overrides.max_tcp_buffered_bytes) |v| limits.max_tcp_buffered_bytes = v;
    if (overrides.max_udp_associations) |v| limits.max_udp_associations = v;
    return limits;
}

pub fn setLimits(cfg: *conf.Configuration, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c = &cfg.limits;
    const map = try yaml.requireMapping(cfg.gpa, cfg.diag, value, "limits");
    try yaml.checkKeys(cfg.gpa, cfg.diag, map, &.{ "tcpListenBacklog", "maxTCPBufferedBytes", "maxUDPAssociations", "maxUDPPendingDatagrams", "maxUDPPendingBytes" }, "limits");
    if (yaml.mappingGet(map, "tcpListenBacklog")) |v| {
        c.tcp_listen_backlog = try yaml.decodeInt(cfg.gpa, cfg.diag, v, "limits.tcpListenBacklog");
    }
    if (yaml.mappingGet(map, "maxTCPBufferedBytes")) |v| {
        c.max_tcp_buffered_bytes = try yaml.decodeInt(cfg.gpa, cfg.diag, v, "limits.maxTCPBufferedBytes");
    }
    if (yaml.mappingGet(map, "maxUDPAssociations")) |v| {
        c.max_udp_associations = try yaml.decodeInt(cfg.gpa, cfg.diag, v, "limits.maxUDPAssociations");
    }
    if (yaml.mappingGet(map, "maxUDPPendingDatagrams")) |v| {
        c.max_udp_pending_datagrams = try yaml.decodeInt(cfg.gpa, cfg.diag, v, "limits.maxUDPPendingDatagrams");
    }
    if (yaml.mappingGet(map, "maxUDPPendingBytes")) |v| {
        c.max_udp_pending_bytes = try yaml.decodeInt(cfg.gpa, cfg.diag, v, "limits.maxUDPPendingBytes");
    }
}

pub fn setRuleLimits(cfg: *conf.Configuration, oc: *RuleConf, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    const c = oc;
    var path_buf: [96]u8 = undefined;
    const limits_path = std.fmt.bufPrint(&path_buf, "{s}.limits", .{path}) catch "rules.limits";
    const map = try yaml.requireMapping(cfg.gpa, cfg.diag, value, limits_path);
    try yaml.checkKeys(cfg.gpa, cfg.diag, map, &.{ "tcpListenBacklog", "maxTCPBufferedBytes", "maxUDPAssociations" }, limits_path);
    var key_buf: [128]u8 = undefined;
    if (yaml.mappingGet(map, "tcpListenBacklog")) |v| {
        const field_path = std.fmt.bufPrint(&key_buf, "{s}.tcpListenBacklog", .{limits_path}) catch limits_path;
        c.tcp_listen_backlog = try yaml.decodeInt(cfg.gpa, cfg.diag, v, field_path);
    }
    if (yaml.mappingGet(map, "maxTCPBufferedBytes")) |v| {
        const field_path = std.fmt.bufPrint(&key_buf, "{s}.maxTCPBufferedBytes", .{limits_path}) catch limits_path;
        c.max_tcp_buffered_bytes = try yaml.decodeInt(cfg.gpa, cfg.diag, v, field_path);
    }
    if (yaml.mappingGet(map, "maxUDPAssociations")) |v| {
        const field_path = std.fmt.bufPrint(&key_buf, "{s}.maxUDPAssociations", .{limits_path}) catch limits_path;
        c.max_udp_associations = try yaml.decodeInt(cfg.gpa, cfg.diag, v, field_path);
    }
}

pub fn validate(cfg: *conf.Configuration) yaml.LoadError!void {
    const c = &cfg.limits;
    if (c.tcp_listen_backlog < 1 or c.tcp_listen_backlog > std.math.maxInt(i32)) {
        yaml.setDiag(cfg.gpa, cfg.diag, "limits.tcpListenBacklog must be between 1 and {d}", .{std.math.maxInt(i32)});
        return error.InvalidConfiguration;
    }
    if (c.max_tcp_buffered_bytes <= 0) {
        yaml.setDiag(cfg.gpa, cfg.diag, "limits.maxTCPBufferedBytes must be positive", .{});
        return error.InvalidConfiguration;
    }
    if (c.max_udp_associations < 1 or c.max_udp_associations > max_udp_associations) {
        yaml.setDiag(cfg.gpa, cfg.diag, "limits.maxUDPAssociations must be between 1 and {d}", .{max_udp_associations});
        return error.InvalidConfiguration;
    }
    if (c.max_udp_pending_datagrams <= 0) {
        yaml.setDiag(cfg.gpa, cfg.diag, "limits.maxUDPPendingDatagrams must be positive", .{});
        return error.InvalidConfiguration;
    }
    if (c.max_udp_pending_bytes <= 0) {
        yaml.setDiag(cfg.gpa, cfg.diag, "limits.maxUDPPendingBytes must be positive", .{});
        return error.InvalidConfiguration;
    }

    for (cfg.rules.rules, 0..) |*rule, index| {
        const overrides = rule.limits;
        if (overrides.tcp_listen_backlog) |value| {
            if (value < 1 or value > std.math.maxInt(i32)) {
                yaml.setDiag(cfg.gpa, cfg.diag, "rules[{d}].limits.tcpListenBacklog must be between 1 and {d}", .{ index, std.math.maxInt(i32) });
                return error.InvalidConfiguration;
            }
        }
        if (overrides.max_tcp_buffered_bytes) |value| {
            if (value <= 0) {
                yaml.setDiag(cfg.gpa, cfg.diag, "rules[{d}].limits.maxTCPBufferedBytes must be positive", .{index});
                return error.InvalidConfiguration;
            }
        }
        if (overrides.max_udp_associations) |value| {
            if (value < 1 or value > max_udp_associations) {
                yaml.setDiag(cfg.gpa, cfg.diag, "rules[{d}].limits.maxUDPAssociations must be between 1 and {d}", .{ index, max_udp_associations });
                return error.InvalidConfiguration;
            }
        }
    }
}
