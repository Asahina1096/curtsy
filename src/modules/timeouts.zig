//! timeouts section: owns the `timeouts` key in the root and rule
//! contexts.
//!
//! The root conf holds the full global timeouts; the rule conf holds only
//! overrides (null inherits the global value, like an nginx loc conf merged
//! over the main conf via merge()).

const std = @import("std");
const conf = @import("../conf.zig");
const yaml = @import("../yaml.zig");

pub const max_timeout_seconds: i64 = std.math.maxInt(i64) / 1_000_000_000; // 9223372036

pub const TimeoutConfiguration = struct {
    connect_seconds: i64 = 5,
    tcp_idle_seconds: i64 = 300,
    udp_session_seconds: i64 = 60,
    shutdown_grace_seconds: i64 = 10,
};

/// Per-rule timeout overrides; null inherits the global value.
pub const RuleTimeoutOverrides = struct {
    connect_seconds: ?i64 = null,
    tcp_idle_seconds: ?i64 = null,
    udp_session_seconds: ?i64 = null,
};

pub const Conf = TimeoutConfiguration;
pub const RuleConf = RuleTimeoutOverrides;

/// merge_conf analogue: rule overrides applied over the global timeouts.
pub fn merge(global: TimeoutConfiguration, overrides: RuleTimeoutOverrides) TimeoutConfiguration {
    var timeouts = global;
    if (overrides.connect_seconds) |v| timeouts.connect_seconds = v;
    if (overrides.tcp_idle_seconds) |v| timeouts.tcp_idle_seconds = v;
    if (overrides.udp_session_seconds) |v| timeouts.udp_session_seconds = v;
    return timeouts;
}

pub fn setTimeouts(cfg: *conf.Configuration, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c = &cfg.timeouts;
    const map = try yaml.requireMapping(cfg.gpa, cfg.diag, value, "timeouts");
    try yaml.checkKeys(cfg.gpa, cfg.diag, map, &.{ "connectSeconds", "tcpIdleSeconds", "udpSessionSeconds", "shutdownGraceSeconds" }, "timeouts");
    if (yaml.mappingGet(map, "connectSeconds")) |v| {
        c.connect_seconds = try yaml.decodeInt(cfg.gpa, cfg.diag, v, "timeouts.connectSeconds");
    }
    if (yaml.mappingGet(map, "tcpIdleSeconds")) |v| {
        c.tcp_idle_seconds = try yaml.decodeInt(cfg.gpa, cfg.diag, v, "timeouts.tcpIdleSeconds");
    }
    if (yaml.mappingGet(map, "udpSessionSeconds")) |v| {
        c.udp_session_seconds = try yaml.decodeInt(cfg.gpa, cfg.diag, v, "timeouts.udpSessionSeconds");
    }
    if (yaml.mappingGet(map, "shutdownGraceSeconds")) |v| {
        c.shutdown_grace_seconds = try yaml.decodeInt(cfg.gpa, cfg.diag, v, "timeouts.shutdownGraceSeconds");
    }
}

pub fn setRuleTimeouts(cfg: *conf.Configuration, oc: *RuleConf, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    const c = oc;
    var path_buf: [80]u8 = undefined;
    const timeouts_path = std.fmt.bufPrint(&path_buf, "{s}.timeouts", .{path}) catch "rules.timeouts";
    const map = try yaml.requireMapping(cfg.gpa, cfg.diag, value, timeouts_path);
    try yaml.checkKeys(cfg.gpa, cfg.diag, map, &.{ "connectSeconds", "tcpIdleSeconds", "udpSessionSeconds" }, timeouts_path);
    if (yaml.mappingGet(map, "connectSeconds")) |v| {
        c.connect_seconds = try yaml.decodeInt(cfg.gpa, cfg.diag, v, timeouts_path);
    }
    if (yaml.mappingGet(map, "tcpIdleSeconds")) |v| {
        c.tcp_idle_seconds = try yaml.decodeInt(cfg.gpa, cfg.diag, v, timeouts_path);
    }
    if (yaml.mappingGet(map, "udpSessionSeconds")) |v| {
        c.udp_session_seconds = try yaml.decodeInt(cfg.gpa, cfg.diag, v, timeouts_path);
    }
}

pub fn validate(cfg: *conf.Configuration) yaml.LoadError!void {
    const c = &cfg.timeouts;
    const values = [_]i64{ c.connect_seconds, c.tcp_idle_seconds, c.udp_session_seconds, c.shutdown_grace_seconds };
    for (values) |value| {
        if (value <= 0) {
            yaml.setDiag(cfg.gpa, cfg.diag, "all timeout values must be positive", .{});
            return error.InvalidConfiguration;
        }
    }
    for (values) |value| {
        if (value > max_timeout_seconds) {
            yaml.setDiag(cfg.gpa, cfg.diag, "all timeout values must be no greater than {d} seconds", .{max_timeout_seconds});
            return error.InvalidConfiguration;
        }
    }

    for (cfg.rules.rules, 0..) |*rule, index| {
        const overrides = rule.timeouts;
        const entries = [_]struct { name: []const u8, value: ?i64 }{
            .{ .name = "connectSeconds", .value = overrides.connect_seconds },
            .{ .name = "tcpIdleSeconds", .value = overrides.tcp_idle_seconds },
            .{ .name = "udpSessionSeconds", .value = overrides.udp_session_seconds },
        };
        for (entries) |entry| {
            if (entry.value) |value| {
                if (value <= 0) {
                    yaml.setDiag(cfg.gpa, cfg.diag, "rules[{d}].timeouts.{s} must be positive", .{ index, entry.name });
                    return error.InvalidConfiguration;
                }
                if (value > max_timeout_seconds) {
                    yaml.setDiag(cfg.gpa, cfg.diag, "rules[{d}].timeouts.{s} must be no greater than {d} seconds", .{ index, entry.name, max_timeout_seconds });
                    return error.InvalidConfiguration;
                }
            }
        }
    }
}
