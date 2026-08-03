//! logging module: owns the `logging` directive (root context).
//!
//! The LogStore mechanism lives in log.zig; this module only parses and
//! validates the configured level, like an nginx module owning its
//! error_log directive.

const std = @import("std");
const conf = @import("../conf.zig");
const fw = @import("../module.zig");
const yaml = @import("../yaml.zig");

pub const LogConfiguration = struct {
    level: []const u8 = "info",
};

pub const Conf = LogConfiguration;

pub const module: fw.Module = .{
    .name = "logging",
    .directives = &directives,
    .create_conf = createConf,
    .validate = validate,
};

const directives = [_]fw.Directive{
    .{ .name = "logging", .root = true, .set = setLogging },
};

fn createConf(cycle: *conf.Cycle) error{OutOfMemory}!*anyopaque {
    const c = try cycle.allocator().create(Conf);
    c.* = .{};
    return c;
}

fn setLogging(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c: *Conf = @ptrCast(@alignCast(slot));
    const map = try yaml.requireMapping(cycle.gpa, cycle.diag, value, "logging");
    try yaml.checkKeys(cycle.gpa, cycle.diag, map, &.{"level"}, "logging");
    if (yaml.mappingGet(map, "level")) |v| {
        c.level = try yaml.decodeString(cycle.gpa, cycle.diag, v, "logging.level");
    }
}

fn validate(cycle: *conf.Cycle) yaml.LoadError!void {
    if (!isValidLogLevel(cycle.conf(@This()).level)) {
        yaml.setDiag(cycle.gpa, cycle.diag, "logging.level is invalid", .{});
        return error.InvalidConfiguration;
    }
}

pub fn isValidLogLevel(level: []const u8) bool {
    var buf: [16]u8 = undefined;
    if (level.len > buf.len) return false;
    const lower = std.ascii.lowerString(&buf, level);
    const valid = [_][]const u8{ "trace", "debug", "info", "notice", "warning", "error", "critical" };
    for (valid) |name| {
        if (std.mem.eql(u8, name, lower)) return true;
    }
    return false;
}
