//! logging section: owns the `logging` key (root context).
//!
//! The LogStore mechanism lives in log.zig; this module only parses and
//! validates the configured level, like an nginx module owning its
//! error_log directive.

const conf = @import("../conf.zig");
const log = @import("../log.zig");
const yaml = @import("../yaml.zig");

pub const LogConfiguration = struct {
    level: []const u8 = "info",
};

pub const Conf = LogConfiguration;

pub fn setLogging(cfg: *conf.Configuration, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c = &cfg.logging;
    const map = try yaml.requireMapping(cfg.gpa, cfg.diag, value, "logging");
    try yaml.checkKeys(cfg.gpa, cfg.diag, map, &.{"level"}, "logging");
    if (yaml.mappingGet(map, "level")) |v| {
        c.level = try yaml.decodeString(cfg.gpa, cfg.diag, v, "logging.level");
    }
}

pub fn validate(cfg: *conf.Configuration) yaml.LoadError!void {
    // The level vocabulary lives in log.Level; fromString is the single
    // case-insensitive parser for it.
    if (log.Level.fromString(cfg.logging.level) == null) {
        yaml.setDiag(cfg.gpa, cfg.diag, "logging.level is invalid", .{});
        return error.InvalidConfiguration;
    }
}
