//! runtime section: owns the `runtime` key (root context): worker thread
//! count.

const std = @import("std");
const conf = @import("../conf.zig");
const yaml = @import("../yaml.zig");

/// Fixed built-in worker thread count. An omitted key means exactly this
/// value; there is no host-derived selection.
pub const default_worker_threads: i64 = 1;

pub const RuntimeOptions = struct {
    worker_threads: i64 = default_worker_threads,
};

pub const Conf = RuntimeOptions;

pub fn setRuntime(cfg: *conf.Configuration, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c = &cfg.runtime;
    const map = try yaml.requireMapping(cfg.gpa, cfg.diag, value, "runtime");
    try yaml.checkKeys(cfg.gpa, cfg.diag, map, &.{"workerThreads"}, "runtime");
    if (yaml.mappingGet(map, "workerThreads")) |v| {
        c.worker_threads = try yaml.decodeInt(cfg.gpa, cfg.diag, v, "runtime.workerThreads");
    }
}

pub fn validate(cfg: *conf.Configuration) yaml.LoadError!void {
    const c = &cfg.runtime;
    if (c.worker_threads < 1 or c.worker_threads > std.math.maxInt(i32)) {
        yaml.setDiag(cfg.gpa, cfg.diag, "runtime.workerThreads must be between 1 and {d}", .{std.math.maxInt(i32)});
        return error.InvalidConfiguration;
    }
}
