//! runtime module: owns the `runtime` directive (root context): worker thread
//! count.

const std = @import("std");
const conf = @import("../conf.zig");
const fw = @import("../module.zig");
const yaml = @import("../yaml.zig");

/// Fixed built-in worker thread count. An omitted key means exactly this
/// value; there is no host-derived selection.
pub const default_worker_threads: i64 = 1;

pub const RuntimeOptions = struct {
    worker_threads: i64 = default_worker_threads,
};

pub const Conf = RuntimeOptions;

pub const module: fw.Module = .{
    .name = "runtime",
    .directives = &directives,
    .create_conf = createConf,
    .validate = validate,
};

const directives = [_]fw.Directive{
    .{ .name = "runtime", .root = true, .set = setRuntime },
};

fn createConf(cycle: *conf.Cycle) error{OutOfMemory}!*anyopaque {
    const c = try cycle.allocator().create(Conf);
    c.* = .{};
    return c;
}

fn setRuntime(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c: *Conf = @ptrCast(@alignCast(slot));
    const map = try yaml.requireMapping(cycle.gpa, cycle.diag, value, "runtime");
    try yaml.checkKeys(cycle.gpa, cycle.diag, map, &.{"workerThreads"}, "runtime");
    if (yaml.mappingGet(map, "workerThreads")) |v| {
        c.worker_threads = try yaml.decodeInt(cycle.gpa, cycle.diag, v, "runtime.workerThreads");
    }
}

fn validate(cycle: *conf.Cycle) yaml.LoadError!void {
    const c = cycle.conf(@This());
    if (c.worker_threads < 1 or c.worker_threads > std.math.maxInt(i32)) {
        yaml.setDiag(cycle.gpa, cycle.diag, "runtime.workerThreads must be between 1 and {d}", .{std.math.maxInt(i32)});
        return error.InvalidConfiguration;
    }
}
