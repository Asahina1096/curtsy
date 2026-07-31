//! runtime module: owns the `runtime` directive (root context): worker
//! thread count, tuning daemon toggle and interval.

const std = @import("std");
const conf = @import("../conf.zig");
const fw = @import("../module.zig");
const yaml = @import("../yaml.zig");

pub const RuntimeOptions = struct {
    worker_threads: i64 = 0,
    tuning_daemon: bool = true,
    tuning_interval_seconds: i64 = 5,
};

pub const Conf = RuntimeOptions;

pub const module: fw.Module = .{
    .name = "runtime",
    .index = .runtime,
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
    try yaml.checkKeys(cycle.gpa, cycle.diag, map, &.{ "workerThreads", "tuningDaemon", "tuningIntervalSeconds" }, "runtime");
    const workers = try yaml.decodeAutoTunedInt(cycle.gpa, cycle.diag, map, "workerThreads", "runtime.workerThreads", 0);
    c.worker_threads = workers.value;
    if (yaml.mappingGet(map, "tuningDaemon")) |v| {
        c.tuning_daemon = try yaml.decodeBool(cycle.gpa, cycle.diag, v, "runtime.tuningDaemon");
    }
    if (yaml.mappingGet(map, "tuningIntervalSeconds")) |v| {
        c.tuning_interval_seconds = try yaml.decodeInt(cycle.gpa, cycle.diag, v, "runtime.tuningIntervalSeconds");
    }
}

fn validate(cycle: *conf.Cycle) yaml.LoadError!void {
    const c = cycle.conf(@This());
    if (c.worker_threads < 0) {
        yaml.setDiag(cycle.gpa, cycle.diag, "runtime.workerThreads must be zero for auto or positive", .{});
        return error.InvalidConfiguration;
    }
    if (c.tuning_interval_seconds <= 0) {
        yaml.setDiag(cycle.gpa, cycle.diag, "runtime.tuningIntervalSeconds must be positive", .{});
        return error.InvalidConfiguration;
    }
}
