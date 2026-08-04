//! plugins module: declares runtime shared libraries loaded by the service.

const std = @import("std");
const conf = @import("../conf.zig");
const fw = @import("../module.zig");
const runtime_plugin = @import("../plugin.zig");
const yaml = @import("../yaml.zig");

pub const Conf = struct {
    specs: []const runtime_plugin.Spec = &.{},
};

pub const module: fw.Module = .{
    .name = "plugins",
    .directives = &directives,
    .create_conf = createConf,
    .validate = validate,
};

const directives = [_]fw.Directive{
    .{ .name = "plugins", .root = true, .set = setPlugins },
};

pub fn specs(cycle: *conf.Cycle) []const runtime_plugin.Spec {
    return cycle.conf(@This()).specs;
}

fn createConf(cycle: *conf.Cycle) error{OutOfMemory}!*anyopaque {
    const c = try cycle.allocator().create(Conf);
    c.* = .{};
    return c;
}

fn setPlugins(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c: *Conf = @ptrCast(@alignCast(slot));
    if (value.* != .sequence) return yaml.fail(cycle.gpa, cycle.diag, "plugins: expected a sequence", .{});
    var decoded: std.ArrayList(runtime_plugin.Spec) = .empty;
    for (value.sequence, 0..) |item, i| {
        var path_buf: [64]u8 = undefined;
        const item_path = std.fmt.bufPrint(&path_buf, "plugins[{d}]", .{i}) catch "plugins";
        if (item.* == .scalar) {
            try decoded.append(cycle.allocator(), .{ .path = try yaml.decodeString(cycle.gpa, cycle.diag, item, item_path) });
            continue;
        }
        const map = try yaml.requireMapping(cycle.gpa, cycle.diag, item, item_path);
        try yaml.checkKeys(cycle.gpa, cycle.diag, map, &.{ "path", "config" }, item_path);
        const path_value = yaml.mappingGet(map, "path") orelse
            return yaml.fail(cycle.gpa, cycle.diag, "missing required key: {s}.path", .{item_path});
        const plugin_path = try yaml.decodeString(cycle.gpa, cycle.diag, path_value, item_path);
        var config_entries: []const runtime_plugin.ConfigEntry = &.{};
        if (yaml.mappingGet(map, "config")) |config_value| {
            const config_path = std.fmt.bufPrint(&path_buf, "plugins[{d}].config", .{i}) catch "plugins.config";
            const config_map = try yaml.requireMapping(cycle.gpa, cycle.diag, config_value, config_path);
            var entries: std.ArrayList(runtime_plugin.ConfigEntry) = .empty;
            for (config_map) |entry| {
                for (entries.items) |previous| {
                    if (std.mem.eql(u8, previous.key, entry.key)) {
                        return yaml.fail(cycle.gpa, cycle.diag, "{s}: duplicate key '{s}'", .{ config_path, entry.key });
                    }
                }
                try entries.append(cycle.allocator(), .{
                    .key = entry.key,
                    .value = try yaml.decodeString(cycle.gpa, cycle.diag, entry.value, config_path),
                });
            }
            config_entries = try entries.toOwnedSlice(cycle.allocator());
        }
        try decoded.append(cycle.allocator(), .{ .path = plugin_path, .config = config_entries });
    }
    c.specs = try decoded.toOwnedSlice(cycle.allocator());
}

fn validate(cycle: *conf.Cycle) yaml.LoadError!void {
    const configured = cycle.conf(@This()).specs;
    for (configured, 0..) |spec, i| {
        if (!std.fs.path.isAbsolute(spec.path)) {
            return yaml.fail(cycle.gpa, cycle.diag, "plugins[{d}]: path must be absolute", .{i});
        }
        for (configured[0..i]) |previous| {
            if (std.mem.eql(u8, previous.path, spec.path)) {
                return yaml.fail(cycle.gpa, cycle.diag, "plugins[{d}]: duplicate path '{s}'", .{ i, spec.path });
            }
        }
    }
}

test "plugins defaults empty and decodes absolute paths" {
    var diag = conf.Diagnostics{};
    defer if (diag.message) |message| std.testing.allocator.free(message);
    var cycle = try conf.loadYaml(std.testing.allocator,
        \\listen: { port: 9000 }
        \\upstream: { host: "127.0.0.1" }
        \\plugins: ["/opt/curtsy/one.so", "/opt/curtsy/two.so"]
    , &diag);
    defer cycle.deinit();
    try std.testing.expectEqual(@as(usize, 2), specs(&cycle).len);
}

test "plugins decode namespaced scalar configuration" {
    var diag = conf.Diagnostics{};
    defer if (diag.message) |message| std.testing.allocator.free(message);
    var cycle = try conf.loadYaml(std.testing.allocator,
        \\listen: { port: 9000 }
        \\upstream: { host: "127.0.0.1" }
        \\plugins:
        \\  - path: "/opt/curtsy/hello.so"
        \\    config: { message: "hello", threshold: 3 }
    , &diag);
    defer cycle.deinit();
    const configured = specs(&cycle);
    try std.testing.expectEqual(@as(usize, 1), configured.len);
    try std.testing.expectEqualStrings("message", configured[0].config[0].key);
    try std.testing.expectEqualStrings("hello", configured[0].config[0].value);
    try std.testing.expectEqualStrings("3", configured[0].config[1].value);
}

test "plugins reject relative and duplicate paths" {
    const cases = [_][]const u8{
        "listen: { port: 9000 }\nupstream: { host: a }\nplugins: [relative.so]\n",
        "listen: { port: 9000 }\nupstream: { host: a }\nplugins: [/a.so, /a.so]\n",
    };
    for (cases) |text| {
        var diag = conf.Diagnostics{};
        defer if (diag.message) |message| std.testing.allocator.free(message);
        const result = conf.loadYaml(std.testing.allocator, text, &diag);
        if (result) |cycle_value| {
            var cycle = cycle_value;
            cycle.deinit();
            return error.TestExpectedInvalidPlugins;
        } else |_| {}
    }
}
