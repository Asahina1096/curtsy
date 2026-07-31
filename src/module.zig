//! Module framework: the curtsy analogue of ngx_module_t / ngx_command_t.
//!
//! Every feature is a module: it declares a `Module` struct with a directive
//! table (`Directive`, the ngx_command_t analogue) plus configuration
//! lifecycle hooks — createConf (defaults), finalize (cross-key decoding
//! after all directives ran) and validate. The engine in conf.zig walks the
//! YAML root mapping and dispatches each key to the owning module's `set`
//! handler (the ngx_conf_handler analogue); unknown keys are rejected by the
//! engine itself.
//!
//! Directives carry a context: `root` (document top level, the nginx main
//! context) or `rule` (inside a `rules[]` entry, the nginx srv/loc context).
//! Modules with rule-context directives implement createRuleConf; the rules
//! module drives nested dispatch and the core module merges rule confs over
//! global confs (the merge_conf analogue).
//!
//! The registry below is the ngx_modules[] analogue: comptime-fixed, with an
//! explicit module index per module used to address conf slots in the cycle.

const std = @import("std");
const conf = @import("conf.zig");
const yaml = @import("yaml.zig");

const core = @import("modules/core.zig");
const rules = @import("modules/rules.zig");
const timeouts = @import("modules/timeouts.zig");
const limits = @import("modules/limits.zig");
const logging = @import("modules/logging.zig");
const runtime = @import("modules/runtime.zig");
const performance = @import("modules/performance.zig");
const tcp = @import("modules/tcp.zig");
const udp = @import("modules/udp.zig");

/// Module conf slot indexes (explicit, like ngx_modules.c ordering).
pub const Index = enum(usize) {
    core = 0,
    rules,
    timeouts,
    limits,
    logging,
    runtime,
    performance,
};

pub const module_count = @typeInfo(Index).@"enum".fields.len;

/// The ngx_modules[] analogue.
pub const modules: [module_count]Module = .{
    core.module,
    rules.module,
    timeouts.module,
    limits.module,
    logging.module,
    runtime.module,
    performance.module,
};

/// Protocol modules registered by the data planes (ngx event module
/// analogue: the core orchestrator spawns listeners through this table
/// instead of hardcoding TCP/UDP branches).
pub const protocol_modules: []const core.ProtocolModule = &.{ tcp.protocol_module, udp.protocol_module };

pub fn protocolModule(protocol: @import("net.zig").ForwardProtocol) *const core.ProtocolModule {
    for (protocol_modules) |*m| {
        if (m.protocol == protocol) return m;
    }
    unreachable;
}

pub const Context = enum { root, rule };

/// One configuration directive (ngx_command_t analogue). `set` receives the
/// owning module's conf slot for the current context plus the raw value
/// node; `path` is the dotted key prefix for diagnostics ("" at the root,
/// "rules[0]" inside a rule).
pub const Directive = struct {
    name: []const u8,
    root: bool = false,
    rule: bool = false,
    set: *const fn (cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void,
};

/// Module lifecycle (ngx_module_t + ngx core module conf hooks).
pub const Module = struct {
    name: []const u8,
    index: Index,
    directives: []const Directive = &.{},
    /// Produce the module's global conf with defaults (create_main_conf).
    create_conf: ?*const fn (cycle: *conf.Cycle) error{OutOfMemory}!*anyopaque = null,
    /// Produce the module's per-rule conf (null for modules without a rule
    /// context); every field starts as "inherit" (create_srv/loc_conf).
    create_rule_conf: ?*const fn (cycle: *conf.Cycle) error{OutOfMemory}!?*anyopaque = null,
    /// Runs after all root directives were dispatched, in registry order.
    /// Cross-key decoding (upstream port defaulting to the listen port, ...)
    /// happens here rather than in set handlers.
    finalize: ?*const fn (cycle: *conf.Cycle) yaml.LoadError!void = null,
    /// Runs after every module finalized (init_main_conf).
    validate: ?*const fn (cycle: *conf.Cycle) yaml.LoadError!void = null,
};

pub const Found = struct {
    module: *const Module,
    directive: *const Directive,
};

/// Find the module directive handling `name` in `context`.
pub fn findDirective(name: []const u8, context: Context) ?Found {
    for (&modules) |*m| {
        for (m.directives) |*d| {
            if (!std.mem.eql(u8, d.name, name)) continue;
            const allowed = switch (context) {
                .root => d.root,
                .rule => d.rule,
            };
            if (allowed) return .{ .module = m, .directive = d };
        }
    }
    return null;
}

test "every directive resolves in its declared context" {
    try std.testing.expect(findDirective("rules", .root) != null);
    try std.testing.expect(findDirective("listen", .root) != null);
    try std.testing.expect(findDirective("listen", .rule) != null);
    try std.testing.expect(findDirective("timeouts", .root) != null);
    try std.testing.expect(findDirective("timeouts", .rule) != null);
    try std.testing.expect(findDirective("rules", .rule) == null);
    try std.testing.expect(findDirective("bogus", .root) == null);
    try std.testing.expect(findDirective("performance", .rule) == null);
}

test "module indexes match the registry order" {
    for (&modules, 0..) |*m, i| {
        try std.testing.expectEqual(i, @intFromEnum(m.index));
    }
    try std.testing.expectEqual(@as(usize, 2), protocol_modules.len);
}
