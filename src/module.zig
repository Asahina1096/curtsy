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
//! The registry below is the ngx_modules[] analogue: comptime-fixed, derived
//! from the `module_types` list of module implementation types. Each type
//! yields a generated ModuleRef carrying its descriptor pointer and conf slot
//! index, so the module list order is the single source of truth for slot
//! addressing in the cycle.

const std = @import("std");
const conf = @import("conf.zig");
const yaml = @import("yaml.zig");

const core = @import("modules/core.zig");
const plugins = @import("modules/plugins.zig");
const rules = @import("modules/rules.zig");
const timeouts = @import("modules/timeouts.zig");
const limits = @import("modules/limits.zig");
const logging = @import("modules/logging.zig");
const runtime = @import("modules/runtime.zig");
const performance = @import("modules/performance.zig");
const cli = @import("modules/cli.zig");
const tcp = @import("modules/tcp.zig");
const udp = @import("modules/udp.zig");

/// Registry order (single source of truth): one module implementation type
/// per entry. Adding or reordering a registered module only requires editing
/// this list; the descriptor array, slot indexes and directive lookup follow
/// from it automatically.
pub const module_types = [_]type{
    core,
    plugins,
    rules,
    timeouts,
    limits,
    logging,
    runtime,
    performance,
    cli,
};

pub const module_count = module_types.len;

/// Resolve a registered module type's conf slot index at comptime. Type-safe
/// `Cycle.conf(M)` / `Cycle.ruleConf(..., M)` call this instead of carrying a
/// manually maintained per-module index.
pub fn moduleSlot(comptime M: type) usize {
    return comptime blk: {
        for (module_types, 0..) |T, i| {
            if (T == M) break :blk i;
        }
        @compileError("module type " ++ @typeName(M) ++ " is not registered in module_types");
    };
}

/// One generated registry entry: the module descriptor plus its conf slot
/// index. Directive lookup and lifecycle iteration walk this reference array
/// instead of copying module descriptors.
pub const ModuleRef = struct {
    module: *const Module,
    slot: usize,
};

/// The ngx_modules[] analogue: one generated reference per registered module
/// in registry order. `slot` addresses the module's conf slots in a cycle.
pub const modules: [module_count]ModuleRef = blk: {
    var refs: [module_count]ModuleRef = undefined;
    for (module_types, 0..) |M, i| {
        refs[i] = .{ .module = &M.module, .slot = i };
    }
    break :blk refs;
};

/// Protocol modules registered by the data planes (ngx event module
/// analogue: the core orchestrator combines these built-ins with the runtime
/// plugin registry and spawns listeners by protocol name).
pub const protocol_modules: []const core.ProtocolModule = &.{ tcp.protocol_module, udp.protocol_module };

pub fn protocolModule(protocol: @import("net.zig").ForwardProtocol) ?core.ProtocolModule {
    if (core.dynamicProtocolModule(protocol)) |dynamic| return dynamic;
    for (protocol_modules) |*m| {
        if (m.protocol.eql(protocol)) return m.*;
    }
    return null;
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
    module: *const ModuleRef,
    directive: *const Directive,
};

/// Find the module directive handling `name` in `context`.
pub fn findDirective(name: []const u8, context: Context) ?Found {
    for (&modules) |*ref| {
        for (ref.module.directives) |*d| {
            if (!std.mem.eql(u8, d.name, name)) continue;
            const allowed = switch (context) {
                .root => d.root,
                .rule => d.rule,
            };
            if (allowed) return .{ .module = ref, .directive = d };
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

test "generated module references follow registry order" {
    inline for (module_types, 0..) |M, i| {
        try std.testing.expectEqual(@as(usize, i), modules[i].slot);
        try std.testing.expectEqual(&M.module, modules[i].module);
    }
    try std.testing.expectEqual(@as(usize, module_count), modules.len);
    try std.testing.expectEqual(@as(usize, 2), protocol_modules.len);
}

test "moduleSlot resolves registered module types" {
    inline for (module_types, 0..) |M, i| {
        try std.testing.expectEqual(@as(usize, i), moduleSlot(M));
    }
}
