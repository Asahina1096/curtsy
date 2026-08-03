//! Configuration engine: the ngx_conf_file analogue.
//!
//! Runs one configuration cycle: parse the YAML document, let every module
//! create its default conf, dispatch each root mapping key to the owning
//! module directive, then run finalize (cross-key decoding) and validate
//! hooks in registry order. The result is a Cycle holding one conf slot per
//! module plus the per-rule conf bundles created by nested rule dispatch.
//!
//! Reloads run a fresh cycle and the core module diffs it against the live
//! one; a retired cycle stays alive until no listener references its arena.

const std = @import("std");
const module = @import("module.zig");
const net = @import("net.zig");
const yaml = @import("yaml.zig");

const Allocator = std.mem.Allocator;

pub const Diagnostics = yaml.Diagnostics;
pub const LoadError = yaml.LoadError;

/// Per-rule conf slots: one entry per module, null for modules without a
/// rule context. `seen` implements first-occurrence-wins for duplicate keys,
/// matching the legacy mappingGet semantics.
pub const RuleBundle = struct {
    index: usize,
    slots: [module.module_count]?*anyopaque,
    seen: std.ArrayList([]const u8) = .empty,
};

pub const Cycle = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    diag: *Diagnostics,
    confs: [module.module_count]?*anyopaque,
    rule_bundles: std.ArrayList(RuleBundle) = .empty,
    /// Set when the document uses the top-level `rules` directive.
    rules_mode: bool = false,
    current_rule: ?usize = null,
    seen_root: std.ArrayList([]const u8) = .empty,

    pub fn allocator(self: *Cycle) Allocator {
        return self.arena.allocator();
    }

    pub fn deinit(self: *Cycle) void {
        self.arena.deinit();
    }

    /// Typed access to a module's global conf (module must exist and have
    /// run createConf).
    pub fn conf(self: *Cycle, comptime M: type) *M.Conf {
        const slot = self.confs[module.moduleSlot(M)] orelse unreachable;
        return @ptrCast(@alignCast(slot));
    }

    /// Typed access to a module's conf inside a rule bundle; null when the
    /// module has no rule context.
    pub fn ruleConf(self: *Cycle, bundle: *const RuleBundle, comptime M: type) ?*M.RuleConf {
        _ = self;
        const slot = bundle.slots[module.moduleSlot(M)] orelse return null;
        return @ptrCast(@alignCast(slot));
    }

    fn seenRoot(self: *const Cycle, name: []const u8) bool {
        for (self.seen_root.items) |seen| {
            if (std.mem.eql(u8, seen, name)) return true;
        }
        return false;
    }
};

/// Load and fully validate a configuration file into a fresh cycle.
pub fn loadFile(gpa: Allocator, path: []const u8, diag: *Diagnostics) LoadError!Cycle {
    const text = yaml.readFileAlloc(gpa, path, 16 * 1_024 * 1_024) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            yaml.setDiag(gpa, diag, "unable to read configuration file: {s}", .{path});
            return error.ReadFailed;
        },
    };
    defer gpa.free(text);
    return loadYaml(gpa, text, diag);
}

/// Load and fully validate a configuration from YAML text.
pub fn loadYaml(gpa: Allocator, text: []const u8, diag: *Diagnostics) LoadError!Cycle {
    var cycle = Cycle{
        .gpa = gpa,
        .arena = std.heap.ArenaAllocator.init(gpa),
        .diag = diag,
        .confs = .{null} ** module.module_count,
    };
    errdefer cycle.deinit();
    const arena = cycle.arena.allocator();

    const root = try yaml.parse(arena, gpa, text, diag);
    if (root.* != .mapping) {
        yaml.setDiag(gpa, diag, "YAML root must be a mapping", .{});
        return error.InvalidConfiguration;
    }

    // createConf: every module installs its defaults before any directive
    // runs, so set handlers only touch explicitly configured values.
    for (&module.modules) |*ref| {
        if (ref.module.create_conf) |create| {
            cycle.confs[ref.slot] = try create(&cycle);
        }
    }

    try dispatchMapping(&cycle, root.mapping, .root, "");

    if (cycle.rules_mode and (cycle.seenRoot("listen") or cycle.seenRoot("upstream"))) {
        yaml.setDiag(gpa, diag, "configuration cannot mix listen/upstream with rules", .{});
        return error.InvalidConfiguration;
    }

    for (&module.modules) |*ref| {
        if (ref.module.finalize) |finalize| try finalize(&cycle);
    }
    for (&module.modules) |*ref| {
        if (ref.module.validate) |validate| try validate(&cycle);
    }
    return cycle;
}

/// Dispatch every entry of a mapping to the owning module directive in the
/// given context. Unknown keys are rejected with dotted paths. Modules whose
/// directives introduce a nested scope (rules) call this recursively through
/// beginRule/dispatchMapping/endRule.
pub fn dispatchMapping(cycle: *Cycle, mapping: []const yaml.Entry, context: module.Context, path: []const u8) LoadError!void {
    const gpa = cycle.gpa;
    const diag = cycle.diag;
    const arena = cycle.allocator();

    for (mapping) |entry| {
        const found = module.findDirective(entry.key, context) orelse {
            if (path.len == 0) {
                yaml.setDiag(gpa, diag, "unknown configuration key: {s}", .{entry.key});
            } else {
                yaml.setDiag(gpa, diag, "unknown configuration key: {s}.{s}", .{ path, entry.key });
            }
            return error.InvalidConfiguration;
        };

        const slot: *anyopaque = switch (context) {
            .root => blk: {
                // First occurrence wins (legacy mappingGet semantics).
                if (cycle.seenRoot(entry.key)) break :blk null;
                try cycle.seen_root.append(arena, entry.key);
                break :blk cycle.confs[found.module.slot].?;
            },
            .rule => blk: {
                const bundle = &cycle.rule_bundles.items[cycle.current_rule.?];
                for (bundle.seen.items) |seen| {
                    if (std.mem.eql(u8, seen, entry.key)) break :blk null;
                }
                try bundle.seen.append(arena, entry.key);
                break :blk bundle.slots[found.module.slot].?;
            },
        } orelse continue;

        try found.directive.set(cycle, slot, entry.value, path);
    }
}

/// Open a nested rule scope: creates a rule bundle with one conf slot per
/// module that has a rule context. The rules module calls this before
/// dispatching a rule's mapping.
pub fn beginRule(cycle: *Cycle, index: usize) error{OutOfMemory}!void {
    var bundle = RuleBundle{
        .index = index,
        .slots = .{null} ** module.module_count,
    };
    for (&module.modules) |*ref| {
        if (ref.module.create_rule_conf) |create| {
            bundle.slots[ref.slot] = try create(cycle);
        }
    }
    try cycle.rule_bundles.append(cycle.allocator(), bundle);
    cycle.current_rule = cycle.rule_bundles.items.len - 1;
}

pub fn endRule(cycle: *Cycle) void {
    cycle.current_rule = null;
}

/// Mark the cycle as rules-mode; called by the rules directive handler.
pub fn enterRulesMode(cycle: *Cycle) void {
    cycle.rules_mode = true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const core = @import("modules/core.zig");

fn loadForTest(text: []const u8) !Cycle {
    var diag = Diagnostics{};
    return loadYaml(testing.allocator, text, &diag) catch |err| {
        if (diag.message) |message| {
            std.debug.print("unexpected load failure: {s}\n", .{message});
            testing.allocator.free(message);
        }
        return err;
    };
}

pub fn expectLoadFailure(text: []const u8, expected_message: ?[]const u8) !void {
    var diag = Diagnostics{};
    const result = loadYaml(testing.allocator, text, &diag);
    if (result) |cycle_value| {
        var cycle = cycle_value;
        cycle.deinit();
        return error.TestExpectedFailureButLoaded;
    } else |_| {}
    if (expected_message) |expected| {
        try testing.expectEqualStrings(expected, diag.message.?);
    }
    if (diag.message) |message| testing.allocator.free(message);
}

test "unknown keys are rejected by the engine at the root" {
    try expectLoadFailure(
        \\listen: { port: 9000 }
        \\upstream: { host: "127.0.0.1", port: 9001 }
        \\bogus: true
        \\
    , "unknown configuration key: bogus");
}

test "rejects rules mixed with legacy endpoints" {
    try expectLoadFailure(
        \\listen: { port: 9000 }
        \\rules:
        \\  - listen: { port: 9001 }
        \\    upstreams: [ { host: "a" } ]
        \\
    , "configuration cannot mix listen/upstream with rules");

    try expectLoadFailure(
        \\rules:
        \\  - listen: { port: 9001 }
        \\    upstreams: [ { host: "a" } ]
        \\upstream: { host: "b", port: 9001 }
        \\
    , "configuration cannot mix listen/upstream with rules");
}

test "first occurrence of a duplicate root key wins" {
    var cycle = try loadForTest(
        \\listen: { port: 9000 }
        \\listen: { port: 9001 }
        \\upstream: { host: "localhost" }
        \\
    );
    defer cycle.deinit();
    try testing.expectEqual(9_000, cycle.conf(core).listen.?.port);
}

test "YAML root must be a mapping" {
    try expectLoadFailure("- tcp\n- udp\n", "YAML root must be a mapping");
}
