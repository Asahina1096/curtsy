//! Configuration loading.
//!
//! The YAML document is decoded straight into a `Configuration` value: one
//! explicit pass over the top level and one per `rules[]` entry. Every section
//! is owned by the module that implements it.
//!
//! There is deliberately no module registry, no directive table, no conf slot
//! and no lifecycle dispatch. Adding a key means editing `RootKey`/`parseRoot`
//! (or `RuleKey`/`parseRule`) and the owning module — there is no extension
//! point for an out-of-tree module to register itself against.

const std = @import("std");
const Allocator = std.mem.Allocator;
const yaml = @import("yaml.zig");

pub const core = @import("modules/core.zig");
pub const rules = @import("modules/rules.zig");
pub const timeouts = @import("modules/timeouts.zig");
pub const limits = @import("modules/limits.zig");
pub const logging = @import("modules/logging.zig");
pub const runtime = @import("modules/runtime.zig");
pub const performance = @import("modules/performance.zig");

pub const Diagnostics = yaml.Diagnostics;
pub const LoadError = yaml.LoadError;

/// Upper bound on a configuration document read from disk.
const max_config_bytes = 16 * 1_024 * 1_024;

/// Keys accepted at the document top level.
const RootKey = enum { version, protocols, listen, upstream, rules, timeouts, limits, logging, runtime, performance };

/// Keys accepted inside one `rules[]` entry.
const RuleKey = enum { listen, upstreams, protocols, balance, timeouts, limits };

/// A fully parsed configuration document. Every allocation is owned by
/// `arena`; `diag` points at caller-owned storage for error reporting.
pub const Configuration = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    diag: *Diagnostics,

    /// True when the document used the `rules:` form.
    rules_mode: bool = false,

    core: core.Conf = .{},
    rules: rules.Conf = .{},
    timeouts: timeouts.Conf = .{},
    limits: limits.Conf = .{},
    logging: logging.Conf = .{},
    runtime: runtime.Conf = .{},
    performance: performance.Conf = .{},

    pub fn allocator(self: *Configuration) Allocator {
        return self.arena.allocator();
    }

    pub fn deinit(self: *Configuration) void {
        self.arena.deinit();
    }
};

/// Read and decode the configuration document at `path`.
pub fn loadFile(gpa: Allocator, path: []const u8, diag: *Diagnostics) LoadError!Configuration {
    const text = yaml.readFileAlloc(gpa, path, max_config_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            yaml.setDiag(gpa, diag, "unable to read configuration file: {s}", .{path});
            return error.ReadFailed;
        },
    };
    defer gpa.free(text);
    return loadYaml(gpa, text, diag);
}

/// Decode an in-memory configuration document (also the backend of the CLI
/// endpoint flags, which render to YAML first).
pub fn loadYaml(gpa: Allocator, text: []const u8, diag: *Diagnostics) LoadError!Configuration {
    var cfg = Configuration{
        .gpa = gpa,
        .arena = std.heap.ArenaAllocator.init(gpa),
        .diag = diag,
    };
    errdefer cfg.deinit();

    // The YAML parser keeps scalar strings as slices of the input document
    // rather than copying every token, so the Value tree borrows that buffer.
    // Copy the document into the arena first: `loadFile` frees the file bytes
    // as soon as the configuration is parsed, and every decoded string
    // (listen/upstream hosts, logging level, ...) must stay valid for as long
    // as the configuration lives.
    const owned_text = try cfg.allocator().dupe(u8, text);
    const root = try yaml.parse(cfg.allocator(), gpa, owned_text, diag);
    if (root.* != .mapping) {
        yaml.setDiag(gpa, diag, "YAML root must be a mapping", .{});
        return error.InvalidConfiguration;
    }
    try parseRoot(&cfg, root.mapping);
    try finalize(&cfg);
    try validate(&cfg);
    return cfg;
}

fn contains(seen: []const []const u8, key: []const u8) bool {
    for (seen) |entry| {
        if (std.mem.eql(u8, entry, key)) return true;
    }
    return false;
}

/// Decode the document top level. The first occurrence of a duplicated key
/// wins, matching the rest of the configuration surface.
fn parseRoot(cfg: *Configuration, mapping: []const yaml.Entry) LoadError!void {
    var seen: std.ArrayList([]const u8) = .empty;
    for (mapping) |entry| {
        const key = std.meta.stringToEnum(RootKey, entry.key) orelse
            return yaml.fail(cfg.gpa, cfg.diag, "unknown configuration key: {s}", .{entry.key});
        if (contains(seen.items, entry.key)) continue;
        try seen.append(cfg.allocator(), entry.key);

        switch (key) {
            .version => cfg.core.version = try yaml.decodeInt(cfg.gpa, cfg.diag, entry.value, "version"),
            .protocols => try core.setProtocols(cfg, entry.value, "protocols"),
            .listen => {
                if (cfg.rules_mode) return yaml.fail(cfg.gpa, cfg.diag, "configuration cannot mix listen/upstream with rules", .{});
                cfg.core.listen_node = entry.value;
            },
            .upstream => {
                if (cfg.rules_mode) return yaml.fail(cfg.gpa, cfg.diag, "configuration cannot mix listen/upstream with rules", .{});
                cfg.core.upstream_node = entry.value;
            },
            .rules => {
                if (cfg.core.listen_node != null or cfg.core.upstream_node != null) {
                    return yaml.fail(cfg.gpa, cfg.diag, "configuration cannot mix listen/upstream with rules", .{});
                }
                cfg.rules_mode = true;
                cfg.rules.rules_node = entry.value;
            },
            .timeouts => try timeouts.setTimeouts(cfg, entry.value, "timeouts"),
            .limits => try limits.setLimits(cfg, entry.value, "limits"),
            .logging => try logging.setLogging(cfg, entry.value, "logging"),
            .runtime => try runtime.setRuntime(cfg, entry.value, "runtime"),
            .performance => try performance.setPerformance(cfg, entry.value, "performance"),
        }
    }
}

/// Decode one `rules[]` entry. The caller (`modules/rules.zig`) requires the
/// `listen`/`upstreams` keys and finishes the entry.
pub fn parseRule(
    cfg: *Configuration,
    rule: *rules.RuleConf,
    timeout_overrides: *timeouts.RuleConf,
    limit_overrides: *limits.RuleConf,
    mapping: []const yaml.Entry,
    path: []const u8,
) LoadError!void {
    var seen: std.ArrayList([]const u8) = .empty;
    for (mapping) |entry| {
        const key = std.meta.stringToEnum(RuleKey, entry.key) orelse
            return yaml.fail(cfg.gpa, cfg.diag, "unknown configuration key: {s}.{s}", .{ path, entry.key });
        if (contains(seen.items, entry.key)) continue;
        try seen.append(cfg.allocator(), entry.key);

        switch (key) {
            .listen => try rules.setRuleListen(cfg, rule, entry.value, path),
            .upstreams => try rules.setRuleUpstreams(cfg, rule, entry.value, path),
            .protocols => try rules.setRuleProtocols(cfg, rule, entry.value, path),
            .balance => try rules.setRuleBalance(cfg, rule, entry.value, path),
            .timeouts => try timeouts.setRuleTimeouts(cfg, timeout_overrides, entry.value, path),
            .limits => try limits.setRuleLimits(cfg, limit_overrides, entry.value, path),
        }
    }
}

/// Cross-key decoding, in the order the sections depend on each other.
fn finalize(cfg: *Configuration) LoadError!void {
    try core.finalize(cfg);
    try rules.finalize(cfg);
}

fn validate(cfg: *Configuration) LoadError!void {
    try core.validate(cfg);
    try rules.validate(cfg);
    try timeouts.validate(cfg);
    try limits.validate(cfg);
    try logging.validate(cfg);
    try runtime.validate(cfg);
    try performance.validate(cfg);
}

/// Test helper: the document must be rejected with `expected` as the message.
pub fn expectLoadFailure(text: []const u8, expected: []const u8) !void {
    const gpa = std.testing.allocator;
    var diag = Diagnostics{};
    defer if (diag.message) |message| gpa.free(message);
    try std.testing.expectError(error.InvalidConfiguration, loadYaml(gpa, text, &diag));
    const message = diag.message orelse return error.TestExpectedError;
    try std.testing.expectEqualStrings(expected, message);
}

test "unknown keys are rejected in both contexts" {
    try expectLoadFailure("bogus: 1\n", "unknown configuration key: bogus");
    try expectLoadFailure(
        "rules:\n  - listen: 1.2.3.4:80\n    upstreams: [5.6.7.8:80]\n    bogus: 1\n",
        "unknown configuration key: rules[0].bogus",
    );
}

test "the document root must be a mapping" {
    try expectLoadFailure("- 1\n- 2\n", "YAML root must be a mapping");
}

test "listen/upstream cannot be mixed with rules" {
    const expected = "configuration cannot mix listen/upstream with rules";
    try expectLoadFailure("listen: 1.2.3.4:80\nrules: []\n", expected);
    try expectLoadFailure("rules: []\nupstream: 5.6.7.8:80\n", expected);
}

test "the first occurrence of a duplicate key wins" {
    const gpa = std.testing.allocator;
    var diag = Diagnostics{};
    defer if (diag.message) |message| gpa.free(message);

    var cfg = try loadYaml(gpa,
        \\listen: { port: 9000 }
        \\listen: { port: 9001 }
        \\upstream: { host: "localhost" }
        \\
    , &diag);
    defer cfg.deinit();
    try std.testing.expectEqual(@as(u16, 9000), cfg.core.listen.?.port);
    try std.testing.expectEqualStrings("localhost", cfg.core.upstream.?.host);
}
