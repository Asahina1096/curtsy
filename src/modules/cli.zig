//! cli module: command-line running mode (optional, disabled unless used).
//!
//! Curtsy normally reads one YAML file; this module is the ngx-analogue
//! counterpart for running entirely from the command line. It parses a
//! shorthand endpoint/rule syntax (`--listen :9000 --upstream example.com`
//! for a single rule, repeatable `--rule "listen=...,upstreams=..."` for
//! multiple rules), renders the result into a `rules:` YAML document and
//! feeds it through the normal engine (conf.loadYaml). CLI rules are decoded,
//! validated, resolved and hot-reloaded by exactly the same code paths as the
//! multi-upstream rules module, so the running mode inherits its defaults,
//! shorthand (upstream port defaults to the listen port) and transactional
//! SIGHUP reload. Without any CLI endpoint flags the module stays inert and
//! curtsy behaves exactly as before.
//!
//! Shorthand grammar:
//!   ENDPOINT := [HOST][:PORT]            ":9000" / "9000" -> host "*"
//!                                         "[::1]:9000" IPv6 literals are
//!                                         bracketed; a bare HOST leaves the
//!                                         port unset (defaults to the listen
//!                                         port for upstreams).
//!   RULE := key=value,key=value,...
//!     listen=ENDPOINT                    required, port required
//!     upstreams=UP[,UP...]               required; UP := ENDPOINT[/weight=N]
//!     protocols=NAME[,NAME...]           optional
//!     balance=NAME                       optional
//!
//! The Configuration is arena-owned (like conf.Cycle): every parsed string is
//! stored in an embedded arena and released by deinit.

const std = @import("std");
const conf = @import("../conf.zig");
const fw = @import("../module.zig");
const net = @import("../net.zig");
const upstream = @import("upstream.zig");
const yaml = @import("../yaml.zig");

const Allocator = std.mem.Allocator;

/// One parsed upstream entry. A null port renders no `port:` key, so the
/// engine defaults it to the rule listen port.
pub const CliUpstream = struct {
    host: []const u8,
    port: ?i64 = null,
    weight: i64 = 1,
};

/// One parsed rule. `listen_host` defaults to "*" when the shorthand omitted
/// the host. Protocol names and the balance name are kept as text and
/// validated by the engine during dispatch (plus early checks here).
pub const CliRule = struct {
    listen_host: []const u8,
    listen_port: i64,
    upstreams: []CliUpstream,
    protocols: ?[]const []const u8 = null,
    balance: ?[]const u8 = null,
};

/// The parsed CLI configuration: always rules-mode with 1..N rules.
pub const Configuration = struct {
    rules: []CliRule,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Configuration) void {
        self.arena.deinit();
    }
};

/// Register the module in fw.module_types. It declares no directives and no
/// conf hooks: the module is inert unless the command line actually carries
/// CLI endpoint flags, which is what "disabled by default" means here.
pub const module: fw.Module = .{
    .name = "cli",
};

/// Parse the CLI endpoint flags into a Configuration. Returns null when no
/// CLI endpoint flag was given at all. On invalid shorthand the message is
/// recorded in `diag` and error.InvalidConfiguration is returned.
pub fn parseFlags(
    gpa: Allocator,
    listen: ?[]const u8,
    upstream_flag: ?[]const u8,
    rule_specs: []const []const u8,
    protocols: ?[]const u8,
    balance: ?[]const u8,
    diag: *conf.Diagnostics,
) error{ OutOfMemory, InvalidConfiguration }!?Configuration {
    if (listen == null and upstream_flag == null and rule_specs.len == 0 and
        protocols == null and balance == null) return null;

    var config = Configuration{
        .rules = &.{},
        .arena = std.heap.ArenaAllocator.init(gpa),
    };
    errdefer config.deinit();
    const alloc = config.arena.allocator();

    // Multi-rule mode: one spec per --rule flag.
    if (rule_specs.len > 0) {
        if (listen != null or upstream_flag != null or protocols != null or balance != null) {
            return yaml.fail(gpa, diag, "--rule cannot be combined with --listen/--upstream/--protocols/--balance", .{});
        }
        config.rules = try alloc.alloc(CliRule, rule_specs.len);
        for (rule_specs, 0..) |spec, i| {
            config.rules[i] = try parseRuleSpec(gpa, alloc, spec, diag);
        }
        return config;
    }

    // Single-rule shorthand: --listen and --upstream together.
    const listen_flag = listen orelse
        return yaml.fail(gpa, diag, "missing --listen for the single-rule shorthand", .{});
    const listen_ep = try parseEndpoint(gpa, alloc, listen_flag, diag, "listen");
    const listen_port = listen_ep.port orelse
        return yaml.fail(gpa, diag, "--listen endpoint requires a port", .{});
    const upstream_ep = try parseEndpoint(gpa, alloc, upstream_flag orelse
        return yaml.fail(gpa, diag, "missing --upstream for the single-rule shorthand", .{}), diag, "upstream");

    const protocols_parsed = if (protocols) |text|
        try parseProtocolList(gpa, alloc, text, diag)
    else
        null;
    const balance_parsed = if (balance) |name|
        try parseBalance(gpa, alloc, name, diag)
    else
        null;

    config.rules = try alloc.alloc(CliRule, 1);
    config.rules[0] = .{
        .listen_host = listen_ep.host,
        .listen_port = listen_port,
        .upstreams = try alloc.alloc(CliUpstream, 1),
        .protocols = protocols_parsed,
        .balance = balance_parsed,
    };
    config.rules[0].upstreams[0] = .{ .host = upstream_ep.host, .port = upstream_ep.port };
    return config;
}

/// Render the configuration as a `rules:` YAML document. The output is owned
/// by `out` and is later copied into the cycle arena by conf.loadYaml, so the
/// buffer only needs to outlive this call.
pub fn renderYaml(config: *const Configuration, out: *std.ArrayList(u8), gpa: Allocator) error{OutOfMemory}!void {
    try out.appendSlice(gpa, "rules:\n");
    for (config.rules) |rule| {
        try out.appendSlice(gpa, "  - listen: ");
        try renderEndpoint(out, gpa, rule.listen_host, rule.listen_port);
        try out.appendSlice(gpa, "\n    upstreams:\n");
        for (rule.upstreams) |entry| {
            try out.appendSlice(gpa, "      - { host: ");
            try appendQuoted(out, gpa, entry.host);
            if (entry.port) |port| try appendPrint(out, gpa, ", port: {d}", .{port});
            if (entry.weight != 1) try appendPrint(out, gpa, ", weight: {d}", .{entry.weight});
            try out.appendSlice(gpa, " }\n");
        }
        if (rule.protocols) |protocols| {
            try out.appendSlice(gpa, "    protocols: [");
            for (protocols, 0..) |name, i| {
                if (i > 0) try out.appendSlice(gpa, ", ");
                try out.appendSlice(gpa, name);
            }
            try out.appendSlice(gpa, "]\n");
        }
        if (rule.balance) |balance| {
            try out.appendSlice(gpa, "    balance: ");
            try appendQuoted(out, gpa, balance);
            try out.appendSlice(gpa, "\n");
        }
    }
}

/// Build a fully validated configuration cycle from the parsed CLI flags,
/// mirroring conf.loadFile for the file-based running mode. The engine dupes
/// the rendered document into the cycle arena, so the temporary buffer is
/// freed here.
pub fn loadCycle(gpa: Allocator, config: *const Configuration, diag: *conf.Diagnostics) conf.LoadError!conf.Cycle {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try renderYaml(config, &out, gpa);
    return conf.loadYaml(gpa, out.items, diag);
}

// ---------------------------------------------------------------------------
// Shorthand parsing
// ---------------------------------------------------------------------------

const Endpoint = struct {
    host: []const u8,
    port: ?i64,
};

fn parseEndpoint(gpa: Allocator, alloc: Allocator, text: []const u8, diag: *conf.Diagnostics, what: []const u8) error{ OutOfMemory, InvalidConfiguration }!Endpoint {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len == 0) return yaml.fail(gpa, diag, "{s}: endpoint must not be empty", .{what});

    if (trimmed[0] == '[') {
        const close = std.mem.indexOfScalar(u8, trimmed, ']') orelse
            return yaml.fail(gpa, diag, "{s}: unterminated IPv6 literal '{s}'", .{ what, trimmed });
        const host = try alloc.dupe(u8, trimmed[1..close]);
        const rest = trimmed[close + 1 ..];
        const port: ?i64 = if (rest.len == 0) null else blk: {
            if (rest[0] != ':') return yaml.fail(gpa, diag, "{s}: expected ':port' after the IPv6 literal", .{what});
            break :blk try parseNumber(gpa, diag, rest[1..], what);
        };
        return .{ .host = host, .port = port };
    }

    if (std.mem.lastIndexOfScalar(u8, trimmed, ':')) |colon| {
        const host = try alloc.dupe(u8, if (colon == 0) "*" else trimmed[0..colon]);
        try validateHost(gpa, diag, host, what);
        const port = try parseNumber(gpa, diag, trimmed[colon + 1 ..], what);
        return .{ .host = host, .port = port };
    }

    if (isAllDigits(trimmed)) {
        const port = try parseNumber(gpa, diag, trimmed, what);
        return .{ .host = try alloc.dupe(u8, "*"), .port = port };
    }
    const host = try alloc.dupe(u8, trimmed);
    try validateHost(gpa, diag, host, what);
    return .{ .host = host, .port = null };
}

/// Hosts cannot carry characters that would be ambiguous with the shorthand
/// grammar or the rendered YAML flow mappings.
fn validateHost(gpa: Allocator, diag: *conf.Diagnostics, host: []const u8, what: []const u8) error{ InvalidConfiguration, OutOfMemory }!void {
    if (std.mem.indexOfAny(u8, host, "=,{}\"") != null) {
        return yaml.fail(gpa, diag, "{s}: invalid host '{s}'", .{ what, host });
    }
}

fn parseNumber(gpa: Allocator, diag: *conf.Diagnostics, text: []const u8, what: []const u8) error{ InvalidConfiguration, OutOfMemory }!i64 {
    if (text.len == 0 or !isAllDigits(text)) {
        return yaml.fail(gpa, diag, "{s}: invalid value '{s}'", .{ what, text });
    }
    const value = std.fmt.parseInt(i64, text, 10) catch
        return yaml.fail(gpa, diag, "{s}: invalid value '{s}'", .{ what, text });
    if (value < 1 or value > 65_535) {
        return yaml.fail(gpa, diag, "{s}: must be between 1 and 65535", .{what});
    }
    return value;
}

fn isAllDigits(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |c| {
        if (c < '0' or c > '9') return false;
    }
    return true;
}

fn parseRuleSpec(gpa: Allocator, alloc: Allocator, spec: []const u8, diag: *conf.Diagnostics) error{ OutOfMemory, InvalidConfiguration }!CliRule {
    var rule = CliRule{ .listen_host = "", .listen_port = 0, .upstreams = &.{} };
    var seen_listen = false;
    var seen_upstreams = false;
    var seen_protocols = false;
    var seen_balance = false;

    // Values may themselves contain commas (upstream lists, protocol lists),
    // so segments are delimited by the next known `key=` prefix, not by
    // commas. `keys` is also the fixed set of accepted keys.
    const keys = [_][]const u8{ "listen=", "upstreams=", "protocols=", "balance=" };
    var pos: usize = 0;
    while (pos < spec.len) {
        var current_key: ?[]const u8 = null;
        var match: usize = spec.len;
        for (keys) |key_text| {
            if (std.mem.indexOfPos(u8, spec, pos, key_text)) |idx| {
                if (idx < match) {
                    match = idx;
                    current_key = key_text[0 .. key_text.len - 1];
                }
            }
        }
        const key = current_key orelse
            return yaml.fail(gpa, diag, "--rule: expected 'key=value' in '{s}'", .{spec});
        const leftover = std.mem.trim(u8, spec[pos..match], " \t\r\n,");
        if (leftover.len > 0) {
            return yaml.fail(gpa, diag, "--rule: unexpected segment '{s}'", .{leftover});
        }

        const value_start = match + key.len + 1;
        var end: usize = spec.len;
        for (keys) |key_text| {
            if (std.mem.indexOfPos(u8, spec, value_start, key_text)) |idx| {
                if (idx < end) end = idx;
            }
        }
        const value = std.mem.trim(u8, spec[value_start..end], " \t\r\n,");

        if (std.mem.eql(u8, key, "listen")) {
            if (seen_listen) return yaml.fail(gpa, diag, "--rule: duplicate key 'listen'", .{});
            seen_listen = true;
            const ep = try parseEndpoint(gpa, alloc, value, diag, "listen");
            rule.listen_host = ep.host;
            rule.listen_port = ep.port orelse
                return yaml.fail(gpa, diag, "--rule: listen endpoint requires a port", .{});
        } else if (std.mem.eql(u8, key, "upstreams")) {
            if (seen_upstreams) return yaml.fail(gpa, diag, "--rule: duplicate key 'upstreams'", .{});
            seen_upstreams = true;
            rule.upstreams = try parseUpstreamList(gpa, alloc, value, diag);
        } else if (std.mem.eql(u8, key, "protocols")) {
            if (seen_protocols) return yaml.fail(gpa, diag, "--rule: duplicate key 'protocols'", .{});
            seen_protocols = true;
            rule.protocols = try parseProtocolList(gpa, alloc, value, diag);
        } else if (std.mem.eql(u8, key, "balance")) {
            if (seen_balance) return yaml.fail(gpa, diag, "--rule: duplicate key 'balance'", .{});
            seen_balance = true;
            rule.balance = try parseBalance(gpa, alloc, value, diag);
        }

        pos = end;
    }

    if (!seen_listen) return yaml.fail(gpa, diag, "--rule: missing required key 'listen'", .{});
    if (!seen_upstreams) return yaml.fail(gpa, diag, "--rule: missing required key 'upstreams'", .{});
    return rule;
}

fn parseUpstreamList(gpa: Allocator, alloc: Allocator, value: []const u8, diag: *conf.Diagnostics) error{ OutOfMemory, InvalidConfiguration }![]CliUpstream {
    var entries: std.ArrayList(CliUpstream) = .empty;
    errdefer entries.deinit(alloc);
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (trimmed.len == 0) continue;
        var host = trimmed;
        var weight: i64 = 1;
        if (std.mem.lastIndexOfScalar(u8, trimmed, '/')) |slash| {
            host = std.mem.trim(u8, trimmed[0..slash], " \t\r\n");
            const suffix = trimmed[slash + 1 ..];
            if (!std.mem.startsWith(u8, suffix, "weight=")) {
                return yaml.fail(gpa, diag, "upstreams: expected '/weight=N' suffix, got '/{s}'", .{suffix});
            }
            weight = try parseNumber(gpa, diag, suffix["weight=".len..], "weight");
        }
        const ep = try parseEndpoint(gpa, alloc, host, diag, "upstreams");
        try entries.append(alloc, .{ .host = ep.host, .port = ep.port, .weight = weight });
    }
    if (entries.items.len == 0) return yaml.fail(gpa, diag, "upstreams: must not be empty", .{});
    return entries.toOwnedSlice(alloc);
}

fn parseProtocolList(gpa: Allocator, alloc: Allocator, value: []const u8, diag: *conf.Diagnostics) error{ OutOfMemory, InvalidConfiguration }![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    errdefer names.deinit(alloc);
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |raw| {
        const name = std.mem.trim(u8, raw, " \t\r\n");
        if (name.len == 0) continue;
        if (!net.validProtocolName(name)) return yaml.fail(gpa, diag, "protocols: invalid protocol name '{s}'", .{name});
        for (names.items) |existing| {
            if (std.mem.eql(u8, existing, name)) {
                return yaml.fail(gpa, diag, "protocols: duplicate protocol '{s}'", .{name});
            }
        }
        try names.append(alloc, try alloc.dupe(u8, name));
    }
    if (names.items.len == 0) return yaml.fail(gpa, diag, "protocols: must not be empty", .{});
    return names.toOwnedSlice(alloc);
}

fn parseBalance(gpa: Allocator, alloc: Allocator, value: []const u8, diag: *conf.Diagnostics) error{ OutOfMemory, InvalidConfiguration }![]const u8 {
    const name = std.mem.trim(u8, value, " \t\r\n");
    if (!net.validProtocolName(name)) return yaml.fail(gpa, diag, "balance: invalid name '{s}'", .{name});
    return alloc.dupe(u8, name);
}

// ---------------------------------------------------------------------------
// YAML rendering
// ---------------------------------------------------------------------------

fn renderEndpoint(out: *std.ArrayList(u8), gpa: Allocator, host: []const u8, port: i64) error{OutOfMemory}!void {
    try out.appendSlice(gpa, "{ host: ");
    try appendQuoted(out, gpa, host);
    try appendPrint(out, gpa, ", port: {d} }}", .{port});
}

/// Format `args` into a fixed buffer and append it to `out`.
fn appendPrint(out: *std.ArrayList(u8), gpa: Allocator, comptime fmt: []const u8, args: anytype) error{OutOfMemory}!void {
    var buf: [128]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt, args) catch return error.OutOfMemory;
    try out.appendSlice(gpa, text);
}

/// Double-quoted scalar with the escapes the engine's parser understands.
fn appendQuoted(out: *std.ArrayList(u8), gpa: Allocator, text: []const u8) error{OutOfMemory}!void {
    try out.append(gpa, '"');
    for (text) |c| {
        switch (c) {
            '"' => try out.appendSlice(gpa, "\\\""),
            '\\' => try out.appendSlice(gpa, "\\\\"),
            '\n' => try out.appendSlice(gpa, "\\n"),
            '\r' => try out.appendSlice(gpa, "\\r"),
            '\t' => try out.appendSlice(gpa, "\\t"),
            0 => try out.appendSlice(gpa, "\\0"),
            else => try out.append(gpa, c),
        }
    }
    try out.append(gpa, '"');
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const core = @import("core.zig");
const rules = @import("rules.zig");

fn parseForTest(
    listen: ?[]const u8,
    upstream_flag: ?[]const u8,
    specs: []const []const u8,
    protocols: ?[]const u8,
    balance: ?[]const u8,
) !Configuration {
    var diag = conf.Diagnostics{};
    defer if (diag.message) |message| testing.allocator.free(message);
    return (try parseFlags(testing.allocator, listen, upstream_flag, specs, protocols, balance, &diag)) orelse
        error.TestUnexpectedNullConfiguration;
}

fn expectParseFailure(
    listen: ?[]const u8,
    upstream_flag: ?[]const u8,
    specs: []const []const u8,
    protocols: ?[]const u8,
    balance: ?[]const u8,
    expected_message: []const u8,
) !void {
    var diag = conf.Diagnostics{};
    defer if (diag.message) |message| testing.allocator.free(message);
    const result = parseFlags(testing.allocator, listen, upstream_flag, specs, protocols, balance, &diag);
    if (result) |config_value| {
        var config = config_value orelse unreachable;
        config.deinit();
        return error.TestExpectedFailureButParsed;
    } else |_| {}
    try testing.expectEqualStrings(expected_message, diag.message.?);
}

test "single-rule shorthand parses with defaults" {
    var config = try parseForTest(":9000", "example.com", &.{}, null, null);
    defer config.deinit();
    try testing.expectEqual(@as(usize, 1), config.rules.len);
    const rule = config.rules[0];
    try testing.expectEqualStrings("*", rule.listen_host);
    try testing.expectEqual(9_000, rule.listen_port);
    try testing.expectEqual(@as(usize, 1), rule.upstreams.len);
    try testing.expectEqualStrings("example.com", rule.upstreams[0].host);
    try testing.expectEqual(@as(?i64, null), rule.upstreams[0].port);
    try testing.expectEqual(1, rule.upstreams[0].weight);
    try testing.expect(rule.protocols == null);
    try testing.expect(rule.balance == null);
}

test "single-rule shorthand parses explicit hosts, IPv6 and protocols" {
    var config = try parseForTest("127.0.0.1:53", "[::1]:9000", &.{}, "udp", "source_hash");
    defer config.deinit();
    const rule = config.rules[0];
    try testing.expectEqualStrings("127.0.0.1", rule.listen_host);
    try testing.expectEqual(53, rule.listen_port);
    try testing.expectEqualStrings("::1", rule.upstreams[0].host);
    try testing.expectEqual(@as(?i64, 9_000), rule.upstreams[0].port);
    try testing.expectEqual(@as(usize, 1), rule.protocols.?.len);
    try testing.expectEqualStrings("udp", rule.protocols.?[0]);
    try testing.expectEqualStrings("source_hash", rule.balance.?);
}

test "multi-rule shorthand parses weights and port defaults" {
    var config = try parseForTest(
        null,
        null,
        &.{
            "listen=:9001,upstreams=a:9001,b/weight=2,c:9003,protocols=tcp,udp,balance=weighted_round_robin",
            "listen=127.0.0.1:53,upstreams=8.8.8.8:53",
        },
        null,
        null,
    );
    defer config.deinit();
    try testing.expectEqual(@as(usize, 2), config.rules.len);

    const first = config.rules[0];
    try testing.expectEqualStrings("*", first.listen_host);
    try testing.expectEqual(9_001, first.listen_port);
    try testing.expectEqual(@as(usize, 3), first.upstreams.len);
    try testing.expectEqualStrings("a", first.upstreams[0].host);
    try testing.expectEqual(@as(?i64, 9_001), first.upstreams[0].port);
    try testing.expectEqual(1, first.upstreams[0].weight);
    try testing.expectEqualStrings("b", first.upstreams[1].host);
    try testing.expectEqual(@as(?i64, null), first.upstreams[1].port); // defaults to the listen port
    try testing.expectEqual(2, first.upstreams[1].weight);
    try testing.expectEqualStrings("c", first.upstreams[2].host);
    try testing.expectEqual(@as(?i64, 9_003), first.upstreams[2].port);
    try testing.expectEqual(@as(usize, 2), first.protocols.?.len);
    try testing.expectEqualStrings("tcp", first.protocols.?[0]);
    try testing.expectEqualStrings("udp", first.protocols.?[1]);
    try testing.expectEqualStrings("weighted_round_robin", first.balance.?);

    const second = config.rules[1];
    try testing.expectEqualStrings("127.0.0.1", second.listen_host);
    try testing.expectEqual(53, second.listen_port);
    try testing.expectEqual(@as(usize, 1), second.upstreams.len);
    try testing.expectEqualStrings("8.8.8.8", second.upstreams[0].host);
    try testing.expectEqual(@as(?i64, 53), second.upstreams[0].port);
}

test "renders a rules document for the engine" {
    var config = try parseForTest(
        null,
        null,
        &.{"listen=127.0.0.1:9000,upstreams=a.example.com,b.example.com:9001/weight=3,protocols=tcp,udp,balance=round_robin"},
        null,
        null,
    );
    defer config.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try renderYaml(&config, &out, testing.allocator);
    try testing.expectEqualStrings(
        \\rules:
        \\  - listen: { host: "127.0.0.1", port: 9000 }
        \\    upstreams:
        \\      - { host: "a.example.com" }
        \\      - { host: "b.example.com", port: 9001, weight: 3 }
        \\    protocols: [tcp, udp]
        \\    balance: "round_robin"
        \\
    , out.items);
}

test "rejects invalid shorthand" {
    const cases = [_]struct {
        listen: ?[]const u8,
        upstream: ?[]const u8,
        specs: []const []const u8,
        protocols: ?[]const u8,
        balance: ?[]const u8,
        message: []const u8,
    }{
        .{ .listen = null, .upstream = "a", .specs = &.{}, .protocols = null, .balance = null, .message = "missing --listen for the single-rule shorthand" },
        .{ .listen = ":9000", .upstream = null, .specs = &.{}, .protocols = null, .balance = null, .message = "missing --upstream for the single-rule shorthand" },
        .{ .listen = "example.com", .upstream = "a", .specs = &.{}, .protocols = null, .balance = null, .message = "--listen endpoint requires a port" },
        .{ .listen = ":0", .upstream = "a", .specs = &.{}, .protocols = null, .balance = null, .message = "listen: must be between 1 and 65535" },
        .{ .listen = ":70000", .upstream = "a", .specs = &.{}, .protocols = null, .balance = null, .message = "listen: must be between 1 and 65535" },
        .{ .listen = ":abc", .upstream = "a", .specs = &.{}, .protocols = null, .balance = null, .message = "listen: invalid value 'abc'" },
        .{ .listen = ":9000", .upstream = "a", .specs = &.{}, .protocols = "bad/name", .balance = null, .message = "protocols: invalid protocol name 'bad/name'" },
        .{ .listen = ":9000", .upstream = "a", .specs = &.{}, .protocols = "tcp,tcp", .balance = null, .message = "protocols: duplicate protocol 'tcp'" },
        .{ .listen = ":9000", .upstream = "a", .specs = &.{}, .protocols = null, .balance = "bad/name", .message = "balance: invalid name 'bad/name'" },
        .{ .listen = ":9000", .upstream = "", .specs = &.{}, .protocols = null, .balance = null, .message = "upstream: endpoint must not be empty" },
        .{ .listen = null, .upstream = null, .specs = &.{"listen=:9000,upstreams=a,bogus=1"}, .protocols = null, .balance = null, .message = "upstreams: invalid host 'bogus=1'" },
        .{ .listen = null, .upstream = null, .specs = &.{"upstreams=a"}, .protocols = null, .balance = null, .message = "--rule: missing required key 'listen'" },
        .{ .listen = null, .upstream = null, .specs = &.{"listen=:9000"}, .protocols = null, .balance = null, .message = "--rule: missing required key 'upstreams'" },
        .{ .listen = null, .upstream = null, .specs = &.{"listen=:9000,listen=:9001,upstreams=a"}, .protocols = null, .balance = null, .message = "--rule: duplicate key 'listen'" },
        .{ .listen = null, .upstream = null, .specs = &.{"listen=example.com,upstreams=a"}, .protocols = null, .balance = null, .message = "--rule: listen endpoint requires a port" },
        .{ .listen = null, .upstream = null, .specs = &.{"listen=:9000,upstreams=a/weight=0"}, .protocols = null, .balance = null, .message = "weight: must be between 1 and 65535" },
        .{ .listen = null, .upstream = null, .specs = &.{"listen=:9000,upstreams=a/name=b"}, .protocols = null, .balance = null, .message = "upstreams: expected '/weight=N' suffix, got '/name=b'" },
        .{ .listen = null, .upstream = null, .specs = &.{"listen=:9000,upstreams="}, .protocols = null, .balance = null, .message = "upstreams: must not be empty" },
        .{ .listen = null, .upstream = null, .specs = &.{"listen=:9000,upstreams=a,protocols=bad/name"}, .protocols = null, .balance = null, .message = "protocols: invalid protocol name 'bad/name'" },
        .{ .listen = ":9000", .upstream = "a", .specs = &.{"listen=:9001,upstreams=b"}, .protocols = null, .balance = null, .message = "--rule cannot be combined with --listen/--upstream/--protocols/--balance" },
    };
    for (cases) |case| {
        try expectParseFailure(case.listen, case.upstream, case.specs, case.protocols, case.balance, case.message);
    }
}

test "no endpoint flags yields no configuration" {
    var diag = conf.Diagnostics{};
    const result = try parseFlags(testing.allocator, null, null, &.{}, null, null, &diag);
    try testing.expect(result == null);
}

test "cli configuration decodes through the engine like the rules module" {
    var config = try parseForTest(":9000", "a.example.com", &.{}, "tcp", null);
    defer config.deinit();
    var diag = conf.Diagnostics{};
    defer if (diag.message) |message| testing.allocator.free(message);
    var cycle = try loadCycle(testing.allocator, &config, &diag);
    defer cycle.deinit();
    try testing.expect(cycle.rules_mode);

    const decoded = rules.rulesList(&cycle);
    try testing.expectEqual(@as(usize, 1), decoded.len);
    try testing.expectEqualStrings("*", decoded[0].listen.host);
    try testing.expectEqual(9_000, decoded[0].listen.port);
    try testing.expectEqualSlices(core.ForwardProtocol, &.{.tcp}, decoded[0].protocols.?);
    try testing.expect(decoded[0].balance == upstream.defaultBalancer());
    try testing.expectEqual(@as(usize, 1), decoded[0].upstreams.len);
    try testing.expectEqualStrings("a.example.com", decoded[0].upstreams[0].host);
    try testing.expectEqual(9_000, decoded[0].upstreams[0].port); // defaults to the listen port
}

test "multi-rule cli configuration decodes weights through the engine" {
    var config = try parseForTest(
        null,
        null,
        &.{"listen=:9001,upstreams=a:9001,b/weight=2,balance=source_hash"},
        null,
        null,
    );
    defer config.deinit();
    var diag = conf.Diagnostics{};
    defer if (diag.message) |message| testing.allocator.free(message);
    var cycle = try loadCycle(testing.allocator, &config, &diag);
    defer cycle.deinit();
    const decoded = rules.rulesList(&cycle);
    try testing.expectEqual(@as(usize, 1), decoded.len);
    try testing.expectEqual(@as(usize, 2), decoded[0].upstreams.len);
    try testing.expectEqual(1, decoded[0].upstreams[0].weight);
    try testing.expectEqual(2, decoded[0].upstreams[1].weight);
    try testing.expect(decoded[0].balance == upstream.balancerByName("source_hash").?);
}
