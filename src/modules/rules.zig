//! rules section: owns the `rules` key (root context) and the rule-level
//! endpoint keys (listen / upstreams / protocols / balance inside a
//! `rules[]` entry).
//!
//! The root directive only records the raw node and flips the cfg to
//! rules mode; the finalize hook then opens a nested rule scope per entry
//! (conf.beginRule), dispatches the entry's keys to every module with a
//! rule context (timeouts/limits overrides land in their own confs) and
//! decodes the endpoint directives it owns. `balance` values resolve through
//! the upstream module's balancer registry.

const std = @import("std");
const conf = @import("../conf.zig");
const limits = @import("limits.zig");
const net = @import("../net.zig");
const timeouts = @import("timeouts.zig");
const upstream = @import("upstream.zig");
const yaml = @import("../yaml.zig");

pub const UpstreamConfiguration = struct {
    host: []const u8,
    /// Decoded with the rule listen port as default.
    port: i64,
    weight: i64 = 1,
};

pub const RuleConfiguration = struct {
    /// null inherits the global protocols list.
    protocols: ?[]net.ForwardProtocol = null,
    listen: net.EndpointConfiguration,
    upstreams: []UpstreamConfiguration,
    balance: *const upstream.Balancer,
    /// Preserves the configured name until the resolve phase checks the
    /// built-in balancer registry.
    balance_name: ?[]const u8 = null,
    /// Copies of the per-rule override confs owned by the timeouts/limits
    /// modules (collected during finalize).
    timeouts: timeouts.RuleTimeoutOverrides = .{},
    limits: limits.RuleLimitOverrides = .{},
};

pub const Conf = struct {
    rules_node: ?*yaml.Value = null,
    rules: []RuleConfiguration = &.{},
};

pub const RuleConf = struct {
    listen_node: ?*yaml.Value = null,
    upstreams_node: ?*yaml.Value = null,
    protocols: ?[]net.ForwardProtocol = null,
    balance: ?*const upstream.Balancer = null,
    balance_name: ?[]const u8 = null,
};

/// Decoded rules of the current cfg (empty outside rules mode).
pub fn rulesList(cfg: *conf.Configuration) []RuleConfiguration {
    return cfg.rules.rules;
}

/// Shared protocols sequence decoder; used by the core
/// module for the root directive and by this module for rule overrides.
pub fn decodeProtocols(cfg: *conf.Configuration, value: *yaml.Value) yaml.LoadError![]net.ForwardProtocol {
    if (value.* != .sequence) {
        return yaml.fail(cfg.gpa, cfg.diag, "protocols: expected a sequence", .{});
    }
    var protocols: std.ArrayList(net.ForwardProtocol) = .empty;
    for (value.sequence) |item| {
        if (item.* != .scalar) {
            return yaml.fail(cfg.gpa, cfg.diag, "protocols: expected a sequence of names", .{});
        }
        const text = item.scalar.text;
        if (!net.validProtocolName(text)) return yaml.fail(
            cfg.gpa,
            cfg.diag,
            "protocols: invalid protocol name '{s}'",
            .{text},
        );
        try protocols.append(cfg.allocator(), net.ForwardProtocol.fromName(text));
    }
    return protocols.toOwnedSlice(cfg.allocator());
}

pub fn setRuleListen(cfg: *conf.Configuration, oc: *RuleConf, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = cfg;
    _ = path;
    const c = oc;
    c.listen_node = value;
}

pub fn setRuleUpstreams(cfg: *conf.Configuration, oc: *RuleConf, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = cfg;
    _ = path;
    const c = oc;
    c.upstreams_node = value;
}

pub fn setRuleProtocols(cfg: *conf.Configuration, oc: *RuleConf, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c = oc;
    c.protocols = try decodeProtocols(cfg, value);
}

pub fn setRuleBalance(cfg: *conf.Configuration, oc: *RuleConf, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    const c = oc;
    var path_buf: [80]u8 = undefined;
    const balance_path = std.fmt.bufPrint(&path_buf, "{s}.balance", .{path}) catch "rules.balance";
    const text = try yaml.decodeString(cfg.gpa, cfg.diag, value, balance_path);
    c.balance_name = text;
    c.balance = upstream.balancerByName(text);
}

pub fn finalize(cfg: *conf.Configuration) yaml.LoadError!void {
    const c = &cfg.rules;
    const node = c.rules_node orelse return;
    if (node.* != .sequence) {
        return yaml.fail(cfg.gpa, cfg.diag, "rules: expected a sequence", .{});
    }
    var decoded: std.ArrayList(RuleConfiguration) = .empty;
    for (node.sequence, 0..) |item, i| {
        try decoded.append(cfg.allocator(), try decodeRule(cfg, item, i));
    }
    c.rules = try decoded.toOwnedSlice(cfg.allocator());
}

pub fn decodeRule(cfg: *conf.Configuration, item: *yaml.Value, index: usize) yaml.LoadError!RuleConfiguration {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "rules[{d}]", .{index}) catch "rules";
    const map = try yaml.requireMapping(cfg.gpa, cfg.diag, item, path);

    var rule_conf = RuleConf{};
    var timeout_overrides = timeouts.RuleConf{};
    var limit_overrides = limits.RuleConf{};
    try conf.parseRule(cfg, &rule_conf, &timeout_overrides, &limit_overrides, map, path);

    const listen_node = rule_conf.listen_node orelse
        return yaml.fail(cfg.gpa, cfg.diag, "missing required key: {s}.listen", .{path});
    const listen = try decodeRuleListen(cfg, listen_node, path);

    const upstreams_node = rule_conf.upstreams_node orelse
        return yaml.fail(cfg.gpa, cfg.diag, "missing required key: {s}.upstreams", .{path});
    const upstreams = try decodeRuleUpstreams(cfg, upstreams_node, listen.port, path);

    return .{
        .protocols = rule_conf.protocols,
        .listen = listen,
        .upstreams = upstreams,
        .balance = rule_conf.balance orelse upstream.defaultBalancer(),
        .balance_name = rule_conf.balance_name,
        .timeouts = timeout_overrides,
        .limits = limit_overrides,
    };
}

pub fn decodeRuleListen(cfg: *conf.Configuration, value: *yaml.Value, path: []const u8) yaml.LoadError!net.EndpointConfiguration {
    var sub_buf: [80]u8 = undefined;
    const listen_path = std.fmt.bufPrint(&sub_buf, "{s}.listen", .{path}) catch path;
    const map = try yaml.requireMapping(cfg.gpa, cfg.diag, value, listen_path);
    try yaml.checkKeys(cfg.gpa, cfg.diag, map, &.{ "host", "port" }, listen_path);
    var endpoint = net.EndpointConfiguration{ .host = "*", .port = 0 };
    if (yaml.mappingGet(map, "host")) |v| {
        endpoint.host = try yaml.decodeString(cfg.gpa, cfg.diag, v, "rules.listen.host");
    }
    const port_value = yaml.mappingGet(map, "port") orelse
        return yaml.fail(cfg.gpa, cfg.diag, "missing required key: {s}.port", .{listen_path});
    endpoint.port = try yaml.decodeInt(cfg.gpa, cfg.diag, port_value, listen_path);
    return endpoint;
}

pub fn decodeRuleUpstreams(cfg: *conf.Configuration, value: *yaml.Value, listen_port: i64, path: []const u8) yaml.LoadError![]UpstreamConfiguration {
    var sub_buf: [80]u8 = undefined;
    const upstreams_path = std.fmt.bufPrint(&sub_buf, "{s}.upstreams", .{path}) catch path;
    if (value.* != .sequence) {
        return yaml.fail(cfg.gpa, cfg.diag, "{s}: expected a sequence", .{upstreams_path});
    }
    var upstreams: std.ArrayList(UpstreamConfiguration) = .empty;
    for (value.sequence, 0..) |item, j| {
        const map = try yaml.requireMapping(cfg.gpa, cfg.diag, item, upstreams_path);
        var entry_buf: [96]u8 = undefined;
        const entry_path = std.fmt.bufPrint(&entry_buf, "{s}[{d}]", .{ upstreams_path, j }) catch upstreams_path;
        try yaml.checkKeys(cfg.gpa, cfg.diag, map, &.{ "host", "port", "weight" }, entry_path);
        const host_value = yaml.mappingGet(map, "host") orelse
            return yaml.fail(cfg.gpa, cfg.diag, "missing required key: {s}.host", .{entry_path});
        const host = try yaml.decodeString(cfg.gpa, cfg.diag, host_value, upstreams_path);
        var decoded = UpstreamConfiguration{ .host = host, .port = listen_port };
        if (yaml.mappingGet(map, "port")) |v| {
            decoded.port = try yaml.decodeInt(cfg.gpa, cfg.diag, v, upstreams_path);
        }
        if (yaml.mappingGet(map, "weight")) |v| {
            decoded.weight = try yaml.decodeInt(cfg.gpa, cfg.diag, v, upstreams_path);
        }
        try upstreams.append(cfg.allocator(), decoded);
    }
    return upstreams.toOwnedSlice(cfg.allocator());
}

pub fn validate(cfg: *conf.Configuration) yaml.LoadError!void {
    const c = &cfg.rules;
    if (c.rules_node == null) return;
    if (c.rules.len == 0) {
        yaml.setDiag(cfg.gpa, cfg.diag, "rules must not be empty", .{});
        return error.InvalidConfiguration;
    }
    for (c.rules, 0..) |rule, i| {
        try validateRule(cfg, rule, i);
    }
}

pub fn validateRule(cfg: *conf.Configuration, rule: RuleConfiguration, i: usize) yaml.LoadError!void {
    const gpa = cfg.gpa;
    const diag = cfg.diag;
    if (std.mem.trim(u8, rule.listen.host, " \t\n\r").len == 0) {
        yaml.setDiag(gpa, diag, "rules[{d}].listen.host must not be empty", .{i});
        return error.InvalidConfiguration;
    }
    if (rule.listen.port < 1 or rule.listen.port > 65_535) {
        yaml.setDiag(gpa, diag, "rules[{d}].listen.port must be between 1 and 65535", .{i});
        return error.InvalidConfiguration;
    }
    if (rule.upstreams.len == 0) {
        yaml.setDiag(gpa, diag, "rules[{d}].upstreams must not be empty", .{i});
        return error.InvalidConfiguration;
    }
    for (rule.upstreams, 0..) |entry, j| {
        if (std.mem.trim(u8, entry.host, " \t\n\r").len == 0) {
            yaml.setDiag(gpa, diag, "rules[{d}].upstreams[{d}].host must not be empty", .{ i, j });
            return error.InvalidConfiguration;
        }
        if (entry.port < 1 or entry.port > 65_535) {
            yaml.setDiag(gpa, diag, "rules[{d}].upstreams[{d}].port must be between 1 and 65535", .{ i, j });
            return error.InvalidConfiguration;
        }
        if (entry.weight < 1 or entry.weight > 65_535) {
            yaml.setDiag(gpa, diag, "rules[{d}].upstreams[{d}].weight must be between 1 and 65535", .{ i, j });
            return error.InvalidConfiguration;
        }
    }
    if (rule.protocols) |protocols| {
        var path_buf: [80]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "rules[{d}].protocols", .{i}) catch "rules.protocols";
        try net.validateProtocols(gpa, diag, protocols, path);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const core = @import("core.zig");

fn loadRulesForTest(text: []const u8) !struct { cfg: conf.Configuration, rules: []RuleConfiguration } {
    var diag = conf.Diagnostics{};
    var cfg = conf.loadYaml(testing.allocator, text, &diag) catch |err| {
        if (diag.message) |message| {
            std.debug.print("unexpected load failure: {s}\n", .{message});
            testing.allocator.free(message);
        }
        return err;
    };
    if (!cfg.rules_mode) return error.TestUnexpectedSingleMode;
    return .{ .cfg = cfg, .rules = rulesList(&cfg) };
}

test "loads rules with defaults and inheritance" {
    const result = try loadRulesForTest(
        \\rules:
        \\  - listen: { port: 9000 }
        \\    upstreams:
        \\      - { host: "a.example.com" }
        \\      - { host: "b.example.com", port: 9001, weight: 3 }
        \\  - listen: { host: "127.0.0.1", port: 53 }
        \\    protocols: [udp]
        \\    upstreams: [ { host: "8.8.8.8", port: 53 } ]
        \\
    );
    var cfg = result.cfg;
    defer cfg.deinit();
    const decoded = result.rules;

    try testing.expectEqual(@as(usize, 2), decoded.len);

    const first = decoded[0];
    try testing.expectEqualStrings("*", first.listen.host);
    try testing.expectEqual(9_000, first.listen.port);
    try testing.expect(first.protocols == null);
    try testing.expect(first.balance == upstream.defaultBalancer());
    try testing.expectEqual(@as(usize, 2), first.upstreams.len);
    try testing.expectEqualStrings("a.example.com", first.upstreams[0].host);
    try testing.expectEqual(9_000, first.upstreams[0].port); // defaults to the rule listen port
    try testing.expectEqual(1, first.upstreams[0].weight);
    try testing.expectEqualStrings("b.example.com", first.upstreams[1].host);
    try testing.expectEqual(9_001, first.upstreams[1].port);
    try testing.expectEqual(3, first.upstreams[1].weight);

    const second = decoded[1];
    try testing.expectEqualStrings("127.0.0.1", second.listen.host);
    try testing.expectEqualSlices(net.ForwardProtocol, &.{.udp}, second.protocols.?);
    try testing.expectEqual(@as(usize, 1), second.upstreams.len);
}

test "preserves dynamically named protocols for runtime resolution" {
    const result = try loadRulesForTest(
        \\rules:
        \\  - listen: { port: 9000 }
        \\    protocols: [probe_udp]
        \\    upstreams: [ { host: "127.0.0.1" } ]
        \\
    );
    var cfg = result.cfg;
    defer cfg.deinit();
    const protocols = result.rules[0].protocols.?;
    try testing.expectEqual(@as(usize, 1), protocols.len);
    try testing.expectEqualStrings("probe_udp", protocols[0].name());
}

test "loads rule overrides and global sections" {
    const result = try loadRulesForTest(
        \\protocols: [tcp]
        \\timeouts: { connectSeconds: 8, tcpIdleSeconds: 100 }
        \\limits: { maxTCPBufferedBytes: 1048576 }
        \\runtime: { workerThreads: 2 }
        \\rules:
        \\  - listen: { port: 9000 }
        \\    balance: source_hash
        \\    upstreams: [ { host: "a" } ]
        \\    timeouts: { tcpIdleSeconds: 600 }
        \\    limits: { maxTCPBufferedBytes: 8388608, maxUDPAssociations: 128 }
        \\  - listen: { port: 9001 }
        \\    balance: weighted_round_robin
        \\    upstreams: [ { host: "b" } ]
        \\
    );
    var cfg = result.cfg;
    defer cfg.deinit();
    const decoded = result.rules;

    const globals = core.configuration(&cfg);
    try testing.expectEqualSlices(net.ForwardProtocol, &.{.tcp}, globals.protocols);
    try testing.expectEqual(8, globals.timeouts.connect_seconds);
    try testing.expectEqual(100, globals.timeouts.tcp_idle_seconds);
    try testing.expectEqual(1_048_576, globals.limits.max_tcp_buffered_bytes);
    try testing.expectEqual(2, globals.runtime.worker_threads);

    const first = decoded[0];
    try testing.expect(first.balance == upstream.balancerByName("source_hash").?);
    try testing.expectEqual(@as(?i64, 600), first.timeouts.tcp_idle_seconds);
    try testing.expect(first.timeouts.connect_seconds == null);
    try testing.expectEqual(@as(?i64, 8_388_608), first.limits.max_tcp_buffered_bytes);
    try testing.expectEqual(@as(?i64, 128), first.limits.max_udp_associations);
    try testing.expect(first.limits.tcp_listen_backlog == null);

    try testing.expect(decoded[1].balance == upstream.balancerByName("weighted_round_robin").?);
}

test "rejects unknown keys inside rules with indexed paths" {
    try conf.expectLoadFailure(
        \\rules:
        \\  - listen: { port: 9000 }
        \\    upstreams: [ { host: "a" } ]
        \\    bogus: 1
        \\
    , "unknown configuration key: rules[0].bogus");

    try conf.expectLoadFailure(
        \\rules:
        \\  - listen: { port: 9000, typo: 1 }
        \\    upstreams: [ { host: "a" } ]
        \\
    , "unknown configuration key: rules[0].listen.typo");

    try conf.expectLoadFailure(
        \\rules:
        \\  - listen: { port: 9000 }
        \\    upstreams: [ { host: "a", typo: 1 } ]
        \\
    , "unknown configuration key: rules[0].upstreams[0].typo");

    try conf.expectLoadFailure(
        \\rules:
        \\  - listen: { port: 9000 }
        \\    upstreams: [ { host: "a" } ]
        \\    timeouts: { shutdownGraceSeconds: 5 }
        \\
    , "unknown configuration key: rules[0].timeouts.shutdownGraceSeconds");

    try conf.expectLoadFailure(
        \\rules:
        \\  - listen: { port: 9000 }
        \\    upstreams: [ { host: "a" } ]
        \\    limits: { maxUDPPendingBytes: 4096 }
        \\
    , "unknown configuration key: rules[0].limits.maxUDPPendingBytes");
}

test "rejects invalid rules values" {
    const cases = [_]struct { yaml_text: []const u8, message: []const u8 }{
        .{ .yaml_text = "rules: []\n", .message = "rules must not be empty" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n", .message = "missing required key: rules[0].upstreams" },
        .{ .yaml_text = "rules:\n  - upstreams: [ { host: \"a\" } ]\n", .message = "missing required key: rules[0].listen" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: []\n", .message = "rules[0].upstreams must not be empty" },
        .{ .yaml_text = "rules:\n  - listen: { port: 0 }\n    upstreams: [ { host: \"a\" } ]\n", .message = "rules[0].listen.port must be between 1 and 65535" },
        .{ .yaml_text = "rules:\n  - listen: { host: \" \", port: 9000 }\n    upstreams: [ { host: \"a\" } ]\n", .message = "rules[0].listen.host must not be empty" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\", port: 0 } ]\n", .message = "rules[0].upstreams[0].port must be between 1 and 65535" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\", weight: 0 } ]\n", .message = "rules[0].upstreams[0].weight must be between 1 and 65535" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\", weight: 65536 } ]\n", .message = "rules[0].upstreams[0].weight must be between 1 and 65535" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\" } ]\n    protocols: []\n", .message = "rules[0].protocols must not be empty" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\" } ]\n    protocols: [tcp, tcp]\n", .message = "rules[0].protocols must not contain duplicates" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\" } ]\n    timeouts: { tcpIdleSeconds: 0 }\n", .message = "rules[0].timeouts.tcpIdleSeconds must be positive" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\" } ]\n    timeouts: { connectSeconds: 9223372037 }\n", .message = "rules[0].timeouts.connectSeconds must be no greater than 9223372036 seconds" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\" } ]\n    limits: { tcpListenBacklog: 0 }\n", .message = "rules[0].limits.tcpListenBacklog must be between 1 and 2147483647" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\" } ]\n    limits: { maxTCPBufferedBytes: 0 }\n", .message = "rules[0].limits.maxTCPBufferedBytes must be positive" },
        .{ .yaml_text = "rules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\" } ]\n    limits: { maxUDPAssociations: 0 }\n", .message = "rules[0].limits.maxUDPAssociations must be between 1 and 2147483647" },
        .{ .yaml_text = "version: 2\nrules:\n  - listen: { port: 9000 }\n    upstreams: [ { host: \"a\" } ]\n", .message = "unsupported configuration version: 2" },
    };
    for (cases) |case| {
        try conf.expectLoadFailure(case.yaml_text, case.message);
    }
}

fn fixedResolver(host: []const u8, port: u16) !net.SocketAddr {
    _ = host;
    return net.SocketAddr.parseIp("127.0.0.1", port).?;
}

test "unknown balancer is rejected during resolve" {
    const result = try loadRulesForTest(
        \\rules:
        \\  - listen: { port: 9000 }
        \\    upstreams: [ { host: "a" } ]
        \\    balance: nearest
        \\
    );
    var cfg = result.cfg;
    defer cfg.deinit();
    var diag = conf.Diagnostics{};
    defer if (diag.message) |message| testing.allocator.free(message);
    try testing.expectError(error.ResolutionFailed, core.resolveForwarder(testing.allocator, cfg.allocator(), &cfg, fixedResolver, &diag));
    try testing.expect(std.mem.startsWith(u8, diag.message.?, "rules[0].balance: expected one of "));
}

test "effective configuration merges rule overrides" {
    const result = try loadRulesForTest(
        \\timeouts: { connectSeconds: 8 }
        \\limits: { maxTCPBufferedBytes: 1048576 }
        \\rules:
        \\  - listen: { port: 9000 }
        \\    upstreams: [ { host: "a" } ]
        \\    timeouts: { tcpIdleSeconds: 600 }
        \\    limits: { maxTCPBufferedBytes: 8388608 }
        \\
    );
    var cfg = result.cfg;
    defer cfg.deinit();

    const effective = core.effectiveConfiguration(core.configuration(&cfg), result.rules[0]);
    try testing.expectEqual(8, effective.timeouts.connect_seconds);
    try testing.expectEqual(600, effective.timeouts.tcp_idle_seconds);
    try testing.expectEqual(8_388_608, effective.limits.max_tcp_buffered_bytes);
    try testing.expectEqual(limits.default_tcp_listen_backlog, effective.limits.tcp_listen_backlog);
    try testing.expectEqual(limits.default_max_udp_associations, effective.limits.max_udp_associations);
    try testing.expectEqualStrings("a", effective.upstream.host);
    try testing.expectEqual(9_000, effective.upstream.port);
}
