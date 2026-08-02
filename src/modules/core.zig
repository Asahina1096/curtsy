//! core module: the ngx_core_module analogue.
//!
//! Owns the composed configuration model (global sections from the section
//! modules plus the single-rule `listen`/`upstream`/`protocols`/`version`
//! sugar), address resolution with cross-rule conflict detection, the
//! protocol module interface (Listener vtable) and the unified runtime
//! orchestrator: one cycle driving 1..N forwarding rules — a single-rule
//! document is simply one synthesized rule (the nginx http module serving
//! 1..N servers analogue).
//!
//! Hot reload (SIGHUP) runs a fresh configuration cycle and diffs rules by
//! their resolved listen address set: matched rules update in place
//! (upstream pool health is inherited by address), brand-new rules bind
//! before unmatched old ones retire, and any failure rolls the reload back
//! to the previous configuration.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const autotune = @import("../autotune.zig");
const conf = @import("../conf.zig");
const fw = @import("../module.zig");
const limits = @import("limits.zig");
const log = @import("../log.zig");
const logging = @import("logging.zig");
const net = @import("../net.zig");
const performance = @import("performance.zig");
const rules = @import("rules.zig");
const runtime = @import("runtime.zig");
const timeouts = @import("timeouts.zig");
const tuning = @import("tuning.zig");
const upstream = @import("upstream.zig");
const yaml = @import("../yaml.zig");

const Allocator = std.mem.Allocator;

pub const Error = anyerror;

const reap_interval_ms: i32 = 100;

// ---------------------------------------------------------------------------
// Re-exported model (the data planes import this file as their config view)
// ---------------------------------------------------------------------------

pub const SocketAddr = net.SocketAddr;
pub const ForwardProtocol = net.ForwardProtocol;
pub const EndpointConfiguration = net.EndpointConfiguration;
pub const Resolver = net.Resolver;
pub const ResolveError = net.ResolveError;
pub const TimeoutConfiguration = timeouts.TimeoutConfiguration;
pub const LimitConfiguration = limits.LimitConfiguration;
pub const LogConfiguration = logging.LogConfiguration;
pub const RuntimeOptions = runtime.RuntimeOptions;
pub const PerformanceConfiguration = performance.PerformanceConfiguration;
pub const SockmapAccelerationMode = performance.SockmapAccelerationMode;
pub const RuleConfiguration = rules.RuleConfiguration;

/// Composed configuration: global sections from the section modules plus
/// the endpoint view. Used as the global view and (merged with rule
/// overrides) as the effective per-rule view handed to the listeners.
pub const ForwarderConfiguration = struct {
    version: i64,
    protocols: []ForwardProtocol,
    listen: EndpointConfiguration,
    upstream: EndpointConfiguration,
    timeouts: TimeoutConfiguration = .{},
    limits: LimitConfiguration,
    logging: LogConfiguration = .{},
    runtime: RuntimeOptions = .{},
    performance: PerformanceConfiguration = .{},
};

pub const ResolvedConfiguration = struct {
    configuration: ForwarderConfiguration,
    /// One or two addresses; "*" listens dual-stack wildcard 0.0.0.0 and ::.
    listen_addresses: []SocketAddr,
    upstream_address: SocketAddr,

    pub fn listenBindingDiffers(self: *const ResolvedConfiguration, other: *const ResolvedConfiguration) bool {
        return !net.addressesEqual(self.listen_addresses, other.listen_addresses);
    }

    pub fn shouldEnableTCPSockmap(self: *const ResolvedConfiguration) bool {
        return self.configuration.performance.tcp_sockmap_acceleration != .disabled;
    }

    pub fn shouldEnableUDPSockmap(self: *const ResolvedConfiguration) bool {
        // auto skips loopback upstreams: the measured 1400-byte loopback
        // workload had lower goodput and severe reordering through the UDP
        // sockmap verdict path. Explicit enabled still forces an attempt;
        // remote upstreams stay eligible in auto.
        return switch (self.configuration.performance.udp_sockmap_acceleration) {
            .disabled => false,
            .enabled => true,
            .auto => !self.upstream_address.isLoopback(),
        };
    }
};

pub const ResolvedRule = struct {
    rule: RuleConfiguration,
    /// Global sections merged with rule overrides; the rule drives the
    /// listener APIs with this view. Its upstream is upstreams[0]; actual
    /// multi-upstream selection happens through the selector hook.
    effective: ForwarderConfiguration,
    listen_addresses: []SocketAddr,
    /// One resolved address per rule.upstreams entry, same order.
    upstream_addresses: []SocketAddr,

    pub fn effectiveProtocols(self: *const ResolvedRule) []ForwardProtocol {
        return self.rule.protocols orelse self.effective.protocols;
    }
};

/// The resolved whole cycle: a global view plus 1..N resolved rules.
pub const ResolvedForwarder = struct {
    configuration: ForwarderConfiguration,
    rules: []ResolvedRule,
    rules_mode: bool,
};

// ---------------------------------------------------------------------------
// Protocol module interface (ngx event module analogue)
// ---------------------------------------------------------------------------

/// Type-erased listener owned by a protocol module. TCP-style listeners
/// drain on retire; UDP-style listeners are destroyed immediately.
pub const Listener = struct {
    allocator: Allocator,
    context: *anyopaque,
    stop_accepting_fn: *const fn (context: *anyopaque) void,
    destroy_fn: *const fn (allocator: Allocator, context: *anyopaque) void,
    update_configuration_fn: *const fn (context: *anyopaque, resolved: ResolvedConfiguration, reset_sessions: bool) void,
    update_backlog_fn: ?*const fn (context: *anyopaque, backlog: i32) anyerror!void,
    force_close_fn: *const fn (context: *anyopaque) void,
    active_count_fn: *const fn (context: *anyopaque) usize,
    buffered_bytes_fn: *const fn (context: *anyopaque) i64,
    associations_fn: *const fn (context: *anyopaque) u64,

    pub fn stopAccepting(self: *Listener) void {
        self.stop_accepting_fn(self.context);
    }

    pub fn destroy(self: *Listener) void {
        self.destroy_fn(self.allocator, self.context);
        self.allocator.destroy(self);
    }

    pub fn updateConfiguration(self: *Listener, resolved: ResolvedConfiguration, reset_sessions: bool) void {
        self.update_configuration_fn(self.context, resolved, reset_sessions);
    }

    /// No-op for protocols without a listen backlog (UDP).
    pub fn updateBacklog(self: *Listener, backlog: i32) anyerror!void {
        if (self.update_backlog_fn) |f| try f(self.context, backlog);
    }

    pub fn forceCloseConnections(self: *Listener) void {
        self.force_close_fn(self.context);
    }

    pub fn activeConnectionCount(self: *Listener) usize {
        return self.active_count_fn(self.context);
    }

    pub fn bufferedBytesUsed(self: *Listener) i64 {
        return self.buffered_bytes_fn(self.context);
    }

    pub fn associationCount(self: *Listener) u64 {
        return self.associations_fn(self.context);
    }
};

/// A protocol module registers one entry in fw.protocol_modules; the
/// orchestrator spawns listeners through it instead of hardcoding TCP/UDP.
pub const ProtocolModule = struct {
    name: []const u8,
    protocol: ForwardProtocol,
    /// TCP-style listeners park for connection draining on retire.
    drains_connections: bool,
    create: *const fn (allocator: Allocator, resolved: ResolvedConfiguration, logger: *log.LogStore, selector: ?upstream.Selector) anyerror!*Listener,
};

// ---------------------------------------------------------------------------
// Module declaration: version / protocols / listen / upstream (root sugar)
// ---------------------------------------------------------------------------

/// Mutable static so the composed configuration can hand out a mutable
/// slice; the contents are never modified.
var default_protocols = [_]ForwardProtocol{ .tcp, .udp };

pub const Conf = struct {
    version: i64 = 1,
    protocols: ?[]ForwardProtocol = null,
    listen_node: ?*yaml.Value = null,
    upstream_node: ?*yaml.Value = null,
    /// Decoded in finalize (single-rule mode only).
    listen: ?EndpointConfiguration = null,
    upstream: ?EndpointConfiguration = null,
};

pub const module: fw.Module = .{
    .name = "core",
    .index = .core,
    .directives = &directives,
    .create_conf = createConf,
    .finalize = finalize,
    .validate = validate,
};

const directives = [_]fw.Directive{
    .{ .name = "version", .root = true, .set = setVersion },
    .{ .name = "protocols", .root = true, .set = setProtocols },
    .{ .name = "listen", .root = true, .set = setListen },
    .{ .name = "upstream", .root = true, .set = setUpstream },
};

fn createConf(cycle: *conf.Cycle) error{OutOfMemory}!*anyopaque {
    const c = try cycle.allocator().create(Conf);
    c.* = .{};
    return c;
}

fn setVersion(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c: *Conf = @ptrCast(@alignCast(slot));
    c.version = try yaml.decodeInt(cycle.gpa, cycle.diag, value, "version");
}

fn setProtocols(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = path;
    const c: *Conf = @ptrCast(@alignCast(slot));
    c.protocols = try rules.decodeProtocols(cycle, value);
}

fn setListen(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = cycle;
    _ = path;
    const c: *Conf = @ptrCast(@alignCast(slot));
    c.listen_node = value;
}

fn setUpstream(cycle: *conf.Cycle, slot: *anyopaque, value: *yaml.Value, path: []const u8) yaml.LoadError!void {
    _ = cycle;
    _ = path;
    const c: *Conf = @ptrCast(@alignCast(slot));
    c.upstream_node = value;
}

/// Cross-key decoding after every directive ran: the upstream port defaults
/// to the listen port, so the order of keys in the document must not matter.
fn finalize(cycle: *conf.Cycle) yaml.LoadError!void {
    if (cycle.rules_mode) return;
    const c = cycle.conf(@This());

    const listen_node = c.listen_node orelse
        return yaml.fail(cycle.gpa, cycle.diag, "missing required key: listen", .{});
    c.listen = try decodeListen(cycle, listen_node);

    const upstream_node = c.upstream_node orelse
        return yaml.fail(cycle.gpa, cycle.diag, "missing required key: upstream", .{});
    c.upstream = try decodeUpstreamEndpoint(cycle, upstream_node, c.listen.?.port);
}

fn decodeListen(cycle: *conf.Cycle, value: *yaml.Value) yaml.LoadError!EndpointConfiguration {
    const map = try yaml.requireMapping(cycle.gpa, cycle.diag, value, "listen");
    try yaml.checkKeys(cycle.gpa, cycle.diag, map, &.{ "host", "port" }, "listen");
    var endpoint = EndpointConfiguration{ .host = "*", .port = 0 };
    if (yaml.mappingGet(map, "host")) |v| {
        endpoint.host = try yaml.decodeString(cycle.gpa, cycle.diag, v, "listen.host");
    }
    const port_value = yaml.mappingGet(map, "port") orelse
        return yaml.fail(cycle.gpa, cycle.diag, "missing required key: listen.port", .{});
    endpoint.port = try yaml.decodeInt(cycle.gpa, cycle.diag, port_value, "listen.port");
    return endpoint;
}

fn decodeUpstreamEndpoint(cycle: *conf.Cycle, value: *yaml.Value, listen_port: i64) yaml.LoadError!EndpointConfiguration {
    const map = try yaml.requireMapping(cycle.gpa, cycle.diag, value, "upstream");
    try yaml.checkKeys(cycle.gpa, cycle.diag, map, &.{ "host", "port" }, "upstream");
    const host_value = yaml.mappingGet(map, "host") orelse
        return yaml.fail(cycle.gpa, cycle.diag, "missing required key: upstream.host", .{});
    const host = try yaml.decodeString(cycle.gpa, cycle.diag, host_value, "upstream.host");
    var port = listen_port;
    if (yaml.mappingGet(map, "port")) |v| {
        port = try yaml.decodeInt(cycle.gpa, cycle.diag, v, "upstream.port");
    }
    return .{ .host = host, .port = port };
}

fn validate(cycle: *conf.Cycle) yaml.LoadError!void {
    const c = cycle.conf(@This());
    const gpa = cycle.gpa;
    const diag = cycle.diag;

    if (c.version != 1) {
        yaml.setDiag(gpa, diag, "unsupported configuration version: {d}", .{c.version});
        return error.InvalidConfiguration;
    }
    try net.validateProtocols(gpa, diag, c.protocols orelse &default_protocols, "");

    if (cycle.rules_mode) return;
    if (std.mem.trim(u8, c.listen.?.host, " \t\n\r").len == 0) {
        yaml.setDiag(gpa, diag, "listen.host must not be empty", .{});
        return error.InvalidConfiguration;
    }
    if (std.mem.trim(u8, c.upstream.?.host, " \t\n\r").len == 0) {
        yaml.setDiag(gpa, diag, "upstream.host must not be empty", .{});
        return error.InvalidConfiguration;
    }
    if (c.listen.?.port < 1 or c.listen.?.port > 65_535) {
        yaml.setDiag(gpa, diag, "listen.port must be between 1 and 65535", .{});
        return error.InvalidConfiguration;
    }
    if (c.upstream.?.port < 1 or c.upstream.?.port > 65_535) {
        yaml.setDiag(gpa, diag, "upstream.port must be between 1 and 65535", .{});
        return error.InvalidConfiguration;
    }
}

// ---------------------------------------------------------------------------
// Composition and resolution
// ---------------------------------------------------------------------------

/// The global configuration view composed from every module's conf.
pub fn configuration(cycle: *conf.Cycle) ForwarderConfiguration {
    const c = cycle.conf(@This());
    return .{
        .version = c.version,
        .protocols = c.protocols orelse &default_protocols,
        .listen = c.listen orelse .{ .host = "*", .port = 0 },
        .upstream = c.upstream orelse .{ .host = "", .port = 0 },
        .timeouts = cycle.conf(timeouts).*,
        .limits = cycle.conf(limits).*,
        .logging = cycle.conf(logging).*,
        .runtime = cycle.conf(runtime).*,
        .performance = cycle.conf(performance).*,
    };
}

/// merge_conf analogue: global sections plus rule overrides.
pub fn effectiveConfiguration(globals: ForwarderConfiguration, rule: RuleConfiguration) ForwarderConfiguration {
    var effective = globals;
    effective.protocols = rule.protocols orelse globals.protocols;
    effective.listen = rule.listen;
    effective.upstream = .{ .host = rule.upstreams[0].host, .port = rule.upstreams[0].port };
    effective.timeouts = timeouts.merge(globals.timeouts, rule.timeouts);
    effective.limits = limits.merge(globals.limits, rule.limits);
    return effective;
}

/// Resolve every rule's listen/upstream endpoints. `gpa` backs diagnostics;
/// `alloc` backs the returned slices and must outlive them (pass the cycle
/// arena). A single-rule document resolves to one synthesized rule.
pub fn resolveForwarder(
    gpa: Allocator,
    alloc: Allocator,
    cycle: *conf.Cycle,
    resolver: ?Resolver,
    diag: *conf.Diagnostics,
) ResolveError!ResolvedForwarder {
    const resolve = resolver orelse net.defaultResolver;
    const globals = configuration(cycle);

    const definitions: []RuleConfiguration = blk: {
        if (cycle.rules_mode) break :blk rules.rulesList(cycle);
        const single = try alloc.alloc(RuleConfiguration, 1);
        const single_upstreams = try alloc.alloc(rules.UpstreamConfiguration, 1);
        single_upstreams[0] = .{ .host = globals.upstream.host, .port = globals.upstream.port };
        single[0] = .{
            .listen = globals.listen,
            .upstreams = single_upstreams,
            .balance = upstream.defaultBalancer(),
        };
        break :blk single;
    };

    const resolved_rules = try alloc.alloc(ResolvedRule, definitions.len);
    for (definitions, 0..) |definition, i| {
        const listen_port: u16 = @intCast(definition.listen.port);
        const listen_addresses = net.resolveListenAddresses(resolve, alloc, definition.listen.host, listen_port, gpa, diag) catch
            return error.ResolutionFailed;

        const upstream_addresses = try alloc.alloc(SocketAddr, definition.upstreams.len);
        for (definition.upstreams, 0..) |entry, j| {
            const upstream_port: u16 = @intCast(entry.port);
            upstream_addresses[j] = net.resolverAddress(resolve, entry.host, upstream_port, gpa, diag) catch
                return error.ResolutionFailed;
        }

        resolved_rules[i] = .{
            .rule = definition,
            .effective = effectiveConfiguration(globals, definition),
            .listen_addresses = listen_addresses,
            .upstream_addresses = upstream_addresses,
        };
    }

    for (resolved_rules, 0..) |*a, i| {
        for (resolved_rules[i + 1 ..], i + 1..) |*b, j| {
            if (rulesConflict(a, b)) |protocol| {
                net.setDiag(gpa, diag, "rules {d} and {d} listen on the same address for protocol {s}", .{ i, j, @tagName(protocol) });
                return error.ResolutionFailed;
            }
        }
    }

    return .{
        .configuration = globals,
        .rules = resolved_rules,
        .rules_mode = cycle.rules_mode,
    };
}

/// Two rules conflict when they share a concrete listen address and serve an
/// overlapping protocol: both would bind the same socket with SO_REUSEPORT
/// and silently split traffic.
fn rulesConflict(a: *const ResolvedRule, b: *const ResolvedRule) ?ForwardProtocol {
    for (a.effectiveProtocols()) |protocol| {
        var shared_protocol = false;
        for (b.effectiveProtocols()) |other| {
            if (protocol == other) {
                shared_protocol = true;
                break;
            }
        }
        if (!shared_protocol) continue;
        for (a.listen_addresses) |addr_a| {
            for (b.listen_addresses) |addr_b| {
                if (addr_a.eql(addr_b)) return protocol;
            }
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// RuleRuntime: one rule's pool plus its listener pair
// ---------------------------------------------------------------------------

/// Heap-allocated and never moved: selector contexts captured by the
/// listeners point at the embedded pool.
const RuleRuntime = struct {
    /// Current generation's rule (backs slices live in a retained cycle arena).
    rule: RuleConfiguration,
    /// Per-rule view handed to the listeners; listen_addresses is the rule
    /// identity used for reload diffing and never changes in place.
    resolved: ResolvedConfiguration,
    pool: upstream.UpstreamPool,
    balance: *const upstream.Balancer,
    tcp_listener: ?*Listener = null,
    udp_listener: ?*Listener = null,
    /// Thread counts the listeners were started with (change needs restart).
    started_worker_threads: i64,
    started_udp_io_threads: i64,
};

pub const ForwarderService = struct {
    allocator: Allocator,
    configuration_path: []const u8,
    loaded: conf.Cycle,
    resolved: ResolvedForwarder,
    logger: log.LogStore,
    worker_threads: i64,
    /// Global-section view for the tuning daemon (which only reads limits).
    tuning_view: ResolvedConfiguration,

    mutex: log.Mutex = .{},
    rules_list: std.ArrayList(*RuleRuntime) = .empty,
    retired_rules: std.ArrayList(*RuleRuntime) = .empty,
    /// TCP listeners parked for draining after their protocol was removed
    /// from a surviving rule (the pool stays with the rule).
    retired_tcp_listeners: std.ArrayList(*Listener) = .empty,
    retained_cycles: std.ArrayList(conf.Cycle) = .empty,
    tuning_daemon: ?tuning.TuningDaemon = null,
    shutting_down: bool = false,

    pub fn init(
        allocator: Allocator,
        configuration_path: []const u8,
        loaded: conf.Cycle,
        resolved: ResolvedForwarder,
    ) ForwarderService {
        return .{
            .allocator = allocator,
            .configuration_path = configuration_path,
            .loaded = loaded,
            .resolved = resolved,
            .logger = log.LogStore.init(resolved.configuration.logging.level),
            .worker_threads = autotune.workerThreads(resolved.configuration.runtime.worker_threads, .system()),
            .tuning_view = tuningViewFor(resolved.configuration, resolved.rules),
        };
    }

    pub fn deinit(self: *ForwarderService) void {
        self.stopTuningDaemon();
        for (self.rules_list.items) |rt| self.destroyRuleRuntime(rt);
        self.rules_list.deinit(self.allocator);
        self.reapRetiredRules(true);
        self.retired_rules.deinit(self.allocator);
        self.retired_tcp_listeners.deinit(self.allocator);
        for (self.retained_cycles.items) |*old| old.deinit();
        self.retained_cycles.deinit(self.allocator);
        self.loaded.deinit();
    }

    pub fn run(self: *ForwarderService) Error!void {
        var signals = signalMask();
        posix.sigprocmask(posix.SIG.BLOCK, &signals, null);
        const signal_fd = try posix.signalfd(-1, &signals, linux.SFD.CLOEXEC | linux.SFD.NONBLOCK);
        defer _ = linux.close(signal_fd);

        self.logger.info(
            "runtime tuned worker_threads={d} rules={d} tcp_listen_backlog={d} max_tcp_buffered_bytes={d} max_udp_associations={d}",
            .{
                self.worker_threads,
                self.resolved.rules.len,
                self.resolved.configuration.limits.tcp_listen_backlog,
                self.resolved.configuration.limits.max_tcp_buffered_bytes,
                self.resolved.configuration.limits.max_udp_associations,
            },
        );

        try self.startInitialRules();
        self.startTuningDaemonIfNeeded();
        self.logger.info("forwarder started rules={d}", .{self.rules_list.items.len});

        while (!self.shutting_down) {
            self.pollSignals(signal_fd);
            self.reapRetiredRules(false);
        }

        self.shutdownRules();
    }

    // ------------------------------------------------------------------
    // Startup and shutdown
    // ------------------------------------------------------------------

    fn startInitialRules(self: *ForwarderService) Error!void {
        errdefer {
            for (self.rules_list.items) |rt| self.destroyRuleRuntime(rt);
            self.rules_list.clearRetainingCapacity();
        }
        try self.rules_list.ensureTotalCapacity(self.allocator, self.resolved.rules.len);
        for (self.resolved.rules) |*candidate| {
            const rt = try self.createRuleRuntime(candidate, self.resolved.rules.len);
            self.rules_list.appendAssumeCapacity(rt);
        }
    }

    fn shutdownRules(self: *ForwarderService) void {
        self.stopTuningDaemon();

        self.mutex.lock();
        const grace_seconds = self.resolved.configuration.timeouts.shutdown_grace_seconds;
        for (self.rules_list.items) |rt| {
            if (rt.tcp_listener) |listener| listener.stopAccepting();
            if (rt.udp_listener) |listener| {
                listener.destroy();
                rt.udp_listener = null;
            }
            self.retired_rules.append(self.allocator, rt) catch {
                self.destroyRuleRuntime(rt);
            };
        }
        self.rules_list.clearRetainingCapacity();
        self.mutex.unlock();

        const deadline = monotonicNowNs() + @as(u64, @intCast(grace_seconds)) * std.time.ns_per_s;
        while (monotonicNowNs() < deadline and self.retiredConnectionCount() > 0) {
            sleepNs(50 * std.time.ns_per_ms);
        }

        const remaining = self.retiredConnectionCount();
        if (remaining > 0) {
            self.logger.warning("forcing tcp connections closed count={d}", .{remaining});
            for (self.retired_rules.items) |rt| {
                if (rt.tcp_listener) |listener| listener.forceCloseConnections();
            }
            for (self.retired_tcp_listeners.items) |listener| listener.forceCloseConnections();
        }
        self.reapRetiredRules(true);
        self.logger.info("forwarder stopped", .{});
    }

    // ------------------------------------------------------------------
    // Rule lifecycle
    // ------------------------------------------------------------------

    fn createRuleRuntime(
        self: *ForwarderService,
        candidate: *const ResolvedRule,
        rule_count: usize,
    ) Error!*RuleRuntime {
        const effective = adjustedEffective(candidate, rule_count);
        const weights = try self.ruleWeights(candidate.rule);
        defer self.allocator.free(weights);

        const rt = try self.allocator.create(RuleRuntime);
        errdefer self.allocator.destroy(rt);
        rt.* = .{
            .rule = candidate.rule,
            .resolved = resolvedForRule(effective, candidate),
            .pool = try upstream.UpstreamPool.init(
                self.allocator,
                candidate.upstream_addresses,
                weights,
                candidate.rule.balance,
            ),
            .balance = candidate.rule.balance,
            .started_worker_threads = effective.runtime.worker_threads,
            .started_udp_io_threads = effective.performance.udp_io_threads,
        };
        errdefer rt.pool.deinit();

        const protocols = candidate.effectiveProtocols();
        if (net.hasProtocol(protocols, .tcp)) {
            rt.tcp_listener = try self.createListener(candidate, rt, .tcp);
        }
        errdefer if (rt.tcp_listener) |listener| listener.destroy();
        if (net.hasProtocol(protocols, .udp)) {
            rt.udp_listener = try self.createListener(candidate, rt, .udp);
        }

        var protocol_buf: [32]u8 = undefined;
        self.logger.info("rule started listen={f} protocols={s} upstreams={d} balance={s}", .{
            candidate.listen_addresses[0],
            net.protocolsString(protocols, &protocol_buf),
            candidate.upstream_addresses.len,
            candidate.rule.balance.name,
        });
        return rt;
    }

    /// Spawn one protocol listener through the protocol module registry. The
    /// pool selector stays attached across reloads so single/multi-upstream
    /// transitions do not require rebinding the listen sockets.
    fn createListener(self: *ForwarderService, candidate: *const ResolvedRule, rt: *RuleRuntime, protocol: ForwardProtocol) Error!*Listener {
        _ = candidate;
        return fw.protocolModule(protocol).create(
            self.allocator,
            rt.resolved,
            &self.logger,
            upstream.poolSelector(&rt.pool),
        );
    }

    /// Update a matched rule in place: pool upstream set, protocol toggles,
    /// effective configuration. Existing TCP connections keep their upstream;
    /// UDP associations are reset when the upstream set changed.
    fn updateRule(
        self: *ForwarderService,
        rt: *RuleRuntime,
        candidate: *const ResolvedRule,
        rule_count: usize,
    ) Error!void {
        const effective = adjustedEffective(candidate, rule_count);
        const new_resolved = resolvedForRule(effective, candidate);

        if (effective.runtime.worker_threads != rt.started_worker_threads) {
            self.logger.warning("runtime worker thread change requires restart current={d} requested={d}", .{
                rt.started_worker_threads,
                effective.runtime.worker_threads,
            });
        }
        if (effective.performance.udp_io_threads != rt.started_udp_io_threads) {
            self.logger.warning("udp io thread change requires restart current={d} requested={d}", .{
                rt.started_udp_io_threads,
                effective.performance.udp_io_threads,
            });
        }

        // Publish upstream and balance changes as one generation. Listener
        // threads keep selecting without a lock, and matching addresses carry
        // their health state into the new generation.
        const upstream_changed = !rt.pool.addressesEqual(candidate.upstream_addresses);
        const weights_changed = !ruleWeightsEqual(rt.rule, candidate.rule);
        if (candidate.rule.balance != rt.balance or upstream_changed or weights_changed) {
            const weights = try self.ruleWeights(candidate.rule);
            defer self.allocator.free(weights);
            try rt.pool.reconfigure(
                candidate.upstream_addresses,
                weights,
                candidate.rule.balance,
            );
        }

        const protocols = candidate.effectiveProtocols();
        const want_tcp = net.hasProtocol(protocols, .tcp);
        const want_udp = net.hasProtocol(protocols, .udp);

        var added_tcp: ?*Listener = null;
        var added_udp: ?*Listener = null;
        errdefer {
            if (added_tcp) |listener| listener.destroy();
            if (added_udp) |listener| listener.destroy();
        }

        if (want_tcp and rt.tcp_listener == null) added_tcp = try self.createListener(candidate, rt, .tcp);
        if (want_udp and rt.udp_listener == null) added_udp = try self.createListener(candidate, rt, .udp);

        const backlog_changed =
            rt.resolved.configuration.limits.tcp_listen_backlog != new_resolved.configuration.limits.tcp_listen_backlog;
        if (backlog_changed) {
            const listener = rt.tcp_listener orelse added_tcp;
            if (listener) |l| try l.updateBacklog(@intCast(new_resolved.configuration.limits.tcp_listen_backlog));
        }

        if (rt.tcp_listener orelse added_tcp) |listener| listener.updateConfiguration(new_resolved, false);
        if (rt.udp_listener orelse added_udp) |listener| listener.updateConfiguration(new_resolved, upstream_changed);

        if (added_tcp) |listener| {
            rt.tcp_listener = listener;
            added_tcp = null;
        }
        if (added_udp) |listener| {
            rt.udp_listener = listener;
            added_udp = null;
        }

        if (!want_tcp) {
            if (rt.tcp_listener) |listener| {
                listener.stopAccepting();
                // The pool stays with the surviving rule; only the listener
                // is parked for draining.
                self.retired_tcp_listeners.append(self.allocator, listener) catch {
                    listener.forceCloseConnections();
                    listener.destroy();
                };
                rt.tcp_listener = null;
            }
        }
        if (!want_udp) {
            if (rt.udp_listener) |listener| {
                listener.destroy();
                rt.udp_listener = null;
            }
        }

        rt.rule = candidate.rule;
        rt.resolved = new_resolved;
        rt.balance = candidate.rule.balance;
    }

    fn destroyRuleRuntime(self: *ForwarderService, rt: *RuleRuntime) void {
        if (rt.tcp_listener) |listener| {
            listener.destroy();
            rt.tcp_listener = null;
        }
        if (rt.udp_listener) |listener| {
            listener.destroy();
            rt.udp_listener = null;
        }
        rt.pool.deinit();
        self.allocator.destroy(rt);
    }

    /// Stops accepting and parks the rule until its TCP connections drain;
    /// UDP stops immediately.
    fn retireRule(self: *ForwarderService, rt: *RuleRuntime) void {
        if (rt.tcp_listener) |listener| listener.stopAccepting();
        if (rt.udp_listener) |listener| {
            listener.destroy();
            rt.udp_listener = null;
        }
        if (rt.tcp_listener == null) {
            self.destroyRuleRuntime(rt);
            return;
        }
        self.retired_rules.append(self.allocator, rt) catch {
            if (rt.tcp_listener) |listener| listener.forceCloseConnections();
            self.destroyRuleRuntime(rt);
        };
    }

    fn reapRetiredRules(self: *ForwarderService, force: bool) void {
        var i: usize = 0;
        while (i < self.retired_rules.items.len) {
            const rt = self.retired_rules.items[i];
            if (!force and rt.tcp_listener != null and
                rt.tcp_listener.?.activeConnectionCount() != 0)
            {
                i += 1;
                continue;
            }
            self.destroyRuleRuntime(rt);
            _ = self.retired_rules.swapRemove(i);
        }
        var j: usize = 0;
        while (j < self.retired_tcp_listeners.items.len) {
            const listener = self.retired_tcp_listeners.items[j];
            if (!force and listener.activeConnectionCount() != 0) {
                j += 1;
                continue;
            }
            listener.destroy();
            _ = self.retired_tcp_listeners.swapRemove(j);
        }
    }

    fn retiredConnectionCount(self: *ForwarderService) usize {
        var count: usize = 0;
        for (self.retired_rules.items) |rt| {
            if (rt.tcp_listener) |listener| count += listener.activeConnectionCount();
        }
        for (self.retired_tcp_listeners.items) |listener| {
            count += listener.activeConnectionCount();
        }
        return count;
    }

    fn findRule(self: *ForwarderService, listen_addresses: []const SocketAddr) ?usize {
        for (self.rules_list.items, 0..) |rt, i| {
            if (net.addressesEqual(rt.resolved.listen_addresses, listen_addresses)) return i;
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Signals and reload
    // ------------------------------------------------------------------

    fn pollSignals(self: *ForwarderService, signal_fd: posix.fd_t) void {
        var fds = [_]posix.pollfd{.{
            .fd = signal_fd,
            .events = linux.POLL.IN,
            .revents = 0,
        }};
        const ready = posix.poll(&fds, reap_interval_ms) catch |err| {
            self.logger.err("signal poll failed error={s}", .{@errorName(err)});
            return;
        };
        if (ready == 0 or (fds[0].revents & linux.POLL.IN) == 0) return;

        while (true) {
            var info: linux.signalfd_siginfo = undefined;
            const rc = linux.read(signal_fd, @ptrCast(&info), @sizeOf(linux.signalfd_siginfo));
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc != @sizeOf(linux.signalfd_siginfo)) return;
                    self.handleSignal(@enumFromInt(info.signo));
                },
                .AGAIN => return,
                .INTR => continue,
                else => |err| {
                    self.logger.err("signal read failed errno={s}", .{@tagName(err)});
                    return;
                },
            }
        }
    }

    fn handleSignal(self: *ForwarderService, signal: linux.SIG) void {
        switch (signal) {
            .HUP => self.reload(),
            .INT => self.requestShutdown("SIGINT"),
            .TERM => self.requestShutdown("SIGTERM"),
            .PIPE => {},
            else => {},
        }
    }

    fn reload(self: *ForwarderService) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return;

        self.logger.info("reloading configuration path={s}", .{self.configuration_path});

        var diag = conf.Diagnostics{};
        defer if (diag.message) |message| self.allocator.free(message);

        // A reload runs a fresh configuration cycle through the module
        // engine, then diffs it against the live one.
        var cycle = conf.loadFile(self.allocator, self.configuration_path, &diag) catch |err| {
            self.logger.err("configuration reload rejected error={s} reason={s}", .{
                @errorName(err),
                diag.message orelse "unknown error",
            });
            return;
        };
        var owns_cycle = true;
        defer if (owns_cycle) cycle.deinit();

        if (cycle.rules_mode != self.resolved.rules_mode) {
            if (cycle.rules_mode) {
                self.logger.warning("configuration now uses rules; restart required to apply rules mode", .{});
            } else {
                self.logger.warning("configuration no longer uses rules; restart required to apply single-rule mode", .{});
            }
            return;
        }

        const candidate = resolveForwarder(
            self.allocator,
            cycle.allocator(),
            &cycle,
            null,
            &diag,
        ) catch |err| {
            self.logger.err("configuration reload rejected error={s} reason={s}", .{
                @errorName(err),
                diag.message orelse "unknown error",
            });
            return;
        };

        self.retained_cycles.ensureUnusedCapacity(self.allocator, 1) catch |err| {
            self.logger.err("configuration reload rejected error={s}", .{@errorName(err)});
            return;
        };

        self.apply(candidate) catch |err| {
            self.logger.err("configuration reload rejected error={s}", .{@errorName(err)});
            return;
        };

        self.retained_cycles.appendAssumeCapacity(self.loaded);
        self.loaded = cycle;
        owns_cycle = false;
        self.resolved = candidate;
        self.logger.update(candidate.configuration.logging.level);
        self.logger.info("configuration reloaded rules={d}", .{candidate.rules.len});
    }

    fn apply(self: *ForwarderService, candidate: ResolvedForwarder) Error!void {
        const requested_worker_threads = autotune.workerThreads(candidate.configuration.runtime.worker_threads, .system());
        if (requested_worker_threads != self.worker_threads) {
            self.logger.warning("runtime worker thread change requires restart current={d} requested={d}", .{
                self.worker_threads,
                requested_worker_threads,
            });
        }
        if (candidate.configuration.runtime.tuning_daemon != (self.tuning_daemon != null)) {
            self.logger.warning("runtime tuning daemon enablement change requires restart", .{});
        }

        var created: std.ArrayList(*RuleRuntime) = .empty;
        defer created.deinit(self.allocator);
        errdefer for (created.items) |rt| self.destroyRuleRuntime(rt);

        var next_rules: std.ArrayList(*RuleRuntime) = .empty;
        errdefer next_rules.deinit(self.allocator);

        const matched = try self.allocator.alloc(bool, self.rules_list.items.len);
        defer self.allocator.free(matched);
        @memset(matched, false);

        try next_rules.ensureTotalCapacity(self.allocator, candidate.rules.len);
        try created.ensureTotalCapacity(self.allocator, candidate.rules.len);
        for (candidate.rules) |*candidate_rule| {
            if (self.findRule(candidate_rule.listen_addresses)) |index| {
                matched[index] = true;
                try self.updateRule(self.rules_list.items[index], candidate_rule, candidate.rules.len);
                next_rules.appendAssumeCapacity(self.rules_list.items[index]);
            } else {
                const rt = try self.createRuleRuntime(candidate_rule, candidate.rules.len);
                created.appendAssumeCapacity(rt);
                next_rules.appendAssumeCapacity(rt);
            }
        }

        for (self.rules_list.items, 0..) |old, i| {
            if (!matched[i]) self.retireRule(old);
        }
        self.rules_list.deinit(self.allocator);
        self.rules_list = next_rules;
        self.tuning_view = tuningViewFor(candidate.configuration, candidate.rules);
    }

    fn requestShutdown(self: *ForwarderService, reason: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return;
        self.shutting_down = true;
        self.logger.info("shutdown requested signal={s}", .{reason});
    }

    // ------------------------------------------------------------------
    // Tuning daemon
    // ------------------------------------------------------------------

    fn startTuningDaemonIfNeeded(self: *ForwarderService) void {
        if (!self.resolved.configuration.runtime.tuning_daemon) return;
        self.tuning_daemon = tuning.TuningDaemon.init(
            self.resolved.configuration.runtime.tuning_interval_seconds,
            &self.logger,
            self,
            snapshotProvider,
            self,
            applyTunedLimitsCallback,
        );
        self.tuning_daemon.?.start();
    }

    fn stopTuningDaemon(self: *ForwarderService) void {
        if (self.tuning_daemon) |*daemon| daemon.stop();
        self.tuning_daemon = null;
    }

    fn snapshot(self: *ForwarderService) ?tuning.TuningSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return null;
        var tcp_buffered: i64 = 0;
        var udp_associations: u64 = 0;
        for (self.rules_list.items) |rt| {
            if (rt.tcp_listener) |listener| tcp_buffered += listener.bufferedBytesUsed();
            if (rt.udp_listener) |listener| udp_associations += listener.associationCount();
        }
        return .{
            .configuration = self.tuning_view,
            .tcp_buffered_bytes = tcp_buffered,
            .udp_associations = @intCast(udp_associations),
        };
    }

    /// Push new global auto-tuned limits into every rule, honoring per-rule
    /// explicit overrides.
    fn applyTunedLimits(self: *ForwarderService, new_limits: LimitConfiguration) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return;

        self.resolved.configuration.limits = new_limits;
        self.tuning_view.configuration.limits = new_limits;

        for (self.rules_list.items) |rt| {
            const old_effective = rt.resolved.configuration;
            var new_effective = old_effective;
            new_effective.limits = limits.merge(new_limits, rt.rule.limits);
            if (std.meta.eql(old_effective.limits, new_effective.limits)) continue;

            if (new_effective.limits.tcp_listen_backlog != old_effective.limits.tcp_listen_backlog) {
                if (rt.tcp_listener) |listener| {
                    listener.updateBacklog(@intCast(new_effective.limits.tcp_listen_backlog)) catch |err| {
                        self.logger.warning("tuning daemon backlog update failed error={s}", .{@errorName(err)});
                        new_effective.limits.tcp_listen_backlog = old_effective.limits.tcp_listen_backlog;
                    };
                }
            }

            const new_resolved = ResolvedConfiguration{
                .configuration = new_effective,
                .listen_addresses = rt.resolved.listen_addresses,
                .upstream_address = rt.resolved.upstream_address,
            };
            if (rt.tcp_listener) |listener| listener.updateConfiguration(new_resolved, false);
            if (rt.udp_listener) |listener| listener.updateConfiguration(new_resolved, false);
            rt.resolved = new_resolved;
        }
    }

    fn ruleWeights(self: *ForwarderService, rule: RuleConfiguration) Allocator.Error![]u32 {
        const weights = try self.allocator.alloc(u32, rule.upstreams.len);
        for (rule.upstreams, 0..) |entry, i| weights[i] = @intCast(entry.weight);
        return weights;
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ruleWeightsEqual(a: RuleConfiguration, b: RuleConfiguration) bool {
    if (a.upstreams.len != b.upstreams.len) return false;
    for (a.upstreams, b.upstreams) |old, new| {
        if (old.weight != new.weight) return false;
    }
    return true;
}

/// Rule overrides plus auto thread pools divided across rules when more
/// than one rule exists.
fn adjustedEffective(candidate: *const ResolvedRule, rule_count: usize) ForwarderConfiguration {
    var effective = candidate.effective;
    if (rule_count > 1) {
        const total = autotune.workerThreads(0, .system());
        const divisor: i64 = @intCast(rule_count);
        if (effective.runtime.worker_threads == 0) {
            effective.runtime.worker_threads = @max(1, @divTrunc(total, divisor));
        }
        if (effective.performance.udp_io_threads == 0) {
            effective.performance.udp_io_threads = @max(1, @divTrunc(total, divisor));
        }
    }
    return effective;
}

fn resolvedForRule(effective: ForwarderConfiguration, candidate: *const ResolvedRule) ResolvedConfiguration {
    return .{
        .configuration = effective,
        .listen_addresses = candidate.listen_addresses,
        .upstream_address = candidate.upstream_addresses[0],
    };
}

/// Global-section snapshot for the tuning daemon; only limits is consumed.
fn tuningViewFor(globals: ForwarderConfiguration, resolved_rules: []const ResolvedRule) ResolvedConfiguration {
    return .{
        .configuration = globals,
        .listen_addresses = resolved_rules[0].listen_addresses,
        .upstream_address = resolved_rules[0].upstream_addresses[0],
    };
}

fn signalMask() posix.sigset_t {
    var signals = posix.sigemptyset();
    posix.sigaddset(&signals, .INT);
    posix.sigaddset(&signals, .TERM);
    posix.sigaddset(&signals, .HUP);
    posix.sigaddset(&signals, .PIPE);
    return signals;
}

fn snapshotProvider(context: ?*anyopaque) ?tuning.TuningSnapshot {
    const service: *ForwarderService = @ptrCast(@alignCast(context.?));
    return service.snapshot();
}

fn applyTunedLimitsCallback(context: ?*anyopaque, new_limits: LimitConfiguration) void {
    const service: *ForwarderService = @ptrCast(@alignCast(context.?));
    service.applyTunedLimits(new_limits);
}

fn monotonicNowNs() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn sleepNs(ns: u64) void {
    var request = linux.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    while (linux.errno(linux.nanosleep(&request, &request)) == .INTR) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn loadForTest(text: []const u8) !conf.Cycle {
    var diag = conf.Diagnostics{};
    return conf.loadYaml(testing.allocator, text, &diag) catch |err| {
        if (diag.message) |message| {
            std.debug.print("unexpected load failure: {s}\n", .{message});
            testing.allocator.free(message);
        }
        return err;
    };
}

test "loads defaults" {
    var cycle = try loadForTest(
        \\listen:
        \\  port: 9000
        \\upstream:
        \\  host: "localhost"
        \\
    );
    defer cycle.deinit();
    try testing.expect(!cycle.rules_mode);
    const config = configuration(&cycle);
    const auto_limits = autotune.limits(.system());

    try testing.expectEqual(1, config.version);
    try testing.expectEqualSlices(ForwardProtocol, &.{ .tcp, .udp }, config.protocols);
    try testing.expectEqualStrings("*", config.listen.host);
    try testing.expectEqual(9_000, config.listen.port);
    try testing.expectEqualStrings("localhost", config.upstream.host);
    try testing.expectEqual(9_000, config.upstream.port);
    try testing.expectEqual(5, config.timeouts.connect_seconds);
    try testing.expectEqual(300, config.timeouts.tcp_idle_seconds);
    try testing.expectEqual(60, config.timeouts.udp_session_seconds);
    try testing.expectEqual(10, config.timeouts.shutdown_grace_seconds);
    try testing.expectEqual(auto_limits.tcp_listen_backlog, config.limits.tcp_listen_backlog);
    try testing.expectEqual(auto_limits.max_tcp_buffered_bytes, config.limits.max_tcp_buffered_bytes);
    try testing.expectEqual(auto_limits.max_udp_associations, config.limits.max_udp_associations);
    try testing.expectEqual(auto_limits.max_udp_pending_datagrams, config.limits.max_udp_pending_datagrams);
    try testing.expectEqual(auto_limits.max_udp_pending_bytes, config.limits.max_udp_pending_bytes);
    try testing.expectEqual(0, config.runtime.worker_threads);
    try testing.expect(config.runtime.tuning_daemon);
    try testing.expectEqual(5, config.runtime.tuning_interval_seconds);
    try testing.expect(config.limits.auto_tuning.max_tcp_buffered_bytes);
    try testing.expectEqualStrings("info", config.logging.level);
    try testing.expectEqual(SockmapAccelerationMode.auto, config.performance.tcp_sockmap_acceleration);
    try testing.expectEqual(SockmapAccelerationMode.auto, config.performance.udp_sockmap_acceleration);
    try testing.expectEqual(PerformanceConfiguration.default_udp_socket_buffer_bytes, config.performance.udp_socket_buffer_bytes);
    try testing.expectEqual(PerformanceConfiguration.default_udp_datagram_buffer_bytes, config.performance.udp_datagram_buffer_bytes);
    try testing.expectEqual(0, config.performance.udp_io_threads);
}

test "loads overrides" {
    var cycle = try loadForTest(
        \\version: 1
        \\protocols: [udp]
        \\listen: { host: "::1", port: 5353 }
        \\upstream: { host: "2001:4860:4860::8888", port: 53 }
        \\timeouts:
        \\  connectSeconds: 2
        \\  tcpIdleSeconds: 20
        \\  udpSessionSeconds: 15
        \\  shutdownGraceSeconds: 3
        \\limits:
        \\  tcpListenBacklog: 2048
        \\  maxTCPBufferedBytes: 67108864
        \\  maxUDPAssociations: 128
        \\  maxUDPPendingDatagrams: 8
        \\  maxUDPPendingBytes: 4096
        \\runtime: { workerThreads: 2, tuningDaemon: false, tuningIntervalSeconds: 10 }
        \\performance: { tcpSockmapAcceleration: enabled, udpSockmapAcceleration: disabled, udpSocketBufferBytes: 8388608, udpDatagramBufferBytes: 8192, udpIOThreads: 2 }
        \\logging: { level: debug }
        \\
    );
    defer cycle.deinit();
    const config = configuration(&cycle);

    try testing.expectEqualSlices(ForwardProtocol, &.{.udp}, config.protocols);
    try testing.expectEqualStrings("::1", config.listen.host);
    try testing.expectEqual(5_353, config.listen.port);
    try testing.expectEqualStrings("2001:4860:4860::8888", config.upstream.host);
    try testing.expectEqual(53, config.upstream.port);
    try testing.expectEqual(15, config.timeouts.udp_session_seconds);
    try testing.expectEqual(2, config.timeouts.connect_seconds);
    try testing.expectEqual(20, config.timeouts.tcp_idle_seconds);
    try testing.expectEqual(3, config.timeouts.shutdown_grace_seconds);
    try testing.expectEqual(2_048, config.limits.tcp_listen_backlog);
    try testing.expectEqual(64 * 1_024 * 1_024, config.limits.max_tcp_buffered_bytes);
    try testing.expectEqual(128, config.limits.max_udp_associations);
    try testing.expectEqual(8, config.limits.max_udp_pending_datagrams);
    try testing.expectEqual(4_096, config.limits.max_udp_pending_bytes);
    try testing.expectEqualStrings("debug", config.logging.level);
    try testing.expectEqual(2, config.runtime.worker_threads);
    try testing.expect(!config.runtime.tuning_daemon);
    try testing.expectEqual(10, config.runtime.tuning_interval_seconds);
    try testing.expect(!config.limits.auto_tuning.max_tcp_buffered_bytes);
    try testing.expect(config.limits.auto_tuning.tcp_listen_backlog == false);
    try testing.expectEqual(SockmapAccelerationMode.enabled, config.performance.tcp_sockmap_acceleration);
    try testing.expectEqual(SockmapAccelerationMode.disabled, config.performance.udp_sockmap_acceleration);
    try testing.expectEqual(8 * 1_024 * 1_024, config.performance.udp_socket_buffer_bytes);
    try testing.expectEqual(8 * 1_024, config.performance.udp_datagram_buffer_bytes);
    try testing.expectEqual(2, config.performance.udp_io_threads);
}

test "accepts explicit auto values" {
    var cycle = try loadForTest(
        \\listen: { port: 9000 }
        \\upstream: { host: "localhost", port: 9001 }
        \\runtime: { workerThreads: auto }
        \\limits:
        \\  tcpListenBacklog: auto
        \\  maxTCPBufferedBytes: auto
        \\  maxUDPAssociations: auto
        \\  maxUDPPendingDatagrams: auto
        \\  maxUDPPendingBytes: auto
        \\
    );
    defer cycle.deinit();
    const config = configuration(&cycle);
    const auto_limits = autotune.limits(.system());

    try testing.expectEqual(0, config.runtime.worker_threads);
    try testing.expectEqual(auto_limits.tcp_listen_backlog, config.limits.tcp_listen_backlog);
    try testing.expectEqual(auto_limits.max_tcp_buffered_bytes, config.limits.max_tcp_buffered_bytes);
    try testing.expectEqual(auto_limits.max_udp_associations, config.limits.max_udp_associations);
    try testing.expectEqual(auto_limits.max_udp_pending_datagrams, config.limits.max_udp_pending_datagrams);
    try testing.expectEqual(auto_limits.max_udp_pending_bytes, config.limits.max_udp_pending_bytes);
    try testing.expect(config.limits.auto_tuning.tcp_listen_backlog);
    try testing.expect(config.limits.auto_tuning.max_udp_pending_bytes);
}

test "accepts block sequences and comments" {
    var cycle = try loadForTest(
        \\# leading comment
        \\protocols:
        \\  - tcp   # trailing comment
        \\  - udp
        \\listen:
        \\  port: 9000 # inline
        \\upstream:
        \\  host: "example.com"
        \\
    );
    defer cycle.deinit();
    const config = configuration(&cycle);
    try testing.expectEqualSlices(ForwardProtocol, &.{ .tcp, .udp }, config.protocols);
    try testing.expectEqual(9_000, config.listen.port);
    try testing.expectEqual(9_000, config.upstream.port);
}

test "rejects unknown keys with dotted paths" {
    try conf.expectLoadFailure(
        \\version: 1
        \\protocols: [tcp]
        \\listen: { host: "127.0.0.1", port: 9000, typo: true }
        \\upstream: { host: "127.0.0.1", port: 9001 }
        \\
    , "unknown configuration key: listen.typo");

    try conf.expectLoadFailure(
        \\version: 1
        \\protocols: [tcp]
        \\listen: { host: "127.0.0.1", port: 9000 }
        \\upstream: { host: "127.0.0.1", port: 9001 }
        \\performance: { sockmap: enabled }
        \\
    , "unknown configuration key: performance.sockmap");
}

test "rejects duplicate protocols" {
    try conf.expectLoadFailure(
        \\version: 1
        \\protocols: [tcp, tcp]
        \\listen: { host: "127.0.0.1", port: 9000 }
        \\upstream: { host: "127.0.0.1", port: 9001 }
        \\
    , "protocols must not contain duplicates");
}

test "rejects invalid ranges and log levels" {
    const prefix =
        \\version: 1
        \\protocols: [tcp]
        \\listen: { host: "127.0.0.1", port: 9000 }
        \\upstream: { host: "127.0.0.1", port: 9001 }
        \\
    ;
    const cases = [_]struct { yaml_text: []const u8, message: []const u8 }{
        .{ .yaml_text = "version: 2\nlisten: { port: 9000 }\nupstream: { host: \"a\", port: 1 }\n", .message = "unsupported configuration version: 2" },
        .{ .yaml_text = "version: 1\nprotocols: []\nlisten: { host: \"127.0.0.1\", port: 9000 }\nupstream: { host: \"127.0.0.1\", port: 9001 }\n", .message = "protocols must not be empty" },
        .{ .yaml_text = prefix ++ "limits: { tcpListenBacklog: 0 }\n", .message = "limits.tcpListenBacklog must be between 1 and 2147483647" },
        .{ .yaml_text = prefix ++ "limits: { maxTCPBufferedBytes: 0 }\n", .message = "limits.maxTCPBufferedBytes must be positive" },
        .{ .yaml_text = prefix ++ "limits: { maxUDPPendingDatagrams: 0 }\n", .message = "limits.maxUDPPendingDatagrams must be positive" },
        .{ .yaml_text = prefix ++ "limits: { maxUDPPendingBytes: 0 }\n", .message = "limits.maxUDPPendingBytes must be positive" },
        .{ .yaml_text = "version: 1\nlisten: { host: \"127.0.0.1\", port: 0 }\nupstream: { host: \"127.0.0.1\", port: 9001 }\n", .message = "listen.port must be between 1 and 65535" },
        .{ .yaml_text = prefix ++ "timeouts: { udpSessionSeconds: 0 }\n", .message = "all timeout values must be positive" },
        .{ .yaml_text = prefix ++ "timeouts: { tcpIdleSeconds: 9223372037 }\n", .message = "all timeout values must be no greater than 9223372036 seconds" },
        .{ .yaml_text = prefix ++ "logging: { level: verbose }\n", .message = "logging.level is invalid" },
        .{ .yaml_text = prefix ++ "runtime: { workerThreads: -1 }\n", .message = "runtime.workerThreads must be zero for auto or positive" },
        .{ .yaml_text = prefix ++ "runtime: { tuningIntervalSeconds: 0 }\n", .message = "runtime.tuningIntervalSeconds must be positive" },
        .{ .yaml_text = prefix ++ "performance: { tcpSockmapAcceleration: sometimes }\n", .message = "performance.tcpSockmapAcceleration: expected one of auto, enabled, disabled" },
        .{ .yaml_text = prefix ++ "limits: { maxUDPAssociations: 2147483648 }\n", .message = "limits.maxUDPAssociations must be between 1 and 2147483647" },
        .{ .yaml_text = prefix ++ "performance: { udpSockmapAcceleration: sometimes }\n", .message = "performance.udpSockmapAcceleration: expected one of auto, enabled, disabled" },
        .{ .yaml_text = prefix ++ "performance: { udpSocketBufferBytes: -1 }\n", .message = "performance.udpSocketBufferBytes must be between 0 (kernel default) and 268435456" },
        .{ .yaml_text = prefix ++ "performance: { udpSocketBufferBytes: 536870912 }\n", .message = "performance.udpSocketBufferBytes must be between 0 (kernel default) and 268435456" },
        .{ .yaml_text = prefix ++ "performance: { udpIOThreads: -1 }\n", .message = "performance.udpIOThreads must be zero for auto or positive" },
        .{ .yaml_text = prefix ++ "runtime: { workerThreads: forever }\n", .message = "runtime.workerThreads: expected an integer or auto" },
    };
    for (cases) |case| {
        try conf.expectLoadFailure(case.yaml_text, case.message);
    }
}

test "rejects missing required keys and non-mapping root" {
    try conf.expectLoadFailure("upstream: { host: \"a\" }\n", "missing required key: listen");
    try conf.expectLoadFailure("listen: { host: \"a\" }\nupstream: { host: \"a\" }\n", "missing required key: listen.port");
    try conf.expectLoadFailure("listen: { port: 9000 }\nupstream: { port: 9001 }\n", "missing required key: upstream.host");
}

fn resolveYamlForTest(text: []const u8, resolver: ?Resolver) !struct { cycle: conf.Cycle, resolved: ResolvedForwarder } {
    var cycle = try loadForTest(text);
    errdefer cycle.deinit();
    var diag = conf.Diagnostics{};
    const resolved = resolveForwarder(testing.allocator, cycle.allocator(), &cycle, resolver, &diag) catch |err| {
        if (diag.message) |message| {
            std.debug.print("unexpected resolve failure: {s}\n", .{message});
            testing.allocator.free(message);
        }
        return err;
    };
    return .{ .cycle = cycle, .resolved = resolved };
}

test "single rule resolves to one synthetic rule" {
    const result = try resolveYamlForTest(
        \\listen: { host: "127.0.0.1", port: 9000 }
        \\upstream: { host: "127.0.0.2", port: 9001 }
        \\
    , null);
    var cycle = result.cycle;
    defer cycle.deinit();

    try testing.expect(!result.resolved.rules_mode);
    try testing.expectEqual(@as(usize, 1), result.resolved.rules.len);
    const rule = result.resolved.rules[0];
    try testing.expectEqual(@as(usize, 1), rule.listen_addresses.len);
    try testing.expectEqual(@as(u16, 9_000), rule.listen_addresses[0].port);
    try testing.expectEqual(@as(usize, 1), rule.upstream_addresses.len);
    try testing.expectEqual(@as(u16, 9_001), rule.upstream_addresses[0].port);
    try testing.expectEqual(rule.upstream_addresses[0].port, rule.effective.upstream.port);
}

test "resolves rules listen and upstream addresses" {
    const result = try resolveYamlForTest(
        \\rules:
        \\  - listen: { host: "127.0.0.1", port: 9000 }
        \\    upstreams:
        \\      - { host: "127.0.0.2", port: 9001 }
        \\      - { host: "::1", port: 9002 }
        \\  - listen: { host: "*", port: 5353 }
        \\    protocols: [udp]
        \\    upstreams: [ { host: "127.0.0.3", port: 53 } ]
        \\
    , null);
    var cycle = result.cycle;
    defer cycle.deinit();

    try testing.expect(result.resolved.rules_mode);
    const first = result.resolved.rules[0];
    try testing.expectEqual(@as(usize, 1), first.listen_addresses.len);
    try testing.expectEqual(@as(u16, 9_000), first.listen_addresses[0].port);
    try testing.expectEqual(@as(usize, 2), first.upstream_addresses.len);
    try testing.expectEqual(SocketAddr.Family.v4, first.upstream_addresses[0].family);
    try testing.expectEqual(@as(u16, 9_001), first.upstream_addresses[0].port);
    try testing.expectEqual(SocketAddr.Family.v6, first.upstream_addresses[1].family);

    const second = result.resolved.rules[1];
    try testing.expectEqual(@as(usize, 2), second.listen_addresses.len);
    try testing.expectEqual(@as(u16, 5_353), second.listen_addresses[1].port);
    try testing.expectEqualSlices(ForwardProtocol, &.{.udp}, second.effectiveProtocols());
}

fn expectResolveFailure(text: []const u8, expected_message: []const u8) !void {
    var cycle = try loadForTest(text);
    defer cycle.deinit();
    var diag = conf.Diagnostics{};
    const result = resolveForwarder(testing.allocator, cycle.allocator(), &cycle, null, &diag);
    if (result) |_| return error.TestExpectedFailureButResolved else |_| {}
    try testing.expectEqualStrings(expected_message, diag.message.?);
    if (diag.message) |message| testing.allocator.free(message);
}

test "rejects rules sharing a listen address and protocol" {
    try expectResolveFailure(
        \\rules:
        \\  - listen: { host: "127.0.0.1", port: 9000 }
        \\    upstreams: [ { host: "127.0.0.2", port: 9001 } ]
        \\  - listen: { host: "127.0.0.1", port: 9000 }
        \\    upstreams: [ { host: "127.0.0.3", port: 9001 } ]
        \\
    , "rules 0 and 1 listen on the same address for protocol tcp");

    try expectResolveFailure(
        \\rules:
        \\  - listen: { host: "*", port: 9000 }
        \\    upstreams: [ { host: "127.0.0.2", port: 9001 } ]
        \\  - listen: { host: "0.0.0.0", port: 9000 }
        \\    protocols: [udp]
        \\    upstreams: [ { host: "127.0.0.3", port: 9001 } ]
        \\
    , "rules 0 and 1 listen on the same address for protocol udp");
}

test "allows rules sharing an address across disjoint protocols" {
    const result = try resolveYamlForTest(
        \\rules:
        \\  - listen: { host: "127.0.0.1", port: 9000 }
        \\    protocols: [tcp]
        \\    upstreams: [ { host: "127.0.0.2", port: 9001 } ]
        \\  - listen: { host: "127.0.0.1", port: 9000 }
        \\    protocols: [udp]
        \\    upstreams: [ { host: "127.0.0.3", port: 9001 } ]
        \\
    , null);
    var cycle = result.cycle;
    defer cycle.deinit();
    try testing.expectEqual(@as(usize, 2), result.resolved.rules.len);
}

fn makeTestConfiguration(upstream_host: []const u8) ForwarderConfiguration {
    return .{
        .version = 1,
        .protocols = @constCast(&[_]ForwardProtocol{.tcp}),
        .listen = .{ .host = "127.0.0.1", .port = 9_000 },
        .upstream = .{ .host = upstream_host, .port = 9_001 },
        .limits = .{
            .tcp_listen_backlog = 4_096,
            .max_tcp_buffered_bytes = 64 * 1_024 * 1_024,
            .max_udp_associations = 1_024,
            .max_udp_pending_datagrams = 64,
            .max_udp_pending_bytes = 256 * 1_024,
        },
    };
}

fn loopbackResolver(host: []const u8, port: u16) anyerror!SocketAddr {
    _ = host;
    return SocketAddr.parseIp("127.0.0.1", port).?;
}

test "sockmap auto skips loopback upstreams for udp but not tcp" {
    var listen_v4 = [_]SocketAddr{SocketAddr.parseIp("127.0.0.1", 9_000).?};
    var listen_v6 = [_]SocketAddr{SocketAddr.parseIp("::1", 9_000).?};

    // IPv4 127.0.0.0/8 loopback upstream: TCP auto stays enabled, UDP auto
    // skips the loopback path.
    const ipv4 = ResolvedConfiguration{
        .configuration = makeTestConfiguration("127.42.0.1"),
        .listen_addresses = &listen_v4,
        .upstream_address = SocketAddr.parseIp("127.42.0.1", 9_001).?,
    };
    try testing.expect(ipv4.shouldEnableTCPSockmap());
    try testing.expect(!ipv4.shouldEnableUDPSockmap());

    // IPv6 ::1 loopback upstream behaves the same.
    const ipv6 = ResolvedConfiguration{
        .configuration = makeTestConfiguration("::1"),
        .listen_addresses = &listen_v6,
        .upstream_address = SocketAddr.parseIp("::1", 9_001).?,
    };
    try testing.expect(ipv6.shouldEnableTCPSockmap());
    try testing.expect(!ipv6.shouldEnableUDPSockmap());

    // Remote upstream: both stay enabled in auto.
    const remote = ResolvedConfiguration{
        .configuration = makeTestConfiguration("192.0.2.1"),
        .listen_addresses = &listen_v4,
        .upstream_address = SocketAddr.parseIp("192.0.2.1", 9_001).?,
    };
    try testing.expect(remote.shouldEnableTCPSockmap());
    try testing.expect(remote.shouldEnableUDPSockmap());

    // Explicit enabled forces a UDP sockmap attempt even for loopback.
    var udp_enabled = makeTestConfiguration("127.0.0.1");
    udp_enabled.performance.udp_sockmap_acceleration = .enabled;
    const udp_enabled_resolved = ResolvedConfiguration{
        .configuration = udp_enabled,
        .listen_addresses = &listen_v4,
        .upstream_address = SocketAddr.parseIp("127.0.0.1", 9_001).?,
    };
    try testing.expect(udp_enabled_resolved.shouldEnableUDPSockmap());

    // Explicit disabled always wins for UDP.
    var udp_disabled = makeTestConfiguration("192.0.2.1");
    udp_disabled.performance.udp_sockmap_acceleration = .disabled;
    const udp_disabled_resolved = ResolvedConfiguration{
        .configuration = udp_disabled,
        .listen_addresses = &listen_v4,
        .upstream_address = SocketAddr.parseIp("192.0.2.1", 9_001).?,
    };
    try testing.expect(!udp_disabled_resolved.shouldEnableUDPSockmap());

    // TCP enabled/disabled keep their prior semantics for loopback upstreams.
    var tcp_enabled = makeTestConfiguration("127.0.0.1");
    tcp_enabled.performance.tcp_sockmap_acceleration = .enabled;
    const tcp_enabled_resolved = ResolvedConfiguration{
        .configuration = tcp_enabled,
        .listen_addresses = &listen_v4,
        .upstream_address = SocketAddr.parseIp("127.0.0.1", 9_001).?,
    };
    try testing.expect(tcp_enabled_resolved.shouldEnableTCPSockmap());

    var tcp_disabled = makeTestConfiguration("192.0.2.1");
    tcp_disabled.performance.tcp_sockmap_acceleration = .disabled;
    const tcp_disabled_resolved = ResolvedConfiguration{
        .configuration = tcp_disabled,
        .listen_addresses = &listen_v4,
        .upstream_address = SocketAddr.parseIp("192.0.2.1", 9_001).?,
    };
    try testing.expect(!tcp_disabled_resolved.shouldEnableTCPSockmap());
}

fn hostBasedResolver(comptime listener_ip: []const u8) Resolver {
    return struct {
        fn resolve(host: []const u8, port: u16) anyerror!SocketAddr {
            const ip = if (std.mem.eql(u8, host, "upstream.internal")) "127.0.0.10" else listener_ip;
            return SocketAddr.parseIp(ip, port).?;
        }
    }.resolve;
}

test "detects listen hostname resolution change" {
    var original_addresses = [_]SocketAddr{SocketAddr.parseIp("127.0.0.1", 9_000).?};
    var changed_addresses = [_]SocketAddr{SocketAddr.parseIp("127.0.0.2", 9_000).?};
    var config = makeTestConfiguration("upstream.internal");
    config.listen.host = "listener.internal";

    const original = ResolvedConfiguration{
        .configuration = config,
        .listen_addresses = &original_addresses,
        .upstream_address = SocketAddr.parseIp("127.0.0.10", 9_001).?,
    };
    const changed = ResolvedConfiguration{
        .configuration = config,
        .listen_addresses = &changed_addresses,
        .upstream_address = SocketAddr.parseIp("127.0.0.10", 9_001).?,
    };

    try testing.expect(original.listenBindingDiffers(&changed));
    try testing.expect(!original.listenBindingDiffers(&original));
    _ = hostBasedResolver("127.0.0.1");
    _ = loopbackResolver;
}

test "config.example.yaml parses with expected values" {
    // Inline copy of ../config.example.yaml (keep in sync).
    var cycle = try loadForTest(
        \\listen:
        \\  port: 9000
        \\
        \\upstream:
        \\  host: "example.com"
        \\
        \\# Optional overrides. Omitted values are auto-tuned continuously at runtime.
        \\# version: 1
        \\# protocols: [tcp, udp]
        \\# listen:
        \\#   host: "*"
        \\#   port: 9000
        \\# upstream:
        \\#   host: "example.com"
        \\#   port: 9000
        \\# runtime:
        \\#   workerThreads: auto
        \\#   tuningDaemon: true
        \\#   tuningIntervalSeconds: 5
        \\# timeouts:
        \\#   connectSeconds: 5
        \\#   tcpIdleSeconds: 300
        \\#   udpSessionSeconds: 60
        \\#   shutdownGraceSeconds: 10
        \\# limits:
        \\#   tcpListenBacklog: auto
        \\#   maxTCPBufferedBytes: auto
        \\#   maxUDPAssociations: auto
        \\#   maxUDPPendingDatagrams: auto   # legacy: unused by the batched UDP transport
        \\#   maxUDPPendingBytes: auto       # legacy: unused by the batched UDP transport
        \\# performance:
        \\#   tcpSockmapAcceleration: auto
        \\#   udpSockmapAcceleration: auto
        \\#   udpSocketBufferBytes: 4194304   # 0 keeps kernel defaults; clamped to
        \\#                                   # net.core.rmem_max/wmem_max without CAP_NET_ADMIN
        \\#   udpIOThreads: auto              # UDP relay threads; auto = worker count
        \\# logging:
        \\#   level: info
        \\# Optional rules module (disabled unless written): multiple independent
        \\# listen -> upstreams rules in one process. Cannot be combined with the
        \\# top-level listen/upstream above.
        \\# rules:
        \\#   - listen: { host: "*", port: 9000 }
        \\#     upstreams:
        \\#       - { host: "a.example.com", port: 9000 }
        \\#       - { host: "b.example.com", port: 9000, weight: 2 }
        \\#     balance: round_robin
        \\
    );
    defer cycle.deinit();
    const config = configuration(&cycle);
    try testing.expectEqual(9_000, config.listen.port);
    try testing.expectEqualStrings("example.com", config.upstream.host);
    try testing.expectEqual(9_000, config.upstream.port);
}
