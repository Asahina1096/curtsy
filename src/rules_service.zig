//! Rules plugin orchestration (opt-in).
//!
//! Active when the configuration file uses the top-level `rules` list. Each
//! rule is an independent listen -> upstreams forwarding unit driven by the
//! stock TCPListener/UdpListener APIs; multi-upstream selection and passive
//! health tracking live in upstream_pool.zig and reach the data planes
//! through their selector hooks. The legacy single-rule path in service.zig
//! is untouched; switching modes between reloads requires a restart.
//!
//! Hot reload (SIGHUP) diffs rules by their resolved listen address set:
//! matched rules update in place (upstream pool health is inherited by
//! address), brand-new rules bind before unmatched old ones retire, and any
//! failure rolls the reload back to the previous configuration.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const autotune = @import("autotune.zig");
const config = @import("config.zig");
const log = @import("log.zig");
const tcp = @import("tcp.zig");
const tuning = @import("tuning.zig");
const udp = @import("udp.zig");
const upstream_pool = @import("upstream_pool.zig");

const Allocator = std.mem.Allocator;

pub const Error = anyerror;

const reap_interval_ms: i32 = 100;

// ---------------------------------------------------------------------------
// Selector glue: adapt an UpstreamPool to the tcp/udp hook shapes
// ---------------------------------------------------------------------------

fn tcpPick(context: *anyopaque, client: ?config.SocketAddr, now_ns: u64) config.SocketAddr {
    const pool: *upstream_pool.UpstreamPool = @ptrCast(@alignCast(context));
    return pool.pick(client, now_ns);
}

fn tcpReportSuccess(context: *anyopaque, upstream: config.SocketAddr) void {
    const pool: *upstream_pool.UpstreamPool = @ptrCast(@alignCast(context));
    pool.reportSuccess(upstream);
}

fn tcpReportFailure(context: *anyopaque, upstream: config.SocketAddr, now_ns: u64) void {
    const pool: *upstream_pool.UpstreamPool = @ptrCast(@alignCast(context));
    pool.reportFailure(upstream, now_ns);
}

fn udpPick(context: *anyopaque, client: config.SocketAddr, now_ns: u64) config.SocketAddr {
    const pool: *upstream_pool.UpstreamPool = @ptrCast(@alignCast(context));
    return pool.pick(client, now_ns);
}

fn tcpSelector(pool: *upstream_pool.UpstreamPool) tcp.UpstreamSelector {
    return .{
        .context = pool,
        .pick_fn = tcpPick,
        .report_success_fn = tcpReportSuccess,
        .report_failure_fn = tcpReportFailure,
    };
}

fn udpSelector(pool: *upstream_pool.UpstreamPool) udp.UpstreamSelector {
    return .{
        .context = pool,
        .pick_fn = udpPick,
        .report_success_fn = tcpReportSuccess,
        .report_failure_fn = tcpReportFailure,
    };
}

// ---------------------------------------------------------------------------
// RuleRuntime: one rule's pool plus its listener pair
// ---------------------------------------------------------------------------

/// Heap-allocated and never moved: selector contexts captured by the
/// listeners point at the embedded pool.
const RuleRuntime = struct {
    /// Current generation's rule (backs slices live in a retained config arena).
    rule: config.RuleConfiguration,
    /// Per-rule legacy view handed to the listeners; listen_addresses is the
    /// rule identity used for reload diffing and never changes in place.
    resolved: config.ResolvedConfiguration,
    pool: upstream_pool.UpstreamPool,
    balance: config.BalancePolicy,
    tcp_listener: ?*tcp.TCPListener = null,
    udp_listener: ?*udp.UdpListener = null,
    /// Thread counts the listeners were started with (change needs restart).
    started_worker_threads: i64,
    started_udp_io_threads: i64,
};

pub const RulesService = struct {
    allocator: Allocator,
    configuration_path: []const u8,
    loaded: config.LoadedRulesConfiguration,
    resolved: config.ResolvedRulesConfiguration,
    logger: log.LogStore,
    worker_threads: i64,
    /// Legacy-shaped view of the global sections for the tuning daemon
    /// (which only reads configuration.limits).
    tuning_view: config.ResolvedConfiguration,

    mutex: log.Mutex = .{},
    rules: std.ArrayList(*RuleRuntime) = .empty,
    retired_rules: std.ArrayList(*RuleRuntime) = .empty,
    /// TCP listeners parked for draining after their protocol was removed
    /// from a surviving rule (the pool stays with the rule).
    retired_tcp_listeners: std.ArrayList(*tcp.TCPListener) = .empty,
    retained_configurations: std.ArrayList(config.LoadedRulesConfiguration) = .empty,
    tuning_daemon: ?tuning.TuningDaemon = null,
    shutting_down: bool = false,

    pub fn init(
        allocator: Allocator,
        configuration_path: []const u8,
        loaded: config.LoadedRulesConfiguration,
        resolved: config.ResolvedRulesConfiguration,
    ) RulesService {
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

    pub fn deinit(self: *RulesService) void {
        self.stopTuningDaemon();
        for (self.rules.items) |runtime| self.destroyRuleRuntime(runtime);
        self.rules.deinit(self.allocator);
        self.reapRetiredRules(true);
        self.retired_rules.deinit(self.allocator);
        self.retired_tcp_listeners.deinit(self.allocator);
        for (self.retained_configurations.items) |*old| old.deinit();
        self.retained_configurations.deinit(self.allocator);
        self.loaded.deinit();
    }

    pub fn run(self: *RulesService) Error!void {
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
        self.logger.info("forwarder started mode=rules rules={d}", .{self.rules.items.len});

        while (!self.shutting_down) {
            self.pollSignals(signal_fd);
            self.reapRetiredRules(false);
        }

        self.shutdownRules();
    }

    // ------------------------------------------------------------------
    // Startup and shutdown
    // ------------------------------------------------------------------

    fn startInitialRules(self: *RulesService) Error!void {
        errdefer {
            for (self.rules.items) |runtime| self.destroyRuleRuntime(runtime);
            self.rules.clearRetainingCapacity();
        }
        for (self.resolved.rules) |*candidate| {
            const runtime = try self.createRuleRuntime(candidate, self.resolved.configuration);
            try self.rules.append(self.allocator, runtime);
        }
    }

    fn shutdownRules(self: *RulesService) void {
        self.stopTuningDaemon();

        self.mutex.lock();
        const grace_seconds = self.resolved.configuration.timeouts.shutdown_grace_seconds;
        for (self.rules.items) |runtime| {
            if (runtime.tcp_listener) |listener| listener.stopAccepting();
            if (runtime.udp_listener) |listener| {
                listener.deinit();
                self.allocator.destroy(listener);
                runtime.udp_listener = null;
            }
            self.retired_rules.append(self.allocator, runtime) catch {};
        }
        self.rules.clearRetainingCapacity();
        self.mutex.unlock();

        const deadline = monotonicNowNs() + @as(u64, @intCast(grace_seconds)) * std.time.ns_per_s;
        while (monotonicNowNs() < deadline and self.retiredConnectionCount() > 0) {
            sleepNs(50 * std.time.ns_per_ms);
        }

        const remaining = self.retiredConnectionCount();
        if (remaining > 0) {
            self.logger.warning("forcing tcp connections closed count={d}", .{remaining});
            for (self.retired_rules.items) |runtime| {
                if (runtime.tcp_listener) |listener| listener.forceCloseConnections();
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
        self: *RulesService,
        candidate: *const config.ResolvedRule,
        globals: config.RulesConfiguration,
    ) Error!*RuleRuntime {
        const effective = adjustedEffective(candidate, globals);
        const weights = try self.ruleWeights(candidate.rule);
        defer self.allocator.free(weights);

        const runtime = try self.allocator.create(RuleRuntime);
        errdefer self.allocator.destroy(runtime);
        runtime.* = .{
            .rule = candidate.rule,
            .resolved = resolvedForRule(effective, candidate),
            .pool = try upstream_pool.UpstreamPool.init(
                self.allocator,
                candidate.upstream_addresses,
                weights,
                candidate.rule.balance,
            ),
            .balance = candidate.rule.balance,
            .started_worker_threads = effective.runtime.worker_threads,
            .started_udp_io_threads = effective.performance.udp_io_threads,
        };
        errdefer runtime.pool.deinit();

        const protocols = candidate.effectiveProtocols();
        if (hasProtocol(protocols, .tcp)) {
            runtime.tcp_listener = try self.createTcpListener(runtime);
        }
        errdefer if (runtime.tcp_listener) |listener| {
            listener.deinit();
            self.allocator.destroy(listener);
        };
        if (hasProtocol(protocols, .udp)) {
            runtime.udp_listener = try self.createUdpListener(runtime);
        }

        var protocol_buf: [32]u8 = undefined;
        self.logger.info("rule started listen={f} protocols={s} upstreams={d} balance={s}", .{
            candidate.listen_addresses[0],
            protocolsString(protocols, &protocol_buf),
            candidate.upstream_addresses.len,
            @tagName(candidate.rule.balance),
        });
        return runtime;
    }

    fn createTcpListener(self: *RulesService, runtime: *RuleRuntime) Error!*tcp.TCPListener {
        const listener = try self.allocator.create(tcp.TCPListener);
        errdefer self.allocator.destroy(listener);
        listener.* = try tcp.TCPListener.init(runtime.resolved, &self.logger, .{
            .upstream_selector = tcpSelector(&runtime.pool),
        });
        errdefer listener.deinit();
        try listener.start();
        return listener;
    }

    fn createUdpListener(self: *RulesService, runtime: *RuleRuntime) Error!*udp.UdpListener {
        const listener = try self.allocator.create(udp.UdpListener);
        errdefer self.allocator.destroy(listener);
        listener.* = udp.UdpListener.initWithSelector(
            self.allocator,
            runtime.resolved,
            &self.logger,
            null,
            null,
            udpSelector(&runtime.pool),
        );
        errdefer listener.deinit();
        try listener.start();
        return listener;
    }

    /// Update a matched rule in place: pool upstream set, protocol toggles,
    /// effective configuration. Existing TCP connections keep their upstream;
    /// UDP associations are reset when the upstream set changed.
    fn updateRule(
        self: *RulesService,
        runtime: *RuleRuntime,
        candidate: *const config.ResolvedRule,
        globals: config.RulesConfiguration,
    ) Error!void {
        const effective = adjustedEffective(candidate, globals);
        const new_resolved = resolvedForRule(effective, candidate);

        if (effective.runtime.worker_threads != runtime.started_worker_threads) {
            self.logger.warning("runtime worker thread change requires restart current={d} requested={d}", .{
                runtime.started_worker_threads,
                effective.runtime.worker_threads,
            });
        }
        if (effective.performance.udp_io_threads != runtime.started_udp_io_threads) {
            self.logger.warning("udp io thread change requires restart current={d} requested={d}", .{
                runtime.started_udp_io_threads,
                effective.performance.udp_io_threads,
            });
        }

        // Refresh the upstream pool. A balance policy change recreates the
        // pool in place (health state resets); an upstream set change rebinds
        // and inherits health by address. Selector contexts stay valid either
        // way because the pool storage never moves.
        const old_addresses = try runtime.pool.currentAddresses(self.allocator);
        defer self.allocator.free(old_addresses);
        const upstream_changed = !addressesEqual(old_addresses, candidate.upstream_addresses);

        if (candidate.rule.balance != runtime.balance) {
            const weights = try self.ruleWeights(candidate.rule);
            defer self.allocator.free(weights);
            runtime.pool.deinit();
            runtime.pool = try upstream_pool.UpstreamPool.init(
                self.allocator,
                candidate.upstream_addresses,
                weights,
                candidate.rule.balance,
            );
        } else if (upstream_changed) {
            const weights = try self.ruleWeights(candidate.rule);
            defer self.allocator.free(weights);
            try runtime.pool.rebind(candidate.upstream_addresses, weights);
        }

        const protocols = candidate.effectiveProtocols();
        const want_tcp = hasProtocol(protocols, .tcp);
        const want_udp = hasProtocol(protocols, .udp);

        var added_tcp: ?*tcp.TCPListener = null;
        var added_udp: ?*udp.UdpListener = null;
        errdefer {
            if (added_tcp) |listener| {
                listener.deinit();
                self.allocator.destroy(listener);
            }
            if (added_udp) |listener| {
                listener.deinit();
                self.allocator.destroy(listener);
            }
        }

        if (want_tcp and runtime.tcp_listener == null) added_tcp = try self.createTcpListener(runtime);
        if (want_udp and runtime.udp_listener == null) added_udp = try self.createUdpListener(runtime);

        const backlog_changed =
            runtime.resolved.configuration.limits.tcp_listen_backlog != new_resolved.configuration.limits.tcp_listen_backlog;
        if (backlog_changed) {
            const listener = runtime.tcp_listener orelse added_tcp;
            if (listener) |l| try l.updateListeningBacklog(@intCast(new_resolved.configuration.limits.tcp_listen_backlog));
        }

        if (runtime.tcp_listener orelse added_tcp) |listener| listener.updateConfiguration(new_resolved);
        if (runtime.udp_listener orelse added_udp) |listener| listener.updateConfiguration(new_resolved, upstream_changed);

        if (added_tcp) |listener| {
            runtime.tcp_listener = listener;
            added_tcp = null;
        }
        if (added_udp) |listener| {
            runtime.udp_listener = listener;
            added_udp = null;
        }

        if (!want_tcp) {
            if (runtime.tcp_listener) |listener| {
                listener.stopAccepting();
                // The pool stays with the surviving rule; only the listener
                // is parked for draining.
                self.retired_tcp_listeners.append(self.allocator, listener) catch {
                    listener.forceCloseConnections();
                    listener.deinit();
                    self.allocator.destroy(listener);
                };
                runtime.tcp_listener = null;
            }
        }
        if (!want_udp) {
            if (runtime.udp_listener) |listener| {
                listener.deinit();
                self.allocator.destroy(listener);
                runtime.udp_listener = null;
            }
        }

        runtime.rule = candidate.rule;
        runtime.resolved = new_resolved;
        runtime.balance = candidate.rule.balance;
    }

    fn destroyRuleRuntime(self: *RulesService, runtime: *RuleRuntime) void {
        if (runtime.tcp_listener) |listener| {
            listener.deinit();
            self.allocator.destroy(listener);
            runtime.tcp_listener = null;
        }
        if (runtime.udp_listener) |listener| {
            listener.deinit();
            self.allocator.destroy(listener);
            runtime.udp_listener = null;
        }
        runtime.pool.deinit();
        self.allocator.destroy(runtime);
    }

    /// Stops accepting and parks the rule until its TCP connections drain;
    /// UDP stops immediately.
    fn retireRule(self: *RulesService, runtime: *RuleRuntime) void {
        if (runtime.tcp_listener) |listener| listener.stopAccepting();
        if (runtime.udp_listener) |listener| {
            listener.deinit();
            self.allocator.destroy(listener);
            runtime.udp_listener = null;
        }
        if (runtime.tcp_listener == null) {
            self.destroyRuleRuntime(runtime);
            return;
        }
        self.retired_rules.append(self.allocator, runtime) catch {
            if (runtime.tcp_listener) |listener| listener.forceCloseConnections();
            self.destroyRuleRuntime(runtime);
        };
    }

    fn reapRetiredRules(self: *RulesService, force: bool) void {
        var i: usize = 0;
        while (i < self.retired_rules.items.len) {
            const runtime = self.retired_rules.items[i];
            if (!force and runtime.tcp_listener != null and
                runtime.tcp_listener.?.activeConnectionCount() != 0)
            {
                i += 1;
                continue;
            }
            self.destroyRuleRuntime(runtime);
            _ = self.retired_rules.swapRemove(i);
        }
        var j: usize = 0;
        while (j < self.retired_tcp_listeners.items.len) {
            const listener = self.retired_tcp_listeners.items[j];
            if (!force and listener.activeConnectionCount() != 0) {
                j += 1;
                continue;
            }
            listener.deinit();
            self.allocator.destroy(listener);
            _ = self.retired_tcp_listeners.swapRemove(j);
        }
    }

    fn retiredConnectionCount(self: *RulesService) usize {
        var count: usize = 0;
        for (self.retired_rules.items) |runtime| {
            if (runtime.tcp_listener) |listener| count += listener.activeConnectionCount();
        }
        for (self.retired_tcp_listeners.items) |listener| {
            count += listener.activeConnectionCount();
        }
        return count;
    }

    fn findRule(self: *RulesService, listen_addresses: []const config.SocketAddr) ?usize {
        for (self.rules.items, 0..) |runtime, i| {
            if (addressesEqual(runtime.resolved.listen_addresses, listen_addresses)) return i;
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Signals and reload
    // ------------------------------------------------------------------

    fn pollSignals(self: *RulesService, signal_fd: posix.fd_t) void {
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

    fn handleSignal(self: *RulesService, signal: linux.SIG) void {
        switch (signal) {
            .HUP => self.reload(),
            .INT => self.requestShutdown("SIGINT"),
            .TERM => self.requestShutdown("SIGTERM"),
            .PIPE => {},
            else => {},
        }
    }

    fn reload(self: *RulesService) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return;

        self.logger.info("reloading configuration path={s}", .{self.configuration_path});

        var diag = config.Diagnostics{};
        defer if (diag.message) |message| self.allocator.free(message);

        var any = config.loadAnyFile(self.allocator, self.configuration_path, &diag) catch |err| {
            self.logger.err("configuration reload rejected error={s} reason={s}", .{
                @errorName(err),
                diag.message orelse "unknown error",
            });
            return;
        };
        var loaded = switch (any) {
            .rules => |*rules_loaded| rules_loaded.*,
            .single => |*single_loaded| {
                single_loaded.deinit();
                self.logger.warning("configuration no longer uses rules; restart required to apply single-rule mode", .{});
                return;
            },
        };
        var owns_loaded = true;
        defer if (owns_loaded) loaded.deinit();

        const candidate = config.resolveRulesConfiguration(
            self.allocator,
            loaded.arena.allocator(),
            loaded.value,
            null,
            &diag,
        ) catch |err| {
            self.logger.err("configuration reload rejected error={s} reason={s}", .{
                @errorName(err),
                diag.message orelse "unknown error",
            });
            return;
        };

        self.retained_configurations.ensureUnusedCapacity(self.allocator, 1) catch |err| {
            self.logger.err("configuration reload rejected error={s}", .{@errorName(err)});
            return;
        };

        self.apply(candidate) catch |err| {
            self.logger.err("configuration reload rejected error={s}", .{@errorName(err)});
            return;
        };

        self.retained_configurations.appendAssumeCapacity(self.loaded);
        self.loaded = loaded;
        owns_loaded = false;
        self.resolved = candidate;
        self.logger.update(candidate.configuration.logging.level);
        self.logger.info("configuration reloaded rules={d}", .{candidate.rules.len});
    }

    fn apply(self: *RulesService, candidate: config.ResolvedRulesConfiguration) Error!void {
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
        errdefer for (created.items) |runtime| self.destroyRuleRuntime(runtime);

        var next_rules: std.ArrayList(*RuleRuntime) = .empty;
        errdefer next_rules.deinit(self.allocator);

        const matched = try self.allocator.alloc(bool, self.rules.items.len);
        defer self.allocator.free(matched);
        @memset(matched, false);

        for (candidate.rules) |*candidate_rule| {
            if (self.findRule(candidate_rule.listen_addresses)) |index| {
                matched[index] = true;
                try self.updateRule(self.rules.items[index], candidate_rule, candidate.configuration);
                try next_rules.append(self.allocator, self.rules.items[index]);
            } else {
                const runtime = try self.createRuleRuntime(candidate_rule, candidate.configuration);
                try created.append(self.allocator, runtime);
                try next_rules.append(self.allocator, runtime);
            }
        }

        for (self.rules.items, 0..) |old, i| {
            if (!matched[i]) self.retireRule(old);
        }
        self.rules.deinit(self.allocator);
        self.rules = next_rules;
        self.tuning_view = tuningViewFor(candidate.configuration, candidate.rules);
    }

    fn requestShutdown(self: *RulesService, reason: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return;
        self.shutting_down = true;
        self.logger.info("shutdown requested signal={s}", .{reason});
    }

    // ------------------------------------------------------------------
    // Tuning daemon
    // ------------------------------------------------------------------

    fn startTuningDaemonIfNeeded(self: *RulesService) void {
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

    fn stopTuningDaemon(self: *RulesService) void {
        if (self.tuning_daemon) |*daemon| daemon.stop();
        self.tuning_daemon = null;
    }

    fn snapshot(self: *RulesService) ?tuning.TuningSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return null;
        var tcp_buffered: i64 = 0;
        var udp_associations: u64 = 0;
        for (self.rules.items) |runtime| {
            if (runtime.tcp_listener) |listener| tcp_buffered += listener.bufferedBytesUsed();
            if (runtime.udp_listener) |listener| udp_associations += listener.associationCount();
        }
        return .{
            .configuration = self.tuning_view,
            .tcp_buffered_bytes = tcp_buffered,
            .udp_associations = @intCast(udp_associations),
        };
    }

    /// Push new global auto-tuned limits into every rule, honoring per-rule
    /// explicit overrides.
    fn applyTunedLimits(self: *RulesService, limits: config.LimitConfiguration) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return;

        self.resolved.configuration.limits = limits;
        self.tuning_view.configuration.limits = limits;

        for (self.rules.items) |runtime| {
            const old_effective = runtime.resolved.configuration;
            var new_effective = old_effective;
            new_effective.limits = mergeLimits(limits, runtime.rule.limits);
            if (std.meta.eql(old_effective.limits, new_effective.limits)) continue;

            if (new_effective.limits.tcp_listen_backlog != old_effective.limits.tcp_listen_backlog) {
                if (runtime.tcp_listener) |listener| {
                    listener.updateListeningBacklog(@intCast(new_effective.limits.tcp_listen_backlog)) catch |err| {
                        self.logger.warning("tuning daemon backlog update failed error={s}", .{@errorName(err)});
                        new_effective.limits.tcp_listen_backlog = old_effective.limits.tcp_listen_backlog;
                    };
                }
            }

            const new_resolved = config.ResolvedConfiguration{
                .configuration = new_effective,
                .listen_addresses = runtime.resolved.listen_addresses,
                .upstream_address = runtime.resolved.upstream_address,
            };
            if (runtime.tcp_listener) |listener| listener.updateConfiguration(new_resolved);
            if (runtime.udp_listener) |listener| listener.updateConfiguration(new_resolved, false);
            runtime.resolved = new_resolved;
        }
    }

    fn ruleWeights(self: *RulesService, rule: config.RuleConfiguration) Allocator.Error![]u32 {
        const weights = try self.allocator.alloc(u32, rule.upstreams.len);
        for (rule.upstreams, 0..) |upstream, i| weights[i] = @intCast(upstream.weight);
        return weights;
    }
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Global sections plus rule overrides, with auto thread pools divided
/// across rules when more than one rule exists.
fn adjustedEffective(candidate: *const config.ResolvedRule, globals: config.RulesConfiguration) config.ForwarderConfiguration {
    var effective = candidate.effective;
    const rule_count = globals.rules.len;
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

fn resolvedForRule(effective: config.ForwarderConfiguration, candidate: *const config.ResolvedRule) config.ResolvedConfiguration {
    return .{
        .configuration = effective,
        .listen_addresses = candidate.listen_addresses,
        .upstream_address = candidate.upstream_addresses[0],
    };
}

/// Legacy-shaped snapshot of the global sections for the tuning daemon;
/// only configuration.limits is consumed.
fn tuningViewFor(configuration: config.RulesConfiguration, rules: []const config.ResolvedRule) config.ResolvedConfiguration {
    return .{
        .configuration = .{
            .version = configuration.version,
            .protocols = configuration.protocols,
            .listen = rules[0].rule.listen,
            .upstream = .{ .host = rules[0].rule.upstreams[0].host, .port = rules[0].rule.upstreams[0].port },
            .timeouts = configuration.timeouts,
            .limits = configuration.limits,
            .logging = configuration.logging,
            .runtime = configuration.runtime,
            .performance = configuration.performance,
        },
        .listen_addresses = rules[0].listen_addresses,
        .upstream_address = rules[0].upstream_addresses[0],
    };
}

fn mergeLimits(global: config.LimitConfiguration, overrides: config.RuleLimitOverrides) config.LimitConfiguration {
    var limits = global;
    if (overrides.tcp_listen_backlog) |v| {
        limits.tcp_listen_backlog = v;
        limits.auto_tuning.tcp_listen_backlog = false;
    }
    if (overrides.max_tcp_buffered_bytes) |v| {
        limits.max_tcp_buffered_bytes = v;
        limits.auto_tuning.max_tcp_buffered_bytes = false;
    }
    if (overrides.max_udp_associations) |v| {
        limits.max_udp_associations = v;
        limits.auto_tuning.max_udp_associations = false;
    }
    return limits;
}

fn addressesEqual(a: []const config.SocketAddr, b: []const config.SocketAddr) bool {
    if (a.len != b.len) return false;
    for (a, b) |addr_a, addr_b| {
        if (!addr_a.eql(addr_b)) return false;
    }
    return true;
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
    const service: *RulesService = @ptrCast(@alignCast(context.?));
    return service.snapshot();
}

fn applyTunedLimitsCallback(context: ?*anyopaque, limits: config.LimitConfiguration) void {
    const service: *RulesService = @ptrCast(@alignCast(context.?));
    service.applyTunedLimits(limits);
}

fn hasProtocol(protocols: []const config.ForwardProtocol, protocol: config.ForwardProtocol) bool {
    for (protocols) |candidate| {
        if (candidate == protocol) return true;
    }
    return false;
}

fn protocolsString(protocols: []const config.ForwardProtocol, buf: []u8) []const u8 {
    var fbs = std.Io.Writer.fixed(buf);
    for (protocols, 0..) |protocol, i| {
        if (i > 0) fbs.print(",", .{}) catch return buf[0..fbs.end];
        fbs.print("{s}", .{@tagName(protocol)}) catch return buf[0..fbs.end];
    }
    return buf[0..fbs.end];
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
