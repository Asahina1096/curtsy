//! Runtime service orchestration.
//!
//! The TCP and UDP data planes live in tcp.zig and udp.zig. This layer owns
//! configuration lifetime, listener startup/reload/shutdown, signal handling
//! and the optional tuning daemon.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const autotune = @import("autotune.zig");
const config = @import("config.zig");
const log = @import("log.zig");
const tcp = @import("tcp.zig");
const tuning = @import("tuning.zig");
const udp = @import("udp.zig");

const Allocator = std.mem.Allocator;

pub const Error = anyerror;

const reap_interval_ms: i32 = 100;

pub const ForwarderService = struct {
    allocator: Allocator,
    configuration_path: []const u8,
    loaded: config.LoadedConfiguration,
    configuration: config.ResolvedConfiguration,
    logger: log.LogStore,
    worker_threads: i64,

    mutex: log.Mutex = .{},
    tcp_listener: ?*tcp.TCPListener = null,
    udp_listener: ?*udp.UdpListener = null,
    retired_tcp_listeners: std.ArrayList(*tcp.TCPListener) = .empty,
    retained_configurations: std.ArrayList(config.LoadedConfiguration) = .empty,
    tuning_daemon: ?tuning.TuningDaemon = null,
    shutting_down: bool = false,

    pub fn init(
        allocator: Allocator,
        configuration_path: []const u8,
        loaded: config.LoadedConfiguration,
        resolved: config.ResolvedConfiguration,
    ) ForwarderService {
        return .{
            .allocator = allocator,
            .configuration_path = configuration_path,
            .loaded = loaded,
            .configuration = resolved,
            .logger = log.LogStore.init(resolved.configuration.logging.level),
            .worker_threads = autotune.workerThreads(resolved.configuration.runtime.worker_threads, .system()),
        };
    }

    pub fn deinit(self: *ForwarderService) void {
        self.stopTuningDaemon();
        if (self.tcp_listener) |listener| {
            listener.deinit();
            self.allocator.destroy(listener);
            self.tcp_listener = null;
        }
        if (self.udp_listener) |listener| {
            listener.deinit();
            self.allocator.destroy(listener);
            self.udp_listener = null;
        }
        self.destroyRetiredTcpListeners(true);
        self.retired_tcp_listeners.deinit(self.allocator);
        for (self.retained_configurations.items) |*old| old.deinit();
        self.retained_configurations.deinit(self.allocator);
        self.loaded.deinit();
    }

    pub fn run(self: *ForwarderService) Error!void {
        var signals = signalMask();
        posix.sigprocmask(posix.SIG.BLOCK, &signals, null);
        const signal_fd = try posix.signalfd(-1, &signals, linux.SFD.CLOEXEC | linux.SFD.NONBLOCK);
        defer _ = linux.close(signal_fd);

        self.logger.info(
            "runtime tuned worker_threads={d} tcp_listen_backlog={d} max_tcp_buffered_bytes={d} max_udp_associations={d}",
            .{
                self.worker_threads,
                self.configuration.configuration.limits.tcp_listen_backlog,
                self.configuration.configuration.limits.max_tcp_buffered_bytes,
                self.configuration.configuration.limits.max_udp_associations,
            },
        );

        try self.startInitialListeners();
        self.startTuningDaemonIfNeeded();

        var protocol_buf: [32]u8 = undefined;
        self.logger.info("forwarder started protocols={s} upstream={f}", .{
            protocolsString(self.configuration.configuration.protocols, &protocol_buf),
            self.configuration.upstream_address,
        });

        while (!self.shutting_down) {
            self.pollSignals(signal_fd);
            self.destroyRetiredTcpListeners(false);
        }

        self.shutdownListeners();
    }

    fn startInitialListeners(self: *ForwarderService) Error!void {
        var started_tcp: ?*tcp.TCPListener = null;
        errdefer {
            if (started_tcp) |listener| {
                listener.deinit();
                self.allocator.destroy(listener);
            }
            if (self.udp_listener) |listener| {
                listener.deinit();
                self.allocator.destroy(listener);
                self.udp_listener = null;
            }
        }

        if (hasProtocol(self.configuration.configuration.protocols, .tcp)) {
            started_tcp = try self.createTcpListener(self.configuration);
        }
        if (hasProtocol(self.configuration.configuration.protocols, .udp)) {
            self.udp_listener = try self.createUdpListener(self.configuration);
        }
        self.tcp_listener = started_tcp;
    }

    fn createTcpListener(self: *ForwarderService, resolved: config.ResolvedConfiguration) Error!*tcp.TCPListener {
        const listener = try self.allocator.create(tcp.TCPListener);
        errdefer self.allocator.destroy(listener);
        listener.* = try tcp.TCPListener.init(resolved, &self.logger, .{});
        errdefer listener.deinit();
        try listener.start();
        return listener;
    }

    fn createUdpListener(self: *ForwarderService, resolved: config.ResolvedConfiguration) Error!*udp.UdpListener {
        const listener = try self.allocator.create(udp.UdpListener);
        errdefer self.allocator.destroy(listener);
        listener.* = udp.UdpListener.init(self.allocator, resolved, &self.logger, null, null);
        errdefer listener.deinit();
        try listener.start();
        return listener;
    }

    fn startTuningDaemonIfNeeded(self: *ForwarderService) void {
        if (!self.configuration.configuration.runtime.tuning_daemon) return;
        self.tuning_daemon = tuning.TuningDaemon.init(
            self.configuration.configuration.runtime.tuning_interval_seconds,
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

        var diag = config.Diagnostics{};
        defer if (diag.message) |message| self.allocator.free(message);

        var loaded = config.loadFile(self.allocator, self.configuration_path, &diag) catch |err| {
            self.logger.err("configuration reload rejected error={s} reason={s}", .{
                @errorName(err),
                diag.message orelse "unknown error",
            });
            return;
        };
        var owns_loaded = true;
        defer if (owns_loaded) loaded.deinit();

        const candidate = config.resolveConfiguration(
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
        self.configuration = candidate;
        self.logger.update(candidate.configuration.logging.level);

        var protocol_buf: [32]u8 = undefined;
        self.logger.info("configuration reloaded protocols={s} upstream={f}", .{
            protocolsString(candidate.configuration.protocols, &protocol_buf),
            candidate.upstream_address,
        });
    }

    fn apply(self: *ForwarderService, candidate: config.ResolvedConfiguration) Error!void {
        const old = self.configuration;
        const endpoint_changed = old.listenBindingDiffers(&candidate);
        const new_tcp = hasProtocol(candidate.configuration.protocols, .tcp);
        const new_udp = hasProtocol(candidate.configuration.protocols, .udp);
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

        if (endpoint_changed) {
            var replacement_tcp: ?*tcp.TCPListener = null;
            var replacement_udp: ?*udp.UdpListener = null;
            errdefer {
                if (replacement_tcp) |listener| {
                    listener.deinit();
                    self.allocator.destroy(listener);
                }
                if (replacement_udp) |listener| {
                    listener.deinit();
                    self.allocator.destroy(listener);
                }
            }

            if (new_tcp) replacement_tcp = try self.createTcpListener(candidate);
            if (new_udp) replacement_udp = try self.createUdpListener(candidate);

            if (self.tcp_listener) |listener| self.retireTcpListener(listener);
            if (self.udp_listener) |listener| {
                listener.deinit();
                self.allocator.destroy(listener);
            }
            self.tcp_listener = replacement_tcp;
            self.udp_listener = replacement_udp;
            return;
        }

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

        if (new_tcp and self.tcp_listener == null) added_tcp = try self.createTcpListener(candidate);
        if (new_udp and self.udp_listener == null) added_udp = try self.createUdpListener(candidate);

        const backlog_changed =
            old.configuration.limits.tcp_listen_backlog != candidate.configuration.limits.tcp_listen_backlog;
        if (new_tcp and backlog_changed and added_tcp == null) {
            if (self.tcp_listener) |listener| try listener.updateListeningBacklog(
                @intCast(candidate.configuration.limits.tcp_listen_backlog),
            );
        }

        if (added_tcp) |listener| self.tcp_listener = listener;
        if (added_udp) |listener| self.udp_listener = listener;
        added_tcp = null;
        added_udp = null;

        const upstream_changed = !old.upstream_address.eql(candidate.upstream_address);
        if (self.tcp_listener) |listener| listener.updateConfiguration(candidate);
        if (self.udp_listener) |listener| listener.updateConfiguration(candidate, upstream_changed);

        if (!new_tcp) {
            if (self.tcp_listener) |listener| {
                self.retireTcpListener(listener);
                self.tcp_listener = null;
            }
        }
        if (!new_udp) {
            if (self.udp_listener) |listener| {
                listener.deinit();
                self.allocator.destroy(listener);
                self.udp_listener = null;
            }
        }
    }

    fn requestShutdown(self: *ForwarderService, reason: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return;
        self.shutting_down = true;
        self.logger.info("shutdown requested signal={s}", .{reason});
    }

    fn shutdownListeners(self: *ForwarderService) void {
        self.stopTuningDaemon();

        self.mutex.lock();
        if (self.tcp_listener) |listener| {
            self.retireTcpListener(listener);
            self.tcp_listener = null;
        }
        if (self.udp_listener) |listener| {
            listener.deinit();
            self.allocator.destroy(listener);
            self.udp_listener = null;
        }
        const grace_seconds = self.configuration.configuration.timeouts.shutdown_grace_seconds;
        self.mutex.unlock();

        const deadline = monotonicNowNs() + @as(u64, @intCast(grace_seconds)) * std.time.ns_per_s;
        while (monotonicNowNs() < deadline and self.retiredConnectionCount() > 0) {
            sleepNs(50 * std.time.ns_per_ms);
        }

        const remaining = self.retiredConnectionCount();
        if (remaining > 0) {
            self.logger.warning("forcing tcp connections closed count={d}", .{remaining});
            for (self.retired_tcp_listeners.items) |listener| listener.forceCloseConnections();
        }
        self.destroyRetiredTcpListeners(true);
        self.logger.info("forwarder stopped", .{});
    }

    fn applyTunedLimits(self: *ForwarderService, limits: config.LimitConfiguration) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return;

        var updated = self.configuration.configuration;
        const previous_backlog = updated.limits.tcp_listen_backlog;
        updated.limits = limits;

        if (limits.tcp_listen_backlog != previous_backlog) {
            if (self.tcp_listener) |listener| {
                listener.updateListeningBacklog(@intCast(limits.tcp_listen_backlog)) catch |err| {
                    self.logger.warning("tuning daemon backlog update failed error={s}", .{@errorName(err)});
                    updated.limits.tcp_listen_backlog = previous_backlog;
                };
            }
        }

        const applied = config.ResolvedConfiguration{
            .configuration = updated,
            .listen_addresses = self.configuration.listen_addresses,
            .upstream_address = self.configuration.upstream_address,
        };
        if (self.tcp_listener) |listener| listener.updateConfiguration(applied);
        if (self.udp_listener) |listener| listener.updateConfiguration(applied, false);
        self.configuration = applied;
    }

    fn snapshot(self: *ForwarderService) ?tuning.TuningSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.shutting_down) return null;
        return .{
            .configuration = self.configuration,
            .tcp_buffered_bytes = if (self.tcp_listener) |listener| listener.bufferedBytesUsed() else 0,
            .udp_associations = if (self.udp_listener) |listener| @intCast(listener.associationCount()) else 0,
        };
    }

    fn retireTcpListener(self: *ForwarderService, listener: *tcp.TCPListener) void {
        listener.stopAccepting();
        self.retired_tcp_listeners.append(self.allocator, listener) catch {
            listener.forceCloseConnections();
            listener.deinit();
            self.allocator.destroy(listener);
        };
    }

    fn destroyRetiredTcpListeners(self: *ForwarderService, force: bool) void {
        var i: usize = 0;
        while (i < self.retired_tcp_listeners.items.len) {
            const listener = self.retired_tcp_listeners.items[i];
            if (!force and listener.activeConnectionCount() != 0) {
                i += 1;
                continue;
            }
            listener.deinit();
            self.allocator.destroy(listener);
            _ = self.retired_tcp_listeners.swapRemove(i);
        }
    }

    fn retiredConnectionCount(self: *ForwarderService) usize {
        var count: usize = 0;
        for (self.retired_tcp_listeners.items) |listener| {
            count += listener.activeConnectionCount();
        }
        return count;
    }
};

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

fn applyTunedLimitsCallback(context: ?*anyopaque, limits: config.LimitConfiguration) void {
    const service: *ForwarderService = @ptrCast(@alignCast(context.?));
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

test {
    _ = tcp;
    _ = udp;
    _ = tuning;
}
