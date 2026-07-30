//! Tuning daemon and eBPF observer integration.
//!
//! A daemon thread ticks every `tuning_interval_seconds`. Each tick pulls a
//! snapshot (current resolved configuration, TCP buffered bytes used, UDP
//! association count) through a caller-supplied function pointer, reads
//! process-level tcp/udp sendmsg/recvmsg counters through the eBPF observer
//! (a silent no-op when eBPF is unavailable), watches /proc/net/netstat
//! listen-queue overflow counters, and recomputes only the limits still
//! marked auto in `limits.auto_tuning`. Changed limits are delivered through
//! a caller-supplied apply function pointer. The daemon never imports the
//! TCP or UDP forwarders — the service layer wires the callbacks, exactly
//! like service-layer callbacks.
//!
//! Thresholds and hysteresis:
//!   - backlog doubles (capped at Int32.max) on any ListenOverflows/ListenDrops
//!     delta while auto;
//!   - max_tcp_buffered_bytes climbs by 25% at >= 75% usage up to
//!     highTCPBufferBudget, decays by 10% at <= 10% usage down to the
//!     AutoTune default;
//!   - max_udp_associations climbs by 25% at >= 80% usage up to
//!     highUDPAssociationLimit, decays by 10% at <= 5% usage down to the
//!     AutoTune default.

const std = @import("std");
const linux = std.os.linux;

const autotune = @import("autotune.zig");
const bpf = @import("bpf.zig");
const config = @import("config.zig");
const log = @import("log.zig");

extern "c" fn strerror(errnum: c_int) [*:0]u8;

/// Snapshot consumed by each daemon tick.
pub const TuningSnapshot = struct {
    configuration: config.ResolvedConfiguration,
    tcp_buffered_bytes: i64,
    udp_associations: i64,
};

/// Called on the daemon thread once per tick. Returning null skips the tick.
pub const SnapshotProvider = *const fn (context: ?*anyopaque) ?TuningSnapshot;

/// Called on the daemon thread when a tick produced changed limits.
pub const ApplyLimits = *const fn (context: ?*anyopaque, limits: config.LimitConfiguration) void;

/// Listen-queue counters from /proc/net/netstat (TcpExt).
pub const NetstatCounters = struct {
    listen_overflows: u64 = 0,
    listen_drops: u64 = 0,

    pub const zero: NetstatCounters = .{};

    /// Saturating per-field delta.
    pub fn delta(self: NetstatCounters, previous: NetstatCounters) NetstatCounters {
        return .{
            .listen_overflows = saturatingSub(self.listen_overflows, previous.listen_overflows),
            .listen_drops = saturatingSub(self.listen_drops, previous.listen_drops),
        };
    }

    fn saturatingSub(value: u64, previous: u64) u64 {
        return if (value >= previous) value - previous else 0;
    }

    /// Read the TcpExt ListenOverflows/ListenDrops counters. Returns null
    /// when /proc/net/netstat cannot be read or has no TcpExt value line.
    pub fn read() ?NetstatCounters {
        const fd = std.posix.openat(linux.AT.FDCWD, "/proc/net/netstat", .{}, 0) catch return null;
        defer _ = linux.close(fd);
        var buf: [64 * 1_024]u8 = undefined;
        var total: usize = 0;
        while (total < buf.len) {
            const n = std.posix.read(fd, buf[total..]) catch return null;
            if (n == 0) break;
            total += n;
        }
        return parse(buf[0..total]);
    }

    /// The file holds one "TcpExt:" header line followed by one "TcpExt:"
    /// value line; fields are zipped by position. Unparseable values count
    /// as zero.
    fn parse(text: []const u8) ?NetstatCounters {
        const max_fields = 512;
        var header: [max_fields][]const u8 = undefined;
        var header_len: usize = 0;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, "TcpExt:")) continue;
            var fields: [max_fields][]const u8 = undefined;
            var field_count: usize = 0;
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            while (it.next()) |token| {
                if (field_count >= max_fields) break;
                fields[field_count] = token;
                field_count += 1;
            }
            if (header_len == 0) {
                @memcpy(header[0..field_count], fields[0..field_count]);
                header_len = field_count;
                continue;
            }
            var counters = NetstatCounters{};
            var index: usize = 1;
            while (index < @min(header_len, field_count)) : (index += 1) {
                const value = std.fmt.parseInt(u64, fields[index], 10) catch 0;
                if (std.mem.eql(u8, header[index], "ListenOverflows")) counters.listen_overflows = value;
                if (std.mem.eql(u8, header[index], "ListenDrops")) counters.listen_drops = value;
            }
            return counters;
        }
        return null;
    }
};

const ObserverCounters = bpf.BpfObserver.Counters;

fn totalEvents(counters: ObserverCounters) u64 {
    return counters.tcp_sendmsg + counters.tcp_recvmsg + counters.udp_sendmsg + counters.udp_recvmsg;
}

/// Saturating per-field delta.
fn observerDelta(counters: ObserverCounters, previous: ObserverCounters) ObserverCounters {
    return .{
        .tcp_sendmsg = NetstatCounters.saturatingSub(counters.tcp_sendmsg, previous.tcp_sendmsg),
        .tcp_recvmsg = NetstatCounters.saturatingSub(counters.tcp_recvmsg, previous.tcp_recvmsg),
        .udp_sendmsg = NetstatCounters.saturatingSub(counters.udp_sendmsg, previous.udp_sendmsg),
        .udp_recvmsg = NetstatCounters.saturatingSub(counters.udp_recvmsg, previous.udp_recvmsg),
    };
}

/// Outcome of one tuning decision. `reasons` are fixed strings joined with
/// ',' for the log line.
const Decision = struct {
    limits: config.LimitConfiguration,
    changed: bool = false,
    reason_count: usize = 0,
    reasons: [3][]const u8 = undefined,

    fn addReason(self: *Decision, reason: []const u8) void {
        self.reasons[self.reason_count] = reason;
        self.reason_count += 1;
        self.changed = true;
    }

    fn joinReasons(self: *const Decision, buf: []u8) []const u8 {
        var len: usize = 0;
        for (self.reasons[0..self.reason_count], 0..) |reason, i| {
            if (i > 0 and len < buf.len) {
                buf[len] = ',';
                len += 1;
            }
            const n = @min(reason.len, buf.len - len);
            @memcpy(buf[len..][0..n], reason[0..n]);
            len += n;
        }
        return buf[0..len];
    }
};

fn ratio(used: i64, limit: i64) f64 {
    if (limit <= 0) return 1;
    return @as(f64, @floatFromInt(@max(0, used))) / @as(f64, @floatFromInt(limit));
}

/// Pure tuning decision, factored out of the tick for testability. Only
/// fields still marked auto are touched. `target`/`high_*` come from the autotune formulas so
/// tests can inject synthetic hardware values.
fn decide(
    current: config.LimitConfiguration,
    tcp_buffered_bytes: i64,
    udp_associations: i64,
    netstat_delta: NetstatCounters,
    target: autotune.AutoTunedLimits,
    high_tcp_budget: i64,
    high_udp_limit: i64,
) Decision {
    var decision = Decision{ .limits = current };
    const auto = current.auto_tuning;

    if (auto.tcp_listen_backlog and
        (netstat_delta.listen_overflows > 0 or netstat_delta.listen_drops > 0))
    {
        const backlog = current.tcp_listen_backlog;
        const next = @min(std.math.maxInt(i32), @max(backlog + 1, backlog * 2));
        if (next != backlog) {
            decision.limits.tcp_listen_backlog = next;
            decision.addReason("listen_queue_pressure");
        }
    }

    if (auto.max_tcp_buffered_bytes) {
        const budget = current.max_tcp_buffered_bytes;
        const usage = ratio(tcp_buffered_bytes, budget);
        if (usage >= 0.75 and budget < high_tcp_budget) {
            decision.limits.max_tcp_buffered_bytes =
                @min(high_tcp_budget, @max(budget + 1, budget + @divTrunc(budget, 4)));
            decision.addReason("tcp_buffer_pressure");
        } else if (usage <= 0.10 and budget > target.max_tcp_buffered_bytes) {
            decision.limits.max_tcp_buffered_bytes =
                @max(target.max_tcp_buffered_bytes, budget - @divTrunc(budget, 10));
            decision.addReason("tcp_buffer_idle");
        }
    }

    if (auto.max_udp_associations) {
        const associations = current.max_udp_associations;
        const usage = ratio(udp_associations, associations);
        if (usage >= 0.80 and associations < high_udp_limit) {
            decision.limits.max_udp_associations =
                @min(high_udp_limit, @max(associations + 1, associations + @divTrunc(associations, 4)));
            decision.addReason("udp_association_pressure");
        } else if (usage <= 0.05 and associations > target.max_udp_associations) {
            decision.limits.max_udp_associations =
                @max(target.max_udp_associations, associations - @divTrunc(associations, 10));
            decision.addReason("udp_association_idle");
        }
    }

    return decision;
}

/// Daemon thread recomputing auto-tuned limits. `start()` loads the eBPF observer (falling back to internal
/// counters with a warning when unavailable) and spawns the thread;
/// `stop()` wakes and joins the thread promptly and releases the observer.
pub const TuningDaemon = struct {
    interval_seconds: i64,
    logger: *log.LogStore,
    snapshot_context: ?*anyopaque,
    snapshot_provider: SnapshotProvider,
    apply_context: ?*anyopaque,
    apply_limits: ApplyLimits,

    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Futex word; bumped by stop() to interrupt the timed wait.
    wake_word: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    observer: ?bpf.BpfObserver = null,
    last_bpf_counters: ?ObserverCounters = null,
    last_netstat_counters: ?NetstatCounters = null,

    pub fn init(
        interval_seconds: i64,
        logger: *log.LogStore,
        snapshot_context: ?*anyopaque,
        snapshot_provider: SnapshotProvider,
        apply_context: ?*anyopaque,
        apply_limits: ApplyLimits,
    ) TuningDaemon {
        std.debug.assert(interval_seconds > 0);
        return .{
            .interval_seconds = interval_seconds,
            .logger = logger,
            .snapshot_context = snapshot_context,
            .snapshot_provider = snapshot_provider,
            .apply_context = apply_context,
            .apply_limits = apply_limits,
        };
    }

    /// Load the observer, seed the delta baselines and spawn the daemon
    /// thread. A spawn failure is logged and leaves the daemon inert, like
    /// the eBPF fallback: tuning is optional and must never abort startup.
    pub fn start(self: *TuningDaemon) void {
        std.debug.assert(self.thread == null);

        var verifier_log: [256 * 1_024]u8 = [_]u8{0} ** (256 * 1_024);
        const pid: u32 = @intCast(linux.getpid());
        if (bpf.BpfObserver.create(pid, &verifier_log)) |observer| {
            self.observer = observer;
            self.logger.info("tuning daemon ebpf observer enabled", .{});
        } else |_| {
            self.observer = null;
            const reason = std.mem.span(strerror(@intFromEnum(bpf.lastErrno)));
            const verifier = std.mem.sliceTo(&verifier_log, 0);
            if (verifier.len > 0) {
                self.logger.warning(
                    "tuning daemon ebpf observer unavailable; using internal counters error={s}; verifier={s}",
                    .{ reason, verifier },
                );
            } else {
                self.logger.warning(
                    "tuning daemon ebpf observer unavailable; using internal counters error={s}",
                    .{reason},
                );
            }
        }

        self.last_bpf_counters = if (self.observer) |*observer| observer.read() catch null else null;
        self.last_netstat_counters = NetstatCounters.read();

        self.stopping.store(false, .release);
        self.thread = std.Thread.spawn(.{ .stack_size = 1 << 20 }, threadMain, .{self}) catch |err| {
            self.logger.err("tuning daemon failed to start error={s}", .{@errorName(err)});
            return;
        };
    }

    /// Signal the thread, join it (promptly — the futex wait is interrupted)
    /// and release the observer. Safe to call after a failed start().
    pub fn stop(self: *TuningDaemon) void {
        if (self.thread) |thread| {
            self.stopping.store(true, .release);
            _ = self.wake_word.fetchAdd(1, .release);
            _ = linux.futex(&self.wake_word.raw, .{ .cmd = .WAKE, .private = true }, 1, .{ .timeout = null }, null, 0);
            thread.join();
            self.thread = null;
        }
        if (self.observer) |*observer| observer.destroy();
        self.observer = null;
    }

    fn threadMain(self: *TuningDaemon) void {
        while (true) {
            const word = self.wake_word.load(.acquire);
            const timeout: linux.timespec = .{ .sec = @intCast(self.interval_seconds), .nsec = 0 };
            const rc = linux.futex(
                &self.wake_word.raw,
                .{ .cmd = .WAIT, .private = true },
                word,
                .{ .timeout = &timeout },
                null,
                0,
            );
            if (self.stopping.load(.acquire)) return;
            // Spurious wakeups and EINTR restart the wait; only a genuine
            // timeout (or a stop race handled above) drives a tick.
            if (linux.errno(rc) == .TIMEDOUT) self.tick();
        }
    }

    fn tick(self: *TuningDaemon) void {
        const snapshot = self.snapshot_provider(self.snapshot_context) orelse return;
        const current = snapshot.configuration.configuration.limits;
        const hardware = autotune.AutoTuneSnapshot.system();
        const target = autotune.limits(hardware);

        const bpf_delta = self.readBpfDeltas();
        const netstat_delta = self.readNetstatDelta();

        var decision = decide(
            current,
            snapshot.tcp_buffered_bytes,
            snapshot.udp_associations,
            netstat_delta,
            target,
            autotune.highTCPBufferBudget(hardware),
            autotune.highUDPAssociationLimit(hardware),
        );
        if (!decision.changed) return;

        self.apply_limits(self.apply_context, decision.limits);

        var reasons_buf: [128]u8 = undefined;
        self.logger.info(
            "tuning daemon adjusted reason={s} " ++
                "tcp_buffered={d} max_tcp_buffered_bytes={d} " ++
                "udp_associations={d} max_udp_associations={d} " ++
                "tcp_listen_backlog={d} ebpf_events={d} " ++
                "listen_overflows={d} listen_drops={d}",
            .{
                decision.joinReasons(&reasons_buf),
                snapshot.tcp_buffered_bytes,
                decision.limits.max_tcp_buffered_bytes,
                snapshot.udp_associations,
                decision.limits.max_udp_associations,
                decision.limits.tcp_listen_backlog,
                totalEvents(bpf_delta),
                netstat_delta.listen_overflows,
                netstat_delta.listen_drops,
            },
        );
    }

    fn readBpfDeltas(self: *TuningDaemon) ObserverCounters {
        if (self.observer) |*observer| {
            const counters = observer.read() catch return .{};
            defer self.last_bpf_counters = counters;
            if (self.last_bpf_counters) |previous| return observerDelta(counters, previous);
            return .{};
        }
        return .{};
    }

    fn readNetstatDelta(self: *TuningDaemon) NetstatCounters {
        const counters = NetstatCounters.read() orelse return .zero;
        defer self.last_netstat_counters = counters;
        if (self.last_netstat_counters) |previous| return counters.delta(previous);
        return .zero;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_target = autotune.AutoTunedLimits{
    .tcp_listen_backlog = 4_096,
    .max_tcp_buffered_bytes = 512,
    .max_udp_associations = 100,
    .max_udp_pending_datagrams = 64,
    .max_udp_pending_bytes = 1_024,
};

fn testLimits() config.LimitConfiguration {
    return .{
        .tcp_listen_backlog = 128,
        .max_tcp_buffered_bytes = 1_000,
        .max_udp_associations = 1_000,
        .max_udp_pending_datagrams = 64,
        .max_udp_pending_bytes = 1_024,
    };
}

test "netstat counters parse TcpExt lines and delta saturates" {
    const text =
        "TcpExt: Foo ListenOverflows Bar ListenDrops\n" ++
        "TcpExt: 1 41 2 7\n" ++
        "IpExt: InOctets\n" ++
        "IpExt: 99\n";
    const counters = NetstatCounters.parse(text).?;
    try testing.expectEqual(41, counters.listen_overflows);
    try testing.expectEqual(7, counters.listen_drops);

    const grown = NetstatCounters{ .listen_overflows = 50, .listen_drops = 7 };
    const delta = grown.delta(counters);
    try testing.expectEqual(9, delta.listen_overflows);
    try testing.expectEqual(0, delta.listen_drops);

    const shrunk = NetstatCounters{ .listen_overflows = 1, .listen_drops = 0 };
    const reset = shrunk.delta(counters);
    try testing.expectEqual(0, reset.listen_overflows);
    try testing.expectEqual(0, reset.listen_drops);

    try testing.expect(NetstatCounters.parse("IpExt: X\nIpExt: 1\n") == null);
}

test "backlog doubles only under queue pressure while auto" {
    var limits = testLimits();
    limits.auto_tuning = .{
        .tcp_listen_backlog = true,
        .max_tcp_buffered_bytes = false,
        .max_udp_associations = false,
        .max_udp_pending_datagrams = false,
        .max_udp_pending_bytes = false,
    };

    var decision = decide(limits, 0, 0, .zero, test_target, 4_096, 10_000);
    try testing.expect(!decision.changed);

    decision = decide(limits, 0, 0, .{ .listen_overflows = 1 }, test_target, 4_096, 10_000);
    try testing.expect(decision.changed);
    try testing.expectEqual(256, decision.limits.tcp_listen_backlog);

    decision = decide(limits, 0, 0, .{ .listen_drops = 3 }, test_target, 4_096, 10_000);
    try testing.expectEqual(256, decision.limits.tcp_listen_backlog);

    var fixed = limits;
    fixed.auto_tuning.tcp_listen_backlog = false;
    decision = decide(fixed, 0, 0, .{ .listen_overflows = 9 }, test_target, 4_096, 10_000);
    try testing.expect(!decision.changed);

    var maxed = limits;
    maxed.tcp_listen_backlog = std.math.maxInt(i32);
    decision = decide(maxed, 0, 0, .{ .listen_overflows = 1 }, test_target, 4_096, 10_000);
    try testing.expect(!decision.changed);
}

test "tcp buffer budget climbs at 75% and decays at 10% within caps" {
    var limits = testLimits();
    limits.auto_tuning = .{
        .tcp_listen_backlog = false,
        .max_tcp_buffered_bytes = true,
        .max_udp_associations = false,
        .max_udp_pending_datagrams = false,
        .max_udp_pending_bytes = false,
    };

    // 80% usage: climb by 25%.
    var decision = decide(limits, 800, 0, .zero, test_target, 4_096, 10_000);
    try testing.expect(decision.changed);
    try testing.expectEqual(1_250, decision.limits.max_tcp_buffered_bytes);

    // Climb is capped by the high-water budget.
    limits.max_tcp_buffered_bytes = 3_900;
    decision = decide(limits, 3_000, 0, .zero, test_target, 4_096, 10_000);
    try testing.expectEqual(4_096, decision.limits.max_tcp_buffered_bytes);

    // Already at the cap under pressure: no change.
    limits.max_tcp_buffered_bytes = 4_096;
    decision = decide(limits, 4_000, 0, .zero, test_target, 4_096, 10_000);
    try testing.expect(!decision.changed);

    // 5% usage: decay by 10%.
    limits.max_tcp_buffered_bytes = 1_000;
    decision = decide(limits, 50, 0, .zero, test_target, 4_096, 10_000);
    try testing.expectEqual(900, decision.limits.max_tcp_buffered_bytes);

    // Decay is floored at the AutoTune default.
    limits.max_tcp_buffered_bytes = 540;
    decision = decide(limits, 10, 0, .zero, test_target, 4_096, 10_000);
    try testing.expectEqual(512, decision.limits.max_tcp_buffered_bytes);

    // Mid-range usage: hysteresis holds, no change.
    limits.max_tcp_buffered_bytes = 1_000;
    decision = decide(limits, 500, 0, .zero, test_target, 4_096, 10_000);
    try testing.expect(!decision.changed);

    // Not auto: untouched under pressure.
    limits.auto_tuning.max_tcp_buffered_bytes = false;
    decision = decide(limits, 999, 0, .zero, test_target, 4_096, 10_000);
    try testing.expect(!decision.changed);
}

test "udp association limit climbs at 80% and decays at 5% within caps" {
    var limits = testLimits();
    limits.auto_tuning = .{
        .tcp_listen_backlog = false,
        .max_tcp_buffered_bytes = false,
        .max_udp_associations = true,
        .max_udp_pending_datagrams = false,
        .max_udp_pending_bytes = false,
    };

    var decision = decide(limits, 0, 900, .zero, test_target, 4_096, 10_000);
    try testing.expectEqual(1_250, decision.limits.max_udp_associations);

    limits.max_udp_associations = 9_900;
    decision = decide(limits, 0, 9_000, .zero, test_target, 4_096, 10_000);
    try testing.expectEqual(10_000, decision.limits.max_udp_associations);

    limits.max_udp_associations = 10_000;
    decision = decide(limits, 0, 9_999, .zero, test_target, 4_096, 10_000);
    try testing.expect(!decision.changed);

    limits.max_udp_associations = 1_000;
    decision = decide(limits, 0, 20, .zero, test_target, 4_096, 10_000);
    try testing.expectEqual(900, decision.limits.max_udp_associations);

    limits.max_udp_associations = 110;
    decision = decide(limits, 0, 1, .zero, test_target, 4_096, 10_000);
    try testing.expectEqual(100, decision.limits.max_udp_associations);

    limits.max_udp_associations = 1_000;
    decision = decide(limits, 0, 500, .zero, test_target, 4_096, 10_000);
    try testing.expect(!decision.changed);

    limits.auto_tuning.max_udp_associations = false;
    decision = decide(limits, 0, 999, .zero, test_target, 4_096, 10_000);
    try testing.expect(!decision.changed);
}

test "ratio treats non-positive limits as full pressure" {
    try testing.expectEqual(1.0, ratio(0, 0));
    try testing.expectEqual(1.0, ratio(10, -5));
    try testing.expectEqual(0.5, ratio(5, 10));
    try testing.expectEqual(0.0, ratio(-3, 10));
}

// -- Integration tests: real daemon thread, fake snapshot/apply callbacks --

const Harness = struct {
    snapshot: ?TuningSnapshot,
    apply_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    last_applied: config.LimitConfiguration = undefined,

    fn provider(context: ?*anyopaque) ?TuningSnapshot {
        const self: *Harness = @ptrCast(@alignCast(context.?));
        return self.snapshot;
    }

    fn apply(context: ?*anyopaque, limits: config.LimitConfiguration) void {
        const self: *Harness = @ptrCast(@alignCast(context.?));
        self.last_applied = limits;
        _ = self.apply_count.fetchAdd(1, .release);
    }
};

var harness_listen_addresses = [_]config.SocketAddr{config.SocketAddr.initV4(.{ 127, 0, 0, 1 }, 8_080)};
var harness_protocols = [_]config.ForwardProtocol{ .tcp, .udp };

fn harnessSnapshot(limits: config.LimitConfiguration, tcp_buffered: i64, udp_associations: i64) TuningSnapshot {
    return .{
        .configuration = .{
            .configuration = .{
                .version = 1,
                .protocols = &harness_protocols,
                .listen = .{ .host = "127.0.0.1", .port = 8_080 },
                .upstream = .{ .host = "127.0.0.1", .port = 9_090 },
                .limits = limits,
            },
            .listen_addresses = &harness_listen_addresses,
            .upstream_address = config.SocketAddr.initV4(.{ 127, 0, 0, 1 }, 9_090),
        },
        .tcp_buffered_bytes = tcp_buffered,
        .udp_associations = udp_associations,
    };
}

fn sleepMs(ms: u64) void {
    const request: linux.timespec = .{
        .sec = @intCast(ms / 1_000),
        .nsec = @intCast((ms % 1_000) * 1_000_000),
    };
    _ = linux.nanosleep(&request, null);
}

fn monotonicMs() u64 {
    var now: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &now);
    return @intCast(@as(i128, now.sec) * 1_000 + @divTrunc(now.nsec, 1_000_000));
}

fn waitForApply(harness: *Harness, timeout_ms: u64) bool {
    const deadline = monotonicMs() + timeout_ms;
    while (monotonicMs() < deadline) {
        if (harness.apply_count.load(.acquire) > 0) return true;
        sleepMs(10);
    }
    return harness.apply_count.load(.acquire) > 0;
}

test "tick drives apply for auto fields and stop joins promptly" {
    var logger = log.LogStore.init("critical");

    var limits = testLimits();
    // Neutralize machine-dependent fields: udp limit equal to the AutoTune
    // target cannot decay, and the test machine's netstat delta over a
    // one-second window is zero, so only the tcp buffer field can move.
    limits.max_udp_associations = autotune.limits(.system()).max_udp_associations;

    var harness = Harness{ .snapshot = harnessSnapshot(limits, 900, 0) };
    var daemon = TuningDaemon.init(1, &logger, &harness, Harness.provider, &harness, Harness.apply);
    daemon.start();

    try testing.expect(waitForApply(&harness, 5_000));
    const applied = harness.apply_count.load(.acquire);
    try testing.expect(harness.last_applied.max_tcp_buffered_bytes > limits.max_tcp_buffered_bytes);
    try testing.expectEqual(limits.max_udp_associations, harness.last_applied.max_udp_associations);
    try testing.expectEqual(limits.max_udp_pending_datagrams, harness.last_applied.max_udp_pending_datagrams);
    try testing.expectEqual(limits.max_udp_pending_bytes, harness.last_applied.max_udp_pending_bytes);

    const stop_start = monotonicMs();
    daemon.stop();
    const stop_elapsed = monotonicMs() - stop_start;
    try testing.expect(stop_elapsed < 1_000);
    try testing.expect(harness.apply_count.load(.acquire) >= applied);
}

test "nothing applied when no field is auto or snapshot is null" {
    var logger = log.LogStore.init("critical");

    var fixed = testLimits();
    fixed.auto_tuning = .{
        .tcp_listen_backlog = false,
        .max_tcp_buffered_bytes = false,
        .max_udp_associations = false,
        .max_udp_pending_datagrams = false,
        .max_udp_pending_bytes = false,
    };
    var harness = Harness{ .snapshot = harnessSnapshot(fixed, 999, 999) };
    var daemon = TuningDaemon.init(1, &logger, &harness, Harness.provider, &harness, Harness.apply);
    daemon.start();
    sleepMs(1_500);
    daemon.stop();
    try testing.expectEqual(0, harness.apply_count.load(.acquire));

    var null_harness = Harness{ .snapshot = null };
    var null_daemon = TuningDaemon.init(1, &logger, &null_harness, Harness.provider, &null_harness, Harness.apply);
    null_daemon.start();
    sleepMs(1_500);
    null_daemon.stop();
    try testing.expectEqual(0, null_harness.apply_count.load(.acquire));
}

test "stop interrupts a long interval immediately" {
    var logger = log.LogStore.init("critical");
    var harness = Harness{ .snapshot = harnessSnapshot(testLimits(), 0, 0) };
    var daemon = TuningDaemon.init(3_600, &logger, &harness, Harness.provider, &harness, Harness.apply);
    daemon.start();
    sleepMs(50);
    const stop_start = monotonicMs();
    daemon.stop();
    try testing.expect(monotonicMs() - stop_start < 1_000);
    try testing.expectEqual(0, harness.apply_count.load(.acquire));
}
