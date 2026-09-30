//! Thread-safe log store.
//!
//! Seven levels (trace..critical), an atomically swappable level threshold,
//! plain message text written to stderr, thread-safe. Message formatting is
//! skipped entirely when a level is disabled.

const std = @import("std");

pub const Level = enum(u8) {
    trace = 0,
    debug = 1,
    info = 2,
    notice = 3,
    warning = 4,
    err = 5,
    critical = 6,

    /// Case-insensitive parse; returns null for unknown names.
    pub fn fromString(name: []const u8) ?Level {
        var buf: [16]u8 = undefined;
        if (name.len > buf.len) return null;
        const lower = std.ascii.lowerString(&buf, name);
        const map = std.StaticStringMap(Level).initComptime(.{
            .{ "trace", .trace },
            .{ "debug", .debug },
            .{ "info", .info },
            .{ "notice", .notice },
            .{ "warning", .warning },
            .{ "error", .err },
            .{ "critical", .critical },
        });
        return map.get(lower);
    }
};

/// Minimal three-state futex mutex. Zig 0.16 removed std.Thread.Mutex and
/// std.Io.Mutex requires an Io runtime, which the logger cannot depend on —
/// it must be callable from any thread with no runtime handle. The critical
/// section is a single write syscall, so contention is rare and brief.
pub const Mutex = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(unlocked),

    const unlocked: u32 = 0;
    const locked: u32 = 1;
    const contended: u32 = 2;

    pub fn lock(self: *Mutex) void {
        if (self.state.cmpxchgStrong(unlocked, locked, .acquire, .monotonic) == null) return;
        while (self.state.swap(contended, .acquire) != unlocked) {
            _ = std.os.linux.futex(
                &self.state.raw,
                .{ .cmd = .WAIT, .private = true },
                contended,
                .{ .timeout = null },
                null,
                0,
            );
        }
    }

    pub fn unlock(self: *Mutex) void {
        if (self.state.swap(unlocked, .release) == contended) {
            _ = std.os.linux.futex(
                &self.state.raw,
                .{ .cmd = .WAKE, .private = true },
                1,
                .{ .timeout = null },
                null,
                0,
            );
        }
    }
};

/// Longest message that can be emitted; longer messages are truncated.
pub const max_message_bytes = 16 * 1_024;

pub const LogStore = struct {
    threshold: std.atomic.Value(u8),
    mutex: Mutex = .{},
    /// Optional instance identifier; when set, every emitted line is prefixed
    /// with `instance=<name> ` so multi-instance output is distinguishable.
    /// The slice is borrowed and must outlive the store.
    instance_name: ?[]const u8 = null,

    /// Unknown level names fall back to .info.
    pub fn init(level_name: []const u8) LogStore {
        const level = Level.fromString(level_name) orelse .info;
        return .{ .threshold = std.atomic.Value(u8).init(@intFromEnum(level)) };
    }

    pub fn update(self: *LogStore, level_name: []const u8) void {
        const level = Level.fromString(level_name) orelse .info;
        self.threshold.store(@intFromEnum(level), .release);
    }

    /// Set (or clear with null) the instance prefix applied to every line.
    pub fn setInstance(self: *LogStore, name: ?[]const u8) void {
        self.instance_name = name;
    }

    pub fn isEnabled(self: *const LogStore, level: Level) bool {
        return @intFromEnum(level) >= self.threshold.load(.acquire);
    }

    /// Formatted log. The message is only formatted when the level passes the
    /// current threshold.
    pub fn log(self: *LogStore, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (!self.isEnabled(level)) return;
        var buf: [max_message_bytes]u8 = undefined;
        const message = std.fmt.bufPrint(&buf, fmt, args) catch buf[0..];
        self.emit(message, &buf);
    }

    /// Lazy log for expensive messages: `render` is invoked only when the
    /// level is enabled. It receives a buffer and returns the message text.
    pub fn logLazy(
        self: *LogStore,
        level: Level,
        context: anytype,
        comptime render: fn (@TypeOf(context), []u8) []const u8,
    ) void {
        if (!self.isEnabled(level)) return;
        var buf: [max_message_bytes]u8 = undefined;
        self.emit(render(context, &buf), &buf);
    }

    pub fn trace(self: *LogStore, comptime fmt: []const u8, args: anytype) void {
        self.log(.trace, fmt, args);
    }

    pub fn debug(self: *LogStore, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, fmt, args);
    }

    pub fn info(self: *LogStore, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, fmt, args);
    }

    pub fn notice(self: *LogStore, comptime fmt: []const u8, args: anytype) void {
        self.log(.notice, fmt, args);
    }

    pub fn warning(self: *LogStore, comptime fmt: []const u8, args: anytype) void {
        self.log(.warning, fmt, args);
    }

    pub fn err(self: *LogStore, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, fmt, args);
    }

    pub fn critical(self: *LogStore, comptime fmt: []const u8, args: anytype) void {
        self.log(.critical, fmt, args);
    }

    /// Single write including the trailing newline, so the critical section
    /// is one syscall. scratch must be the buffer backing message. When an
    /// instance name is set the line is `instance=<name> <message>`, composed
    /// into a dedicated buffer so it still lands in one write syscall.
    fn emit(self: *LogStore, message: []const u8, scratch: *[max_message_bytes]u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.instance_name) |name| {
            // Compose the prefixed line in a dedicated buffer so it still
            // lands in one write syscall. Only reached with an instance name.
            var line: [max_message_bytes]u8 = undefined;
            var rest = message;
            const prefix_len = name.len + "instance=".len + 1;
            if (rest.len + prefix_len + 1 > line.len) {
                rest = rest[0 .. line.len - prefix_len - 1];
            }
            const prefixed = std.fmt.bufPrint(&line, "instance={s} {s}", .{ name, rest }) catch unreachable;

            if (prefixed.len < max_message_bytes) {
                line[prefixed.len] = '\n';
                writeAllFd(std.posix.STDERR_FILENO, line[0 .. prefixed.len + 1]);
            } else {
                writeAllFd(std.posix.STDERR_FILENO, prefixed);
                writeAllFd(std.posix.STDERR_FILENO, "\n");
            }
            return;
        }

        if (message.len < max_message_bytes) {
            scratch[message.len] = '\n';
            writeAllFd(std.posix.STDERR_FILENO, scratch[0 .. message.len + 1]);
        } else {
            writeAllFd(std.posix.STDERR_FILENO, message);
            writeAllFd(std.posix.STDERR_FILENO, "\n");
        }
    }
};

/// Best-effort unbuffered write of the full slice to a file descriptor.
/// Errors are intentionally ignored (logging must never crash the service).
pub fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) void {
    var rest = bytes;
    while (rest.len > 0) {
        const rc = std.os.linux.write(fd, rest.ptr, rest.len);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => rest = rest[rc..],
            .INTR => continue,
            else => return,
        }
    }
}

test "level parsing is case-insensitive and complete" {
    try std.testing.expectEqual(Level.trace, Level.fromString("trace").?);
    try std.testing.expectEqual(Level.debug, Level.fromString("DEBUG").?);
    try std.testing.expectEqual(Level.info, Level.fromString("Info").?);
    try std.testing.expectEqual(Level.notice, Level.fromString("notice").?);
    try std.testing.expectEqual(Level.warning, Level.fromString("WARNING").?);
    try std.testing.expectEqual(Level.err, Level.fromString("error").?);
    try std.testing.expectEqual(Level.critical, Level.fromString("critical").?);
    try std.testing.expect(Level.fromString("verbose") == null);
}

test "unknown level name falls back to info" {
    var store = LogStore.init("nonsense");
    try std.testing.expect(store.isEnabled(.info));
    try std.testing.expect(!store.isEnabled(.debug));
}

test "update switches threshold atomically" {
    var store = LogStore.init("error");
    try std.testing.expect(!store.isEnabled(.warning));
    store.update("warning");
    try std.testing.expect(store.isEnabled(.warning));
    try std.testing.expect(!store.isEnabled(.notice));
}
