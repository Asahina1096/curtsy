//! Command line entry point.
//!
//! curtsy --config PATH [--check-config]
//!   -c, --config PATH   Path to the YAML configuration file (required)
//!       --check-config  Validate configuration and exit
//!       --version       Print version and exit
//!   -h, --help          Print usage and exit
//!
//! Configuration or resolution errors print "curtsy: configuration error: ..."
//! to stderr and exit 2; --check-config prints "configuration is valid" and
//! exits 0. A normal run starts the Zig TCP/UDP forwarding runtime.

const std = @import("std");
const config = @import("config.zig");
const log = @import("log.zig");
const service = @import("service.zig");

const version = "0.3.0";

const usage =
    \\Usage: curtsy --config <path> [--check-config]
    \\
    \\Transparent TCP and UDP traffic forwarder
    \\
    \\Options:
    \\  -c, --config <path>  Path to the YAML configuration file
    \\      --check-config   Validate configuration and exit
    \\      --version        Print version and exit
    \\  -h, --help           Show this help and exit
    \\
;

const Options = struct {
    config_path: []const u8,
    check_config: bool = false,
};

pub fn main(init: std.process.Init) u8 {
    const gpa = init.gpa;

    const options = parseArgs(init.minimal.args.vector) orelse return 64; // EX_USAGE

    var diag = config.Diagnostics{};
    defer if (diag.message) |message| gpa.free(message);

    var loaded = config.loadFile(gpa, options.config_path, &diag) catch {
        reportConfigError(&diag);
        return 2;
    };
    var owns_loaded = true;
    defer if (owns_loaded) loaded.deinit();

    // Resolve listen/upstream addresses before reporting success, so an
    // unresolvable host fails --check-config too.
    const resolved = config.resolveConfiguration(gpa, loaded.arena.allocator(), loaded.value, null, &diag) catch {
        reportConfigError(&diag);
        return 2;
    };

    if (options.check_config) {
        writeOut("configuration is valid\n", .{});
        return 0;
    }

    var runtime = service.ForwarderService.init(gpa, options.config_path, loaded, resolved);
    owns_loaded = false;
    runtime.run() catch |err| {
        writeErr("curtsy: runtime error: {s}\n", .{@errorName(err)});
        runtime.deinit();
        return 1;
    };
    runtime.deinit();
    return 0;
}

fn reportConfigError(diag: *const config.Diagnostics) void {
    writeErr("curtsy: configuration error: {s}\n", .{diag.message orelse "unknown error"});
}

/// Parse argv; on failure prints the reason plus usage and returns null.
/// --version and -h/--help print and exit inside here.
fn parseArgs(args: []const [*:0]const u8) ?Options {
    var options: ?Options = null;
    var check_config = false;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = std.mem.span(args[i]);
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            writeOut("{s}", .{usage});
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--version")) {
            writeOut("{s}\n", .{version});
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "--check-config")) {
            check_config = true;
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            i += 1;
            if (i >= args.len) {
                writeErr("curtsy: missing value for '{s}'\n{s}", .{ arg, usage });
                return null;
            }
            options = .{ .config_path = std.mem.span(args[i]), .check_config = check_config };
        } else if (std.mem.startsWith(u8, arg, "--config=")) {
            options = .{ .config_path = arg["--config=".len..], .check_config = check_config };
        } else {
            writeErr("curtsy: unexpected argument '{s}'\n{s}", .{ arg, usage });
            return null;
        }
    }

    if (options) |*value| {
        value.check_config = check_config;
        return value.*;
    }
    writeErr("curtsy: missing expected argument '--config <path>'\n{s}", .{usage});
    return null;
}

fn writeOut(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt, args) catch return;
    log.writeAllFd(std.posix.STDOUT_FILENO, text);
}

fn writeErr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt, args) catch return;
    log.writeAllFd(std.posix.STDERR_FILENO, text);
}

// Pull unit tests from the foundation modules into the test build.
test {
    _ = config;
    _ = log;
    _ = @import("autotune.zig");
    _ = service;
}
