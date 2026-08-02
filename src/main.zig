//! Command line entry point.
//!
//! curtsy --config PATH [--check-config]
//!   -c, --config PATH   Path to the YAML configuration file (required)
//!       --check-config  Validate configuration and exit
//!       --version       Print version and exit
//!   -h, --help          Print usage and exit
//!
//! A run is one configuration cycle through the module engine (conf.zig):
//! every module parses its own directives, the core module resolves addresses
//! and the unified orchestrator (core.ForwarderService) drives 1..N rules.
//! Configuration or resolution errors print "curtsy: configuration error: ..."
//! to stderr and exit 2; --check-config prints "configuration is valid" and
//! exits 0.

const std = @import("std");
const conf = @import("conf.zig");
const core = @import("modules/core.zig");
const log = @import("log.zig");

const version = "0.3.1";

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

    var diag = conf.Diagnostics{};
    defer if (diag.message) |message| gpa.free(message);

    var cycle = conf.loadFile(gpa, options.config_path, &diag) catch {
        reportConfigError(&diag);
        return 2;
    };
    var owns_cycle = true;
    defer if (owns_cycle) cycle.deinit();

    // Resolve listen/upstream addresses before reporting success, so an
    // unresolvable host fails --check-config too.
    const resolved = core.resolveForwarder(gpa, cycle.allocator(), &cycle, null, &diag) catch {
        reportConfigError(&diag);
        return 2;
    };

    if (options.check_config) {
        writeOut("configuration is valid\n", .{});
        return 0;
    }

    var service = core.ForwarderService.init(gpa, options.config_path, cycle, resolved);
    owns_cycle = false;
    service.run() catch |err| {
        writeErr("curtsy: runtime error: {s}\n", .{@errorName(err)});
        service.deinit();
        return 1;
    };
    service.deinit();
    return 0;
}

fn reportConfigError(diag: *const conf.Diagnostics) void {
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
