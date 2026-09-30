//! Command line entry point.
//!
//! curtsy --config PATH [--check-config]
//!   -c, --config PATH   Path to the YAML configuration file (required)
//!       --check-config  Validate configuration and exit
//!       --version       Print version and exit
//!   -h, --help          Print usage and exit
//!
//! CLI running mode (optional module, disabled unless used, mutually
//! exclusive with --config):
//!   -l, --listen EP     Listen endpoint for the single-rule shorthand
//!   -u, --upstream EP   Upstream endpoint (port defaults to the listen port)
//!   -r, --rule SPEC     Repeatable multi-rule shorthand
//!       --protocols L   tcp,udp protocol list (single-rule shorthand only)
//!       --balance NAME  Balancer name (single-rule shorthand only)
//!
//! Multi-instance support:
//!   --instance NAME    Optional instance identifier used only for log
//!                      prefixing, process naming (PR_SET_NAME) and the
//!                      systemd template unit name. It never affects
//!                      configuration, routing or any forwarding decision.
//!                      Allowed charset is [A-Za-z0-9._-], at most 64 bytes.
//!
//! A run loads the configuration once (conf.zig): every section is decoded,
//! the core module resolves addresses
//! and the unified orchestrator (core.ForwarderService) drives 1..N rules.
//! Configuration or resolution errors print "curtsy: configuration error: ..."
//! to stderr and exit 2; --check-config prints "configuration is valid" and
//! exits 0. In CLI mode the shorthand is rendered into a `rules:` document and
//! fed through the same engine, so CLI rules share the multi-upstream module's
//! defaults and SIGHUP hot reload.

const std = @import("std");
const cli = @import("modules/cli.zig");
const conf = @import("conf.zig");
const core = @import("modules/core.zig");
const log = @import("log.zig");

const version = "0.3.3";

const usage =
    \\Usage: curtsy --config <path> [--check-config] [--instance <name>]
    \\       curtsy --listen <endpoint> --upstream <endpoint> [--protocols <list>] [--balance <name>] [--check-config] [--instance <name>]
    \\       curtsy --rule <spec> [--rule <spec> ...] [--check-config] [--instance <name>]
    \\
    \\Transparent TCP and UDP traffic forwarder
    \\
    \\Options:
    \\  -c, --config <path>  Path to the YAML configuration file
    \\      --check-config   Validate configuration and exit
    \\      --version        Print version and exit
    \\  -h, --help           Show this help and exit
    \\      --instance <name>  Instance identifier: prefixes every log line
    \\                          with instance=<name>, renames the process
    \\                          (PR_SET_NAME, visible in ps/top) and names the
    \\                          systemd unit (template %i). Never affects
    \\                          forwarding. Charset [A-Za-z0-9._-], <= 64 bytes.
    \\
    \\CLI running mode (optional module; cannot be combined with --config):
    \\  -l, --listen <endpoint>     Listen endpoint for the single-rule shorthand,
    \\                              e.g. ":9000" or "127.0.0.1:9000"
    \\  -u, --upstream <endpoint>   Upstream endpoint; a bare host defaults its
    \\                              port to the listen port
    \\  -r, --rule <spec>           Multi-rule shorthand (repeatable):
    \\                              "listen=:9001,upstreams=a:9001,b:9001/weight=2"
    \\                              optional keys: protocols=tcp,udp, balance=<name>
    \\      --protocols <list>      Comma-separated protocol names (single-rule shorthand)
    \\      --balance <name>        Balancer name: round_robin, source_hash,
    \\                              weighted_round_robin (single-rule shorthand)
    \\
;

const Options = union(enum) {
    file: struct {
        path: []const u8,
        check_config: bool,
        instance: ?[]const u8,
    },
    cli: struct {
        configuration: cli.Configuration,
        check_config: bool,
        instance: ?[]const u8,
    },

    fn checkConfig(self: Options) bool {
        return switch (self) {
            .file => |value| value.check_config,
            .cli => |*value| value.check_config,
        };
    }

    fn instance(self: Options) ?[]const u8 {
        return switch (self) {
            .file => |value| value.instance,
            .cli => |*value| value.instance,
        };
    }
};

pub fn main(init: std.process.Init) u8 {
    const gpa = init.gpa;

    var diag = conf.Diagnostics{};
    defer if (diag.message) |message| gpa.free(message);

    var options = parseArgs(gpa, init.minimal.args.vector, &diag) catch {
        reportConfigError(&diag);
        return 2;
    } orelse return 64; // EX_USAGE
    // The CLI configuration is owned by main for its whole lifetime (the
    // service borrows it for SIGHUP reloads), so it is released on every exit
    // path after the service has deinitialized.
    defer switch (options) {
        .file => {},
        .cli => |*value| value.configuration.deinit(),
    };

    // Capture the file fingerprint before reading so an edit landing during
    // address resolution is detected as a change on the first SIGHUP instead
    // of being fingerprinted-but-never-served.
    const pre_load_fingerprint: ?core.ConfigFingerprint = switch (options) {
        .file => |value| core.ConfigFingerprint.capture(value.path),
        .cli => null,
    };

    var cfg = switch (options) {
        .file => |value| conf.loadFile(gpa, value.path, &diag),
        .cli => |*value| cli.loadCycle(gpa, &value.configuration, &diag),
    } catch {
        reportConfigError(&diag);
        return 2;
    };
    var owns_config = true;
    defer if (owns_config) cfg.deinit();

    // Resolve addresses plus registered balancer/protocol names before
    // reporting success, so --check-config validates the complete runtime.
    const resolved = core.resolveForwarder(gpa, cfg.allocator(), &cfg, &diag) catch {
        reportConfigError(&diag);
        return 2;
    };

    if (options.checkConfig()) {
        writeOut("configuration is valid\n", .{});
        return 0;
    }

    if (options.instance()) |name| setProcessName(name);

    const source: core.ConfigSource = switch (options) {
        .file => |value| .{ .file = value.path },
        .cli => |*value| .{ .cli = &value.configuration },
    };
    var service = core.ForwarderService.init(gpa, source, cfg, resolved, options.instance(), pre_load_fingerprint);
    owns_config = false;
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

/// Parse argv. On command-line misuse (unknown flag, missing value, conflicting
/// modes) prints the reason plus usage and returns null (exit 64); on invalid
/// CLI shorthand records the reason in `diag` and returns
/// error.InvalidConfiguration (exit 2). --version and -h/--help print and exit
/// inside here.
fn parseArgs(
    gpa: std.mem.Allocator,
    args: []const [*:0]const u8,
    diag: *conf.Diagnostics,
) error{ OutOfMemory, InvalidConfiguration }!?Options {
    var config_path: ?[]const u8 = null;
    var check_config = false;
    var instance: ?[]const u8 = null;
    var listen: ?[]const u8 = null;
    var upstream: ?[]const u8 = null;
    var rule_specs: std.ArrayList([]const u8) = .empty;
    defer rule_specs.deinit(gpa);
    var protocols: ?[]const u8 = null;
    var balance: ?[]const u8 = null;

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
            if (i >= args.len) return usageError("missing value for '{s}'", .{arg});
            config_path = std.mem.span(args[i]);
        } else if (std.mem.startsWith(u8, arg, "--config=")) {
            config_path = arg["--config=".len..];
        } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--listen")) {
            i += 1;
            if (i >= args.len) return usageError("missing value for '{s}'", .{arg});
            listen = std.mem.span(args[i]);
        } else if (std.mem.startsWith(u8, arg, "--listen=")) {
            listen = arg["--listen=".len..];
        } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--upstream")) {
            i += 1;
            if (i >= args.len) return usageError("missing value for '{s}'", .{arg});
            upstream = std.mem.span(args[i]);
        } else if (std.mem.startsWith(u8, arg, "--upstream=")) {
            upstream = arg["--upstream=".len..];
        } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--rule")) {
            i += 1;
            if (i >= args.len) return usageError("missing value for '{s}'", .{arg});
            try rule_specs.append(gpa, std.mem.span(args[i]));
        } else if (std.mem.startsWith(u8, arg, "--rule=")) {
            try rule_specs.append(gpa, arg["--rule=".len..]);
        } else if (std.mem.eql(u8, arg, "--protocols")) {
            i += 1;
            if (i >= args.len) return usageError("missing value for '{s}'", .{arg});
            protocols = std.mem.span(args[i]);
        } else if (std.mem.startsWith(u8, arg, "--protocols=")) {
            protocols = arg["--protocols=".len..];
        } else if (std.mem.eql(u8, arg, "--balance")) {
            i += 1;
            if (i >= args.len) return usageError("missing value for '{s}'", .{arg});
            balance = std.mem.span(args[i]);
        } else if (std.mem.startsWith(u8, arg, "--balance=")) {
            balance = arg["--balance=".len..];
        } else if (std.mem.eql(u8, arg, "--instance")) {
            i += 1;
            if (i >= args.len) return usageError("missing value for '{s}'", .{arg});
            instance = std.mem.span(args[i]);
        } else if (std.mem.startsWith(u8, arg, "--instance=")) {
            instance = arg["--instance=".len..];
        } else {
            return usageError("unexpected argument '{s}'", .{arg});
        }
    }

    const has_cli = listen != null or upstream != null or rule_specs.items.len > 0 or
        protocols != null or balance != null;

    if (config_path != null and has_cli) {
        return usageError("cannot combine '--config' with CLI endpoint flags", .{});
    }

    if (instance) |name| {
        if (!validateInstanceName(name)) {
            return usageError("invalid --instance name '{s}': allowed charset is [A-Za-z0-9._-], length 1..64", .{name});
        }
    }

    if (!has_cli) {
        const path = config_path orelse
            return usageError("missing expected argument '--config <path>' or CLI endpoint flags", .{});
        return .{ .file = .{ .path = path, .check_config = check_config, .instance = instance } };
    }

    if (rule_specs.items.len > 0) {
        if (listen != null or upstream != null or protocols != null or balance != null) {
            return usageError("cannot combine '--rule' with '--listen'/'--upstream'/'--protocols'/'--balance'", .{});
        }
        const config = (try cli.parseFlags(gpa, null, null, rule_specs.items, null, null, diag)).?;
        return .{ .cli = .{ .configuration = config, .check_config = check_config, .instance = instance } };
    }

    if (listen == null) return usageError("missing expected argument '--listen <endpoint>'", .{});
    if (upstream == null) return usageError("missing expected argument '--upstream <endpoint>'", .{});
    const config = (try cli.parseFlags(gpa, listen, upstream, &.{}, protocols, balance, diag)).?;
    return .{ .cli = .{ .configuration = config, .check_config = check_config, .instance = instance } };
}

/// Validate an --instance name against the documented charset and length.
/// The rule matches systemd unit instance names (the %i of a template unit),
/// so a name accepted here is safe to use as `curtsy@<name>.service`.
fn validateInstanceName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    for (name) |c| {
        const valid = std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-';
        if (!valid) return false;
    }
    return true;
}

/// Rename the process (PR_SET_NAME, visible in `ps`/`top`) after the instance
/// name so multiple instances are distinguishable in process listings. The
/// kernel caps the comm name at 16 bytes including the NUL, so longer names
/// are truncated; a missing null terminator within the capped window is
/// replaced. Mirrors the thread-naming call in the UDP relay.
fn setProcessName(name: []const u8) void {
    const max_comm: usize = 15;
    var comm: [max_comm + 1]u8 = [_]u8{0} ** (max_comm + 1);
    const len = @min(name.len, max_comm);
    @memcpy(comm[0..len], name[0..len]);
    _ = std.os.linux.prctl(
        @intFromEnum(std.os.linux.PR.SET_NAME),
        @intFromPtr(&comm),
        0,
        0,
        0,
    );
}

/// Print a command-line misuse message plus usage and signal exit 64 (null).
fn usageError(comptime fmt: []const u8, args: anytype) error{OutOfMemory}!?Options {
    var buf: [2048]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, fmt, args) catch return error.OutOfMemory;
    writeErr("curtsy: {s}\n{s}", .{ text, usage });
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

test "instance names follow the documented charset and length" {
    try std.testing.expect(validateInstanceName("edge"));
    try std.testing.expect(validateInstanceName("dmz-2"));
    try std.testing.expect(validateInstanceName("a.b_c-d"));
    try std.testing.expect(validateInstanceName("A0zZ9"));

    try std.testing.expect(!validateInstanceName(""));
    try std.testing.expect(!validateInstanceName("has space"));
    try std.testing.expect(!validateInstanceName("has/slash"));
    try std.testing.expect(!validateInstanceName("has:colon"));
    try std.testing.expect(!validateInstanceName("has@at"));
    const long = "a" ** 65;
    try std.testing.expect(!validateInstanceName(long));
    try std.testing.expect(validateInstanceName("b" ** 64));
}
