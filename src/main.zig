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
//!       --plugin PATH   Runtime plugin shared library (repeatable)
//!       --plugin-config KEY=VALUE  Config for the most recent --plugin
//!
//! A run is one configuration cycle through the module engine (conf.zig):
//! every module parses its own directives, the core module resolves addresses
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
const logging = @import("modules/logging.zig");
const plugin = @import("plugin.zig");
const plugins = @import("modules/plugins.zig");

const version = "0.3.2";

const usage =
    \\Usage: curtsy --config <path> [--check-config]
    \\       curtsy --listen <endpoint> --upstream <endpoint> [--protocols <list>] [--balance <name>] [--check-config]
    \\       curtsy --rule <spec> [--rule <spec> ...] [--check-config]
    \\
    \\Transparent TCP and UDP traffic forwarder
    \\
    \\Options:
    \\  -c, --config <path>  Path to the YAML configuration file
    \\      --check-config   Validate configuration and exit
    \\      --version        Print version and exit
    \\  -h, --help           Show this help and exit
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
    \\      --plugin <path>         Runtime plugin path (repeatable; normalized
    \\                              to an absolute path)
    \\      --plugin-config <k=v>   Private config for the most recent --plugin
    \\                              (repeatable)
    \\
;

const Options = union(enum) {
    file: struct {
        path: []const u8,
        check_config: bool,
    },
    cli: struct {
        configuration: cli.Configuration,
        check_config: bool,
    },

    fn checkConfig(self: Options) bool {
        return switch (self) {
            .file => |value| value.check_config,
            .cli => |*value| value.check_config,
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

    var cycle = switch (options) {
        .file => |value| conf.loadFile(gpa, value.path, &diag),
        .cli => |*value| cli.loadCycle(gpa, &value.configuration, &diag),
    } catch {
        reportConfigError(&diag);
        return 2;
    };
    var owns_cycle = true;
    defer if (owns_cycle) cycle.deinit();

    // Runtime plugins must be loaded before resolve: dynamic balancer and
    // protocol names are registered by init and resolved afterward.
    var bootstrap_logger = log.LogStore.init(cycle.conf(logging).level);
    var plugin_manager = plugin.Manager.init(gpa, &bootstrap_logger);
    var owns_plugin_manager = true;
    defer if (owns_plugin_manager) plugin_manager.deinit();
    const desired_plugins = plugins.specs(&cycle);
    var prepared_plugins = plugin_manager.prepare(desired_plugins) catch |err| {
        writeErr("curtsy: configuration error: unable to load plugins: {s}\n", .{@errorName(err)});
        return 2;
    };
    plugin_manager.commit(&prepared_plugins, desired_plugins);

    // Resolve addresses plus dynamic balancer/protocol names before reporting
    // success, so --check-config validates the complete runtime.
    const resolved = core.resolveForwarder(gpa, cycle.allocator(), &cycle, null, &diag) catch {
        reportConfigError(&diag);
        return 2;
    };

    if (options.checkConfig()) {
        writeOut("configuration is valid\n", .{});
        return 0;
    }

    const source: core.ConfigSource = switch (options) {
        .file => |value| .{ .file = value.path },
        .cli => |*value| .{ .cli = &value.configuration },
    };
    var service = core.ForwarderService.init(gpa, source, cycle, resolved);
    service.adoptPluginManager(plugin_manager);
    owns_plugin_manager = false;
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
    var listen: ?[]const u8 = null;
    var upstream: ?[]const u8 = null;
    var rule_specs: std.ArrayList([]const u8) = .empty;
    defer rule_specs.deinit(gpa);
    var protocols: ?[]const u8 = null;
    var balance: ?[]const u8 = null;
    var plugin_paths: std.ArrayList([]const u8) = .empty;
    defer plugin_paths.deinit(gpa);
    var plugin_config_arguments: std.ArrayList(cli.PluginConfigArgument) = .empty;
    defer plugin_config_arguments.deinit(gpa);

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
        } else if (std.mem.eql(u8, arg, "--plugin")) {
            i += 1;
            if (i >= args.len) return usageError("missing value for '{s}'", .{arg});
            try plugin_paths.append(gpa, std.mem.span(args[i]));
        } else if (std.mem.startsWith(u8, arg, "--plugin=")) {
            try plugin_paths.append(gpa, arg["--plugin=".len..]);
        } else if (std.mem.eql(u8, arg, "--plugin-config")) {
            i += 1;
            if (i >= args.len) return usageError("missing value for '{s}'", .{arg});
            if (plugin_paths.items.len == 0) return usageError("'--plugin-config' requires a preceding '--plugin'", .{});
            try plugin_config_arguments.append(gpa, .{
                .plugin_index = plugin_paths.items.len - 1,
                .text = std.mem.span(args[i]),
            });
        } else if (std.mem.startsWith(u8, arg, "--plugin-config=")) {
            if (plugin_paths.items.len == 0) return usageError("'--plugin-config' requires a preceding '--plugin'", .{});
            try plugin_config_arguments.append(gpa, .{
                .plugin_index = plugin_paths.items.len - 1,
                .text = arg["--plugin-config=".len..],
            });
        } else {
            return usageError("unexpected argument '{s}'", .{arg});
        }
    }

    const has_cli = listen != null or upstream != null or rule_specs.items.len > 0 or
        protocols != null or balance != null or plugin_paths.items.len > 0;

    if (config_path != null and has_cli) {
        return usageError("cannot combine '--config' with CLI endpoint/plugin flags", .{});
    }

    if (!has_cli) {
        const path = config_path orelse
            return usageError("missing expected argument '--config <path>' or CLI endpoint flags", .{});
        return .{ .file = .{ .path = path, .check_config = check_config } };
    }

    if (rule_specs.items.len > 0) {
        if (listen != null or upstream != null or protocols != null or balance != null) {
            return usageError("cannot combine '--rule' with '--listen'/'--upstream'/'--protocols'/'--balance'", .{});
        }
        var config = (try cli.parseFlags(gpa, null, null, rule_specs.items, null, null, diag)).?;
        errdefer config.deinit();
        try cli.setPlugins(&config, plugin_paths.items, plugin_config_arguments.items, gpa, diag);
        return .{ .cli = .{ .configuration = config, .check_config = check_config } };
    }

    if (listen == null) return usageError("missing expected argument '--listen <endpoint>'", .{});
    if (upstream == null) return usageError("missing expected argument '--upstream <endpoint>'", .{});
    var config = (try cli.parseFlags(gpa, listen, upstream, &.{}, protocols, balance, diag)).?;
    errdefer config.deinit();
    try cli.setPlugins(&config, plugin_paths.items, plugin_config_arguments.items, gpa, diag);
    return .{ .cli = .{ .configuration = config, .check_config = check_config } };
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
