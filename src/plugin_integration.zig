//! Build-time integration probe for the shared-library plugin ABI.

const std = @import("std");
const conf = @import("conf.zig");
const log = @import("log.zig");
const fw = @import("module.zig");
const net = @import("net.zig");
const plugin = @import("plugin.zig");
const core = @import("modules/core.zig");
const upstream = @import("modules/upstream.zig");

pub fn main(init: std.process.Init) !void {
    const args = init.minimal.args.vector;
    if (args.len != 3) return error.MissingPluginPath;
    var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
    _ = std.c.getcwd(&cwd_buf, cwd_buf.len) orelse return error.GetCwdFailed;
    const cwd_len = std.mem.indexOfScalar(u8, &cwd_buf, 0) orelse return error.GetCwdFailed;
    const path = try std.fs.path.resolve(init.gpa, &.{ cwd_buf[0..cwd_len], std.mem.span(args[1]) });
    defer init.gpa.free(path);
    const protocol_path = try std.fs.path.resolve(init.gpa, &.{ cwd_buf[0..cwd_len], std.mem.span(args[2]) });
    defer init.gpa.free(protocol_path);

    var logger = log.LogStore.init("critical");
    var manager = plugin.Manager.init(init.gpa, &logger);
    defer manager.deinit();

    const configured = [_]plugin.Spec{.{ .path = path, .config = &.{.{ .key = "message", .value = "configured" }} }};
    var prepared = try manager.prepare(&configured);
    manager.commit(&prepared, &configured);
    if (manager.count() != 1) return error.PluginNotLoaded;

    const with_protocol = [_]plugin.Spec{
        configured[0],
        .{ .path = protocol_path },
    };
    var protocol_addition = try manager.prepare(&with_protocol);
    manager.commit(&protocol_addition, &with_protocol);
    const protocol_binding = plugin.protocolBinding("probe_udp") orelse return error.ProtocolNotRegistered;
    const protocol_module = fw.protocolModule(.{ .dynamic = "probe_udp" }) orelse return error.ProtocolModuleNotOverridden;
    if (protocol_module.context != @as(?*anyopaque, protocol_binding)) return error.ProtocolModuleNotOverridden;
    var protocol_diag = conf.Diagnostics{};
    defer if (protocol_diag.message) |message| init.gpa.free(message);
    const protocol_yaml =
        \\version: 1
        \\runtime: { tuningDaemon: false }
        \\rules:
        \\  - listen: { host: "127.0.0.1", port: 9000 }
        \\    protocols: [probe_udp]
        \\    upstreams:
        \\      - { host: "127.0.0.1", port: 9001 }
        \\      - { host: "127.0.0.1", port: 9002 }
    ;
    var protocol_cycle = try conf.loadYaml(init.gpa, protocol_yaml, &protocol_diag);
    const resolved_protocol = try core.resolveForwarder(init.gpa, protocol_cycle.allocator(), &protocol_cycle, null, &protocol_diag);
    var protocol_service = core.ForwarderService.init(init.gpa, .{ .file = "" }, protocol_cycle, resolved_protocol);
    var protocol_service_live = true;
    defer if (protocol_service_live) protocol_service.deinit();
    try protocol_service.startInitialRules();
    const protocol_snapshot = protocol_service.snapshot() orelse return error.ProtocolSnapshotUnavailable;
    if (protocol_snapshot.metrics.plugin.received_messages != 3 or
        protocol_snapshot.metrics.plugin.sent_messages != 2 or
        protocol_snapshot.metrics.plugin.received_bytes != 300 or
        protocol_snapshot.metrics.plugin.sent_bytes != 200 or
        protocol_snapshot.metrics.plugin.errors != 1)
    {
        return error.ProtocolMetricsMismatch;
    }

    var rejected_protocol_removal = try manager.prepare(&configured);
    if (plugin.protocolBinding("probe_udp") != null) return error.CandidateProtocolRemovalStillVisible;
    rejected_protocol_removal.discard(init.gpa, &logger);
    if (plugin.protocolBinding("probe_udp") == null) return error.RejectedProtocolRemovalNotRestored;

    var protocol_removal = try manager.prepare(&configured);
    var protocol_removal_pending = true;
    defer if (protocol_removal_pending) protocol_removal.discard(init.gpa, &logger);
    var fallback_diag = conf.Diagnostics{};
    defer if (fallback_diag.message) |message| init.gpa.free(message);
    var fallback_cycle = try conf.loadYaml(
        init.gpa,
        \\version: 1
        \\runtime: { tuningDaemon: false }
        \\rules:
        \\  - listen: { host: "127.0.0.1", port: 9000 }
        \\    protocols: [udp]
        \\    upstreams:
        \\      - { host: "127.0.0.1", port: 9001 }
        \\      - { host: "127.0.0.1", port: 9002 }
    ,
        &fallback_diag,
    );
    var fallback_cycle_live = true;
    defer if (fallback_cycle_live) fallback_cycle.deinit();
    const fallback_resolved = try core.resolveForwarder(init.gpa, fallback_cycle.allocator(), &fallback_cycle, null, &fallback_diag);
    try protocol_service.apply(fallback_resolved);
    manager.commit(&protocol_removal, &configured);
    protocol_removal_pending = false;
    if (plugin.protocolBinding("probe_udp") != null) return error.RetiringProtocolStillRegistered;
    if (fw.protocolModule(.{ .dynamic = "probe_udp" }) != null) return error.RemovedProtocolStillResolved;
    if (manager.count() != 2) return error.ReferencedProtocolPluginUnloaded;

    var protocol_revival = try manager.prepare(&with_protocol);
    manager.commit(&protocol_revival, &with_protocol);
    if (plugin.protocolBinding("probe_udp") == null) return error.ProtocolNotRevived;
    var final_protocol_removal = try manager.prepare(&configured);
    manager.commit(&final_protocol_removal, &configured);
    protocol_service.deinit();
    protocol_service_live = false;
    fallback_cycle.deinit();
    fallback_cycle_live = false;
    manager.reap();
    if (manager.count() != 1) return error.ProtocolPluginNotUnloaded;

    const rejected_config = [_]plugin.Spec{.{ .path = path, .config = &.{.{ .key = "unknown", .value = "value" }} }};
    if (manager.prepare(&rejected_config)) |unexpected| {
        var prepared_unexpected = unexpected;
        prepared_unexpected.discard(init.gpa, &logger);
        return error.InvalidPluginConfigurationAccepted;
    } else |err| {
        if (err != error.PluginConfigurationRejected) return err;
    }

    const rollback_config = [_]plugin.Spec{.{ .path = path, .config = &.{.{ .key = "message", .value = "rollback" }} }};
    var rollback = try manager.prepare(&rollback_config);
    rollback.discard(init.gpa, &logger);

    const balancer = upstream.balancerByName("first_available") orelse return error.BalancerNotRegistered;
    const addresses = [_]net.SocketAddr{
        net.SocketAddr.parseIp("127.0.0.1", 9000).?,
        net.SocketAddr.parseIp("127.0.0.1", 9001).?,
    };
    var pool = try upstream.UpstreamPool.init(init.gpa, &addresses, &.{ 1, 1 }, balancer);
    var pool_live = true;
    defer if (pool_live) pool.deinit();
    if (!pool.pick(null, 0).eql(addresses[0])) return error.DynamicBalancerPickFailed;

    var rejected_removal = try manager.prepare(&.{});
    if (upstream.balancerByName("first_available") != null) return error.CandidateRemovalStillVisible;
    rejected_removal.discard(init.gpa, &logger);
    if (upstream.balancerByName("first_available") == null) return error.RejectedRemovalNotRestored;

    var removal = try manager.prepare(&.{});
    manager.commit(&removal, &.{});
    if (manager.count() != 1) return error.ReferencedPluginUnloaded;
    if (upstream.balancerByName("first_available") != null) return error.RetiringBalancerStillRegistered;

    var revival = try manager.prepare(&configured);
    manager.commit(&revival, &configured);
    if (upstream.balancerByName("first_available") == null) return error.BalancerNotRevived;
    var second_removal = try manager.prepare(&.{});
    manager.commit(&second_removal, &.{});

    pool.deinit();
    pool_live = false;
    manager.reap();
    if (manager.count() != 0) return error.PluginNotUnloaded;
}
