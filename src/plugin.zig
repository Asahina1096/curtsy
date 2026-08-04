//! Runtime shared-library plugin loader.
//!
//! Plugins cross a versioned C ABI rather than Zig's unstable native ABI.
//! ABI v1 exposes load/unload lifecycle, logging and an optional balancer
//! callback table plus named protocol modules (new names or TCP/UDP overrides).
//! Upstream generations and listeners retain dynamic code explicitly; removal
//! first hides it from candidate resolution, then keeps the library in a
//! retiring state until the final runtime object releases it.

const std = @import("std");
const log = @import("log.zig");
const net = @import("net.zig");
const upstream = @import("modules/upstream.zig");

const Allocator = std.mem.Allocator;

pub const abi_version: u32 = 1;
pub const entry_symbol: [:0]const u8 = "curtsy_plugin_entry";

pub const ConfigEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const Spec = struct {
    path: []const u8,
    config: []const ConfigEntry = &.{},
};

pub const HostApi = extern struct {
    abi_version: u32,
    struct_size: u32,
    context: ?*anyopaque,
    log_fn: *const fn (?*anyopaque, u32, [*]const u8, usize) callconv(.c) void,
};

pub const Descriptor = extern struct {
    abi_version: u32,
    struct_size: u32,
    name: [*:0]const u8,
    version: [*:0]const u8,
    init: *const fn (*const HostApi, *?*anyopaque) callconv(.c) i32,
    deinit: *const fn (?*anyopaque) callconv(.c) void,
};

const ExtendedDescriptor = extern struct {
    abi_version: u32,
    struct_size: u32,
    name: [*:0]const u8,
    version: [*:0]const u8,
    init: *const fn (*const HostApi, *?*anyopaque) callconv(.c) i32,
    deinit: *const fn (?*anyopaque) callconv(.c) void,
    balancer: ?*const BalancerApi,
};

const FullDescriptor = extern struct {
    abi_version: u32,
    struct_size: u32,
    name: [*:0]const u8,
    version: [*:0]const u8,
    init: *const fn (*const HostApi, *?*anyopaque) callconv(.c) i32,
    deinit: *const fn (?*anyopaque) callconv(.c) void,
    balancer: ?*const BalancerApi,
    configuration: ?*const ConfigurationApi,
};

const CompleteDescriptor = extern struct {
    abi_version: u32,
    struct_size: u32,
    name: [*:0]const u8,
    version: [*:0]const u8,
    init: *const fn (*const HostApi, *?*anyopaque) callconv(.c) i32,
    deinit: *const fn (?*anyopaque) callconv(.c) void,
    balancer: ?*const BalancerApi,
    configuration: ?*const ConfigurationApi,
    protocol: ?*const ProtocolApi,
};

const CConfigEntry = extern struct {
    key: [*]const u8,
    key_len: usize,
    value: [*]const u8,
    value_len: usize,
};

const ConfigurationApi = extern struct {
    struct_size: u32,
    prepare: ?*const fn (?*anyopaque, [*]const CConfigEntry, usize, *?*anyopaque) callconv(.c) i32,
    commit: ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) void,
    discard: ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) void,
};

const EligibleFn = *const fn (?*anyopaque, usize) callconv(.c) u8;

const BalancerApi = extern struct {
    struct_size: u32,
    name: [*:0]const u8,
    build: ?*const fn ([*]const u32, usize, *?*anyopaque) callconv(.c) i32,
    destroy: ?*const fn (?*anyopaque) callconv(.c) void,
    pick: ?*const fn (?*anyopaque, usize, u32, u64, u64, ?*anyopaque, EligibleFn) callconv(.c) usize,
};

pub const CSocketAddress = extern struct {
    family: u32,
    address: [16]u8,
    port: u16,
    reserved: u16 = 0,
    scope_id: u32,
};

pub const CUpstreamSelector = extern struct {
    context: ?*anyopaque,
    is_multi: ?*const fn (?*anyopaque) callconv(.c) u8,
    pick: ?*const fn (?*anyopaque, ?*const CSocketAddress, u64, *CSocketAddress) callconv(.c) u8,
    report_success: ?*const fn (?*anyopaque, *const CSocketAddress) callconv(.c) void,
    report_failure: ?*const fn (?*anyopaque, *const CSocketAddress, u64) callconv(.c) void,
};

pub const CProtocolMetrics = extern struct {
    received_messages: u64 = 0,
    sent_messages: u64 = 0,
    received_bytes: u64 = 0,
    sent_bytes: u64 = 0,
    errors: u64 = 0,
};

pub const ProtocolConfiguration = extern struct {
    struct_size: u32,
    protocol_name: [*]const u8,
    protocol_name_len: usize,
    listen_addresses: [*]const CSocketAddress,
    listen_address_count: usize,
    upstream_address: CSocketAddress,
    upstream_selector: CUpstreamSelector,
    connect_seconds: i64,
    tcp_idle_seconds: i64,
    udp_session_seconds: i64,
    tcp_listen_backlog: i64,
    max_tcp_buffered_bytes: i64,
    max_udp_associations: i64,
    worker_threads: i64,
    udp_io_threads: i64,
    start_paused: u8,
    reserved: [7]u8 = @splat(0),
};

pub const ProtocolApi = extern struct {
    struct_size: u32,
    name: [*:0]const u8,
    drains_connections: u8,
    reserved: [7]u8,
    create: ?*const fn (?*anyopaque, *const ProtocolConfiguration, *?*anyopaque) callconv(.c) i32,
    activate: ?*const fn (?*anyopaque) callconv(.c) void,
    stop_accepting: ?*const fn (?*anyopaque) callconv(.c) void,
    destroy: ?*const fn (?*anyopaque) callconv(.c) void,
    update_configuration: ?*const fn (?*anyopaque, *const ProtocolConfiguration, u8) callconv(.c) void,
    update_backlog: ?*const fn (?*anyopaque, i32) callconv(.c) i32,
    force_close: ?*const fn (?*anyopaque) callconv(.c) void,
    active_count: ?*const fn (?*anyopaque) callconv(.c) usize,
    buffered_bytes: ?*const fn (?*anyopaque) callconv(.c) i64,
    association_count: ?*const fn (?*anyopaque) callconv(.c) u64,
    metrics: ?*const fn (?*anyopaque, *CProtocolMetrics) callconv(.c) void,
};

const ProtocolApiBase = extern struct {
    struct_size: u32,
    name: [*:0]const u8,
    drains_connections: u8,
    reserved: [7]u8,
    create: ?*const fn (?*anyopaque, *const ProtocolConfiguration, *?*anyopaque) callconv(.c) i32,
    activate: ?*const fn (?*anyopaque) callconv(.c) void,
    stop_accepting: ?*const fn (?*anyopaque) callconv(.c) void,
    destroy: ?*const fn (?*anyopaque) callconv(.c) void,
    update_configuration: ?*const fn (?*anyopaque, *const ProtocolConfiguration, u8) callconv(.c) void,
    update_backlog: ?*const fn (?*anyopaque, i32) callconv(.c) i32,
    force_close: ?*const fn (?*anyopaque) callconv(.c) void,
    active_count: ?*const fn (?*anyopaque) callconv(.c) usize,
    buffered_bytes: ?*const fn (?*anyopaque) callconv(.c) i64,
    association_count: ?*const fn (?*anyopaque) callconv(.c) u64,
};

const DynamicBalancer = struct {
    api: *const BalancerApi,
    references: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    balancer: upstream.Balancer,
};

pub const ProtocolBinding = struct {
    api: *const ProtocolApi,
    name: []const u8,
    plugin_context: ?*anyopaque,
    references: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn retain(self: *ProtocolBinding) void {
        _ = self.references.fetchAdd(1, .acq_rel);
    }

    pub fn release(self: *ProtocolBinding) void {
        const previous = self.references.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
    }
};

var protocol_mutex: log.Mutex = .{};
var dynamic_protocols: std.ArrayList(*ProtocolBinding) = .empty;

pub fn protocolBinding(name: []const u8) ?*ProtocolBinding {
    protocol_mutex.lock();
    defer protocol_mutex.unlock();
    for (dynamic_protocols.items) |binding| {
        if (std.mem.eql(u8, binding.name, name)) return binding;
    }
    return null;
}

fn registerDynamicProtocol(binding: *ProtocolBinding) !void {
    protocol_mutex.lock();
    defer protocol_mutex.unlock();
    for (dynamic_protocols.items) |existing| {
        if (std.mem.eql(u8, existing.name, binding.name)) return error.PluginProtocolConflict;
    }
    try dynamic_protocols.append(std.heap.page_allocator, binding);
}

fn unregisterDynamicProtocol(binding: *ProtocolBinding) void {
    protocol_mutex.lock();
    defer protocol_mutex.unlock();
    for (dynamic_protocols.items, 0..) |existing, i| {
        if (existing == binding) {
            _ = dynamic_protocols.swapRemove(i);
            if (dynamic_protocols.items.len == 0) {
                dynamic_protocols.deinit(std.heap.page_allocator);
                dynamic_protocols = .empty;
            }
            return;
        }
    }
}

const EntryFn = *const fn () callconv(.c) ?*const Descriptor;

const Loaded = struct {
    path: []u8,
    library: std.DynLib,
    descriptor: *const Descriptor,
    host_api: *HostApi,
    context: ?*anyopaque,
    dynamic_balancer: ?*DynamicBalancer = null,
    dynamic_protocol: ?*ProtocolBinding = null,
    configuration_api: ?*const ConfigurationApi = null,
    pending_configuration: ?*anyopaque = null,
    retiring: bool = false,

    fn close(self: *Loaded, allocator: Allocator, logger: *log.LogStore) void {
        if (self.pending_configuration) |candidate| {
            self.configuration_api.?.discard.?(self.context, candidate);
            self.pending_configuration = null;
        }
        if (self.dynamic_balancer) |binding| {
            std.debug.assert(binding.references.load(.acquire) == 0);
            upstream.unregisterDynamicBalancer(allocator, &binding.balancer);
            allocator.destroy(binding);
        }
        if (self.dynamic_protocol) |binding| {
            std.debug.assert(binding.references.load(.acquire) == 0);
            unregisterDynamicProtocol(binding);
            allocator.destroy(binding);
        }
        logger.info("plugin unloading name={s} version={s} path={s}", .{
            std.mem.span(self.descriptor.name),
            std.mem.span(self.descriptor.version),
            self.path,
        });
        self.descriptor.deinit(self.context);
        allocator.destroy(self.host_api);
        self.library.close();
        allocator.free(self.path);
    }
};

const ConfigurationUpdate = struct {
    loaded: *Loaded,
    candidate: ?*anyopaque,
};

pub const Prepared = struct {
    additions: std.ArrayList(Loaded) = .empty,
    revivals: std.ArrayList(*Loaded) = .empty,
    suspensions: std.ArrayList(*Loaded) = .empty,
    configuration_updates: std.ArrayList(ConfigurationUpdate) = .empty,

    pub fn discard(self: *Prepared, allocator: Allocator, logger: *log.LogStore) void {
        for (self.additions.items) |*loaded| loaded.close(allocator, logger);
        self.additions.deinit(allocator);
        for (self.revivals.items) |loaded| {
            if (loaded.dynamic_balancer) |binding| upstream.unregisterDynamicBalancer(allocator, &binding.balancer);
            if (loaded.dynamic_protocol) |binding| unregisterDynamicProtocol(binding);
        }
        self.revivals.deinit(allocator);
        for (self.suspensions.items) |loaded| {
            if (loaded.dynamic_balancer) |binding| {
                upstream.registerDynamicBalancer(allocator, &binding.balancer) catch unreachable;
            }
            if (loaded.dynamic_protocol) |binding| registerDynamicProtocol(binding) catch unreachable;
        }
        self.suspensions.deinit(allocator);
        for (self.configuration_updates.items) |update| {
            update.loaded.configuration_api.?.discard.?(update.loaded.context, update.candidate);
        }
        self.configuration_updates.deinit(allocator);
        self.* = .{};
    }
};

pub const Manager = struct {
    allocator: Allocator,
    logger: *log.LogStore,
    loaded: std.ArrayList(Loaded) = .empty,

    pub fn init(allocator: Allocator, logger: *log.LogStore) Manager {
        return .{ .allocator = allocator, .logger = logger };
    }

    pub fn deinit(self: *Manager) void {
        while (self.loaded.pop()) |loaded_value| {
            var loaded = loaded_value;
            loaded.close(self.allocator, self.logger);
        }
        self.loaded.deinit(self.allocator);
    }

    pub fn rebindLogger(self: *Manager, logger: *log.LogStore) void {
        self.logger = logger;
        for (self.loaded.items) |*loaded| {
            loaded.host_api.context = logger;
        }
    }

    pub fn reap(self: *Manager) void {
        var i: usize = 0;
        while (i < self.loaded.items.len) {
            const loaded = &self.loaded.items[i];
            if (!loaded.retiring or pluginReferences(loaded) != 0) {
                i += 1;
                continue;
            }
            var ready = self.loaded.swapRemove(i);
            ready.close(self.allocator, self.logger);
        }
    }

    pub fn prepare(self: *Manager, desired_specs: []const Spec) !Prepared {
        var prepared = Prepared{};
        errdefer prepared.discard(self.allocator, self.logger);
        var addition_count: usize = 0;
        for (desired_specs) |spec| if (!self.contains(spec.path)) {
            addition_count += 1;
        };
        try self.loaded.ensureUnusedCapacity(self.allocator, addition_count);
        try prepared.additions.ensureTotalCapacity(self.allocator, addition_count);
        try prepared.revivals.ensureTotalCapacity(self.allocator, desired_specs.len);
        try prepared.suspensions.ensureTotalCapacity(self.allocator, self.loaded.items.len);
        try prepared.configuration_updates.ensureTotalCapacity(self.allocator, desired_specs.len);
        for (self.loaded.items) |*loaded| {
            if (loaded.retiring or containsSpec(desired_specs, loaded.path)) continue;
            if (loaded.dynamic_balancer != null or loaded.dynamic_protocol != null) {
                prepared.suspensions.appendAssumeCapacity(loaded);
            }
            if (loaded.dynamic_balancer) |binding| {
                upstream.unregisterDynamicBalancer(self.allocator, &binding.balancer);
            }
            if (loaded.dynamic_protocol) |binding| unregisterDynamicProtocol(binding);
        }
        for (desired_specs) |spec| {
            if (self.findActive(spec.path)) |active| {
                if (active.configuration_api != null or spec.config.len > 0) {
                    prepared.configuration_updates.appendAssumeCapacity(.{
                        .loaded = active,
                        .candidate = try prepareConfiguration(self.allocator, active, spec.config),
                    });
                }
                continue;
            }
            if (self.findRetiring(spec.path)) |retiring| {
                prepared.revivals.appendAssumeCapacity(retiring);
                if (retiring.dynamic_balancer) |binding| {
                    try upstream.registerDynamicBalancer(self.allocator, &binding.balancer);
                }
                if (retiring.dynamic_protocol) |binding| try registerDynamicProtocol(binding);
                if (retiring.configuration_api != null or spec.config.len > 0) {
                    prepared.configuration_updates.appendAssumeCapacity(.{
                        .loaded = retiring,
                        .candidate = try prepareConfiguration(self.allocator, retiring, spec.config),
                    });
                }
                continue;
            }
            var loaded = try self.load(spec, desired_specs);
            errdefer loaded.close(self.allocator, self.logger);
            const name = std.mem.span(loaded.descriptor.name);
            for (prepared.additions.items) |addition| {
                if (std.mem.eql(u8, std.mem.span(addition.descriptor.name), name)) {
                    return error.PluginNameConflict;
                }
            }
            prepared.additions.appendAssumeCapacity(loaded);
        }
        return prepared;
    }

    /// Publish additions, then retire libraries absent from the desired set.
    /// All fallible work is completed by prepare; commit is allocation-free.
    pub fn commit(self: *Manager, prepared: *Prepared, desired_specs: []const Spec) void {
        for (prepared.additions.items) |*loaded| {
            commitPendingConfiguration(loaded);
            self.loaded.appendAssumeCapacity(loaded.*);
        }
        prepared.additions.clearRetainingCapacity();
        prepared.additions.deinit(self.allocator);
        for (prepared.revivals.items) |loaded| loaded.retiring = false;
        prepared.revivals.deinit(self.allocator);
        prepared.suspensions.deinit(self.allocator);
        for (prepared.configuration_updates.items) |update| {
            update.loaded.configuration_api.?.commit.?(update.loaded.context, update.candidate);
        }
        prepared.configuration_updates.deinit(self.allocator);
        prepared.* = .{};

        var i: usize = 0;
        while (i < self.loaded.items.len) {
            if (containsSpec(desired_specs, self.loaded.items[i].path)) {
                i += 1;
                continue;
            }
            const loaded = &self.loaded.items[i];
            if (loaded.dynamic_balancer) |binding| {
                upstream.unregisterDynamicBalancer(self.allocator, &binding.balancer);
            }
            if (loaded.dynamic_protocol) |binding| unregisterDynamicProtocol(binding);
            loaded.retiring = true;
            if (pluginReferences(loaded) == 0) {
                var retiring = self.loaded.swapRemove(i);
                retiring.close(self.allocator, self.logger);
            } else {
                i += 1;
            }
        }
    }

    pub fn count(self: *const Manager) usize {
        return self.loaded.items.len;
    }

    fn contains(self: *const Manager, path: []const u8) bool {
        for (self.loaded.items) |loaded| {
            if (!loaded.retiring and std.mem.eql(u8, loaded.path, path)) return true;
        }
        return false;
    }

    fn findActive(self: *Manager, path: []const u8) ?*Loaded {
        for (self.loaded.items) |*loaded| {
            if (!loaded.retiring and std.mem.eql(u8, loaded.path, path)) return loaded;
        }
        return null;
    }

    fn findRetiring(self: *Manager, path: []const u8) ?*Loaded {
        for (self.loaded.items) |*loaded| {
            if (loaded.retiring and std.mem.eql(u8, loaded.path, path)) return loaded;
        }
        return null;
    }

    fn load(self: *Manager, spec: Spec, desired_specs: []const Spec) !Loaded {
        const path = spec.path;
        if (!std.fs.path.isAbsolute(path)) return error.PluginPathNotAbsolute;

        var library = std.DynLib.open(path) catch return error.PluginOpenFailed;
        errdefer library.close();
        const entry = library.lookup(EntryFn, entry_symbol) orelse return error.PluginEntryMissing;
        const descriptor = entry() orelse return error.PluginDescriptorMissing;
        if (descriptor.abi_version != abi_version or descriptor.struct_size < @sizeOf(Descriptor)) {
            return error.PluginAbiMismatch;
        }

        const name = boundedSpan(descriptor.name) orelse return error.PluginMetadataInvalid;
        const version = boundedSpan(descriptor.version) orelse return error.PluginMetadataInvalid;
        if (name.len == 0 or version.len == 0) return error.PluginMetadataInvalid;
        for (self.loaded.items) |loaded| {
            if (std.mem.eql(u8, std.mem.span(loaded.descriptor.name), name) and
                containsSpec(desired_specs, loaded.path)) return error.PluginNameConflict;
        }

        const owned_path = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned_path);
        const host = try self.allocator.create(HostApi);
        errdefer self.allocator.destroy(host);
        host.* = .{
            .abi_version = abi_version,
            .struct_size = @sizeOf(HostApi),
            .context = self.logger,
            .log_fn = hostLog,
        };
        var context: ?*anyopaque = null;
        if (descriptor.init(host, &context) != 0) return error.PluginInitFailed;
        errdefer descriptor.deinit(context);

        var dynamic_balancer: ?*DynamicBalancer = null;
        var dynamic_registered = false;
        errdefer if (dynamic_balancer) |binding| {
            if (dynamic_registered) upstream.unregisterDynamicBalancer(self.allocator, &binding.balancer);
            self.allocator.destroy(binding);
        };
        if (descriptor.struct_size >= @sizeOf(ExtendedDescriptor)) {
            const extended: *const ExtendedDescriptor = @ptrCast(descriptor);
            if (extended.balancer) |api| {
                dynamic_balancer = try createDynamicBalancer(self.allocator, api);
                upstream.registerDynamicBalancer(self.allocator, &dynamic_balancer.?.balancer) catch
                    return error.PluginBalancerConflict;
                dynamic_registered = true;
            }
        }

        var configuration_api: ?*const ConfigurationApi = null;
        if (descriptor.struct_size >= @sizeOf(FullDescriptor)) {
            const full: *const FullDescriptor = @ptrCast(descriptor);
            if (full.configuration) |api| {
                if (api.struct_size < @sizeOf(ConfigurationApi) or api.prepare == null or api.commit == null or api.discard == null) {
                    return error.PluginConfigurationInvalid;
                }
                configuration_api = api;
            }
        }
        var dynamic_protocol: ?*ProtocolBinding = null;
        var protocol_registered = false;
        errdefer if (dynamic_protocol) |binding| {
            if (protocol_registered) unregisterDynamicProtocol(binding);
            self.allocator.destroy(binding);
        };
        if (descriptor.struct_size >= @sizeOf(CompleteDescriptor)) {
            const complete: *const CompleteDescriptor = @ptrCast(descriptor);
            if (complete.protocol) |api| {
                dynamic_protocol = try createDynamicProtocol(self.allocator, api, context);
                registerDynamicProtocol(dynamic_protocol.?) catch return error.PluginProtocolConflict;
                protocol_registered = true;
            }
        }
        var pending_configuration: ?*anyopaque = null;
        if (configuration_api != null or spec.config.len > 0) {
            var configuring = Loaded{
                .path = owned_path,
                .library = library,
                .descriptor = descriptor,
                .host_api = host,
                .context = context,
                .dynamic_balancer = dynamic_balancer,
                .dynamic_protocol = dynamic_protocol,
                .configuration_api = configuration_api,
            };
            pending_configuration = try prepareConfiguration(self.allocator, &configuring, spec.config);
        }

        self.logger.info("plugin loaded name={s} version={s} path={s}", .{ name, version, path });
        return .{
            .path = owned_path,
            .library = library,
            .descriptor = descriptor,
            .host_api = host,
            .context = context,
            .dynamic_balancer = dynamic_balancer,
            .dynamic_protocol = dynamic_protocol,
            .configuration_api = configuration_api,
            .pending_configuration = pending_configuration,
        };
    }
};

fn pluginReferences(loaded: *const Loaded) u32 {
    var references: u32 = 0;
    if (loaded.dynamic_balancer) |binding| references +|= binding.references.load(.acquire);
    if (loaded.dynamic_protocol) |binding| references +|= binding.references.load(.acquire);
    return references;
}

fn createDynamicProtocol(allocator: Allocator, api: *const ProtocolApi, plugin_context: ?*anyopaque) !*ProtocolBinding {
    if (api.struct_size < @sizeOf(ProtocolApiBase) or
        api.create == null or api.activate == null or api.stop_accepting == null or
        api.destroy == null or api.update_configuration == null or api.force_close == null or
        api.active_count == null or api.buffered_bytes == null or api.association_count == null)
    {
        return error.PluginProtocolInvalid;
    }
    const name = boundedSpan(api.name) orelse return error.PluginProtocolInvalid;
    if (!net.validProtocolName(name)) return error.PluginProtocolInvalid;
    if (std.mem.eql(u8, name, "tcp") and api.drains_connections == 0) return error.PluginProtocolInvalid;
    if (std.mem.eql(u8, name, "udp") and api.drains_connections != 0) return error.PluginProtocolInvalid;
    if (std.mem.eql(u8, name, "tcp") and api.update_backlog == null) return error.PluginProtocolInvalid;
    const binding = try allocator.create(ProtocolBinding);
    binding.* = .{ .api = api, .name = name, .plugin_context = plugin_context };
    return binding;
}

fn prepareConfiguration(allocator: Allocator, loaded: *Loaded, entries: []const ConfigEntry) !?*anyopaque {
    const api = loaded.configuration_api orelse {
        if (entries.len > 0) return error.PluginConfigurationUnsupported;
        return null;
    };
    const c_entries = try allocator.alloc(CConfigEntry, entries.len);
    defer allocator.free(c_entries);
    for (entries, 0..) |entry, i| {
        c_entries[i] = .{
            .key = entry.key.ptr,
            .key_len = entry.key.len,
            .value = entry.value.ptr,
            .value_len = entry.value.len,
        };
    }
    var candidate: ?*anyopaque = null;
    if (api.prepare.?(loaded.context, c_entries.ptr, c_entries.len, &candidate) != 0) {
        return error.PluginConfigurationRejected;
    }
    return candidate;
}

fn commitPendingConfiguration(loaded: *Loaded) void {
    const api = loaded.configuration_api orelse return;
    api.commit.?(loaded.context, loaded.pending_configuration);
    loaded.pending_configuration = null;
}

fn createDynamicBalancer(allocator: Allocator, api: *const BalancerApi) !*DynamicBalancer {
    if (api.struct_size < @sizeOf(BalancerApi) or api.build == null or api.destroy == null or api.pick == null) {
        return error.PluginBalancerInvalid;
    }
    const name = boundedSpan(api.name) orelse return error.PluginBalancerInvalid;
    if (name.len == 0) return error.PluginBalancerInvalid;
    const binding = try allocator.create(DynamicBalancer);
    binding.* = .{
        .api = api,
        .balancer = .{
            .name = name,
            .context = binding,
            .retain = dynamicRetain,
            .release = dynamicRelease,
            .build = dynamicBuild,
            .destroy = dynamicDestroy,
            .pick = dynamicPick,
        },
    };
    return binding;
}

fn dynamicRetain(context: ?*anyopaque) void {
    const binding: *DynamicBalancer = @ptrCast(@alignCast(context.?));
    _ = binding.references.fetchAdd(1, .acq_rel);
}

fn dynamicRelease(context: ?*anyopaque) void {
    const binding: *DynamicBalancer = @ptrCast(@alignCast(context.?));
    const previous = binding.references.fetchSub(1, .acq_rel);
    std.debug.assert(previous > 0);
}

fn dynamicBuild(context: ?*anyopaque, allocator: Allocator, addresses: []const net.SocketAddr, weights: []const u32) error{OutOfMemory}!?*anyopaque {
    _ = allocator;
    _ = addresses;
    const binding: *DynamicBalancer = @ptrCast(@alignCast(context.?));
    var state: ?*anyopaque = null;
    if (binding.api.build.?(weights.ptr, weights.len, &state) != 0) return error.OutOfMemory;
    return state;
}

fn dynamicDestroy(context: ?*anyopaque, allocator: Allocator, state: ?*anyopaque) void {
    _ = allocator;
    const binding: *DynamicBalancer = @ptrCast(@alignCast(context.?));
    binding.api.destroy.?(state);
}

const EligibilityContext = struct {
    upstreams: []const upstream.UpstreamState,
    now_ns: u64,
};

fn dynamicEligible(context: ?*anyopaque, index: usize) callconv(.c) u8 {
    const eligibility: *const EligibilityContext = @ptrCast(@alignCast(context.?));
    if (index >= eligibility.upstreams.len) return 0;
    return @intFromBool(eligibility.upstreams[index].eligible(eligibility.now_ns));
}

fn dynamicPick(context: ?*anyopaque, state: ?*anyopaque, upstreams_state: []const upstream.UpstreamState, cursor: *std.atomic.Value(u32), client: ?net.SocketAddr, now_ns: u64) usize {
    const binding: *DynamicBalancer = @ptrCast(@alignCast(context.?));
    const cursor_value = cursor.fetchAdd(1, .monotonic);
    const client_hash: u64 = if (client) |address| std.hash.Wyhash.hash(0, std.mem.asBytes(&address)) else 0;
    var eligibility = EligibilityContext{ .upstreams = upstreams_state, .now_ns = now_ns };
    const picked = binding.api.pick.?(state, upstreams_state.len, cursor_value, client_hash, now_ns, &eligibility, dynamicEligible);
    if (picked < upstreams_state.len and upstreams_state[picked].eligible(now_ns)) return picked;
    const start: usize = cursor_value % @as(u32, @intCast(upstreams_state.len));
    for (0..upstreams_state.len) |offset| {
        const index = (start + offset) % upstreams_state.len;
        if (upstreams_state[index].eligible(now_ns)) return index;
    }
    return start;
}

fn boundedSpan(ptr: [*:0]const u8) ?[]const u8 {
    for (0..256) |i| {
        if (ptr[i] == 0) return ptr[0..i];
    }
    return null;
}

fn containsSpec(specs: []const Spec, needle: []const u8) bool {
    for (specs) |spec| {
        if (std.mem.eql(u8, spec.path, needle)) return true;
    }
    return false;
}

fn hostLog(context: ?*anyopaque, level: u32, message: [*]const u8, message_len: usize) callconv(.c) void {
    const logger: *log.LogStore = @ptrCast(@alignCast(context orelse return));
    const text = message[0..message_len];
    switch (level) {
        0 => logger.debug("plugin message={s}", .{text}),
        1 => logger.info("plugin message={s}", .{text}),
        2 => logger.warning("plugin message={s}", .{text}),
        else => logger.err("plugin message={s}", .{text}),
    }
}

test "manager rejects relative plugin paths" {
    var logger = log.LogStore.init("critical");
    var manager = Manager.init(std.testing.allocator, &logger);
    defer manager.deinit();
    try std.testing.expectError(error.PluginPathNotAbsolute, manager.prepare(&.{.{ .path = "relative.so" }}));
}

test "empty desired set prepares and commits without libraries" {
    var logger = log.LogStore.init("critical");
    var manager = Manager.init(std.testing.allocator, &logger);
    defer manager.deinit();
    var prepared = try manager.prepare(&.{});
    manager.commit(&prepared, &.{});
    try std.testing.expectEqual(@as(usize, 0), manager.count());
}
