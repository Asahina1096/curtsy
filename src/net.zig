//! Network primitives shared by every module.
//!
//! SocketAddr (IPv4/IPv6 union with sockaddr_storage conversion), the
//! resolver abstraction (injectable for tests), listen-address expansion
//! ("*" becomes the dual-stack wildcard pair) and protocol list helpers.
//! This layer knows nothing about YAML or the module engine.

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const Diagnostics = struct {
    message: ?[]const u8 = null,
};

pub fn setDiag(gpa: Allocator, diag: *Diagnostics, comptime fmt: []const u8, args: anytype) void {
    diag.message = std.fmt.allocPrint(gpa, fmt, args) catch "out of memory while reporting error";
}

pub const ForwardProtocol = enum { tcp, udp };

pub const EndpointConfiguration = struct {
    host: []const u8,
    port: i64,
};

// ---------------------------------------------------------------------------
// SocketAddr: IPv4/IPv6 union with sockaddr_storage conversion and formatting
// ---------------------------------------------------------------------------

extern "c" fn inet_pton(af: c_int, src: [*:0]const u8, dst: *anyopaque) c_int;
extern "c" fn inet_ntop(af: c_int, src: *const anyopaque, dst: [*]u8, size: std.os.linux.socklen_t) ?[*:0]const u8;

pub const SocketAddr = struct {
    pub const Family = enum { v4, v6 };

    family: Family,
    /// Network-order address bytes; the first 4 are used for IPv4.
    addr: [16]u8,
    port: u16,
    scope_id: u32 = 0,

    pub fn initV4(addr: [4]u8, port: u16) SocketAddr {
        var bytes: [16]u8 = @splat(0);
        bytes[0..4].* = addr;
        return .{ .family = .v4, .addr = bytes, .port = port };
    }

    pub fn initV6(addr: [16]u8, port: u16) SocketAddr {
        return .{ .family = .v6, .addr = addr, .port = port };
    }

    /// Parse a numeric IPv4 or IPv6 literal. Returns null for anything else.
    pub fn parseIp(host: []const u8, port: u16) ?SocketAddr {
        var buf: [256]u8 = undefined;
        if (host.len >= buf.len) return null;
        @memcpy(buf[0..host.len], host);
        buf[host.len] = 0;
        const c_host: [*:0]const u8 = @ptrCast(&buf);

        var v4: [4]u8 = undefined;
        if (inet_pton(std.os.linux.AF.INET, c_host, &v4) == 1) {
            return initV4(v4, port);
        }
        var v6: [16]u8 = undefined;
        if (inet_pton(std.os.linux.AF.INET6, c_host, &v6) == 1) {
            return initV6(v6, port);
        }
        return null;
    }

    pub fn eql(self: SocketAddr, other: SocketAddr) bool {
        if (self.family != other.family or self.port != other.port) return false;
        return switch (self.family) {
            .v4 => std.mem.eql(u8, self.addr[0..4], other.addr[0..4]),
            .v6 => std.mem.eql(u8, &self.addr, &other.addr) and self.scope_id == other.scope_id,
        };
    }

    /// True for loopback addresses: the whole IPv4 127.0.0.0/8 block and
    /// IPv6 ::1.
    pub fn isLoopback(self: SocketAddr) bool {
        return switch (self.family) {
            .v4 => self.addr[0] == 127,
            .v6 => std.mem.allEqual(u8, self.addr[0..15], 0) and self.addr[15] == 1,
        };
    }

    /// Copy this address into a sockaddr_storage; returns the active length.
    pub fn toSockaddrStorage(self: SocketAddr, storage: *std.os.linux.sockaddr.storage) std.os.linux.socklen_t {
        switch (self.family) {
            .v4 => {
                const in: *std.os.linux.sockaddr.in = @ptrCast(@alignCast(storage));
                in.* = .{
                    .port = std.mem.nativeToBig(u16, self.port),
                    .addr = @bitCast(self.addr[0..4].*),
                };
                return @sizeOf(std.os.linux.sockaddr.in);
            },
            .v6 => {
                const in6: *std.os.linux.sockaddr.in6 = @ptrCast(@alignCast(storage));
                in6.* = .{
                    .port = std.mem.nativeToBig(u16, self.port),
                    .flowinfo = 0,
                    .addr = self.addr,
                    .scope_id = self.scope_id,
                };
                return @sizeOf(std.os.linux.sockaddr.in6);
            },
        }
    }

    /// "1.2.3.4:80" or "[::1]:80".
    pub fn format(self: SocketAddr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        var buf: [64]u8 = undefined;
        const host = self.hostString(&buf);
        switch (self.family) {
            .v4 => try writer.print("{s}:{d}", .{ host, self.port }),
            .v6 => try writer.print("[{s}]:{d}", .{ host, self.port }),
        }
    }

    fn hostString(self: SocketAddr, buf: *[64]u8) []const u8 {
        const af: c_int = switch (self.family) {
            .v4 => std.os.linux.AF.INET,
            .v6 => std.os.linux.AF.INET6,
        };
        const src: *const anyopaque = switch (self.family) {
            .v4 => @ptrCast(self.addr[0..4].ptr),
            .v6 => @ptrCast(&self.addr),
        };
        const result = inet_ntop(af, src, buf.ptr, buf.len) orelse return "<invalid>";
        return std.mem.span(result);
    }
};

// ---------------------------------------------------------------------------
// Resolver: host name or IP literal plus port -> concrete SocketAddr
// ---------------------------------------------------------------------------

pub const ResolveError = error{
    ResolutionFailed,
    OutOfMemory,
};

/// Maps a host name or IP literal plus port to a concrete SocketAddr.
/// Injectable for tests.
pub const Resolver = *const fn (host: []const u8, port: u16) anyerror!SocketAddr;

pub fn resolverAddress(
    resolve: Resolver,
    host: []const u8,
    port: u16,
    gpa: Allocator,
    diag: *Diagnostics,
) !SocketAddr {
    return resolve(host, port) catch {
        setDiag(gpa, diag, "unable to resolve host '{s}'", .{host});
        return error.ResolutionFailed;
    };
}

/// Resolve a listen endpoint to one or two addresses; "*" expands to the
/// dual-stack wildcard pair 0.0.0.0 and ::. `alloc` must outlive the result.
pub fn resolveListenAddresses(
    resolve: Resolver,
    alloc: Allocator,
    host: []const u8,
    port: u16,
    gpa: Allocator,
    diag: *Diagnostics,
) ResolveError![]SocketAddr {
    if (std.mem.eql(u8, host, "*")) {
        const pair = try alloc.alloc(SocketAddr, 2);
        pair[0] = SocketAddr.initV4(.{ 0, 0, 0, 0 }, port);
        pair[1] = SocketAddr.initV6(@splat(0), port);
        return pair;
    }
    const address = try resolverAddress(resolve, host, port, gpa, diag);
    const single = try alloc.alloc(SocketAddr, 1);
    single[0] = address;
    return single;
}

/// Default resolver: IP literals are parsed directly, everything else goes
/// through getaddrinfo (first usable AF_INET/AF_INET6 result wins).
pub fn defaultResolver(host: []const u8, port: u16) anyerror!SocketAddr {
    if (SocketAddr.parseIp(host, port)) |address| return address;

    var host_buf: [512]u8 = undefined;
    if (host.len >= host_buf.len) return error.ResolutionFailed;
    @memcpy(host_buf[0..host.len], host);
    host_buf[host.len] = 0;
    const c_host: [*:0]const u8 = @ptrCast(&host_buf);

    const hints = std.c.addrinfo{
        .flags = .{},
        .family = std.os.linux.AF.UNSPEC,
        .socktype = std.os.linux.SOCK.STREAM,
        .protocol = 0,
        .addrlen = 0,
        .canonname = null,
        .addr = null,
        .next = null,
    };
    var result: ?*std.c.addrinfo = null;
    const rc = std.c.getaddrinfo(c_host, null, &hints, &result);
    if (@intFromEnum(rc) != 0) return error.ResolutionFailed;
    const first = result orelse return error.ResolutionFailed;
    defer std.c.freeaddrinfo(first);

    var current: ?*std.c.addrinfo = first;
    while (current) |info| : (current = info.next) {
        const sockaddr = info.addr orelse continue;
        switch (sockaddr.family) {
            std.os.linux.AF.INET => {
                const in: *std.os.linux.sockaddr.in = @ptrCast(@alignCast(sockaddr));
                return SocketAddr.initV4(@bitCast(in.addr), port);
            },
            std.os.linux.AF.INET6 => {
                const in6: *std.os.linux.sockaddr.in6 = @ptrCast(@alignCast(sockaddr));
                var address = SocketAddr.initV6(in6.addr, port);
                address.scope_id = in6.scope_id;
                return address;
            },
            else => continue,
        }
    }
    return error.ResolutionFailed;
}

// ---------------------------------------------------------------------------
// Protocol list helpers
// ---------------------------------------------------------------------------

pub fn hasProtocol(protocols: []const ForwardProtocol, protocol: ForwardProtocol) bool {
    for (protocols) |candidate| {
        if (candidate == protocol) return true;
    }
    return false;
}

pub fn protocolsString(protocols: []const ForwardProtocol, buf: []u8) []const u8 {
    var fbs = std.Io.Writer.fixed(buf);
    for (protocols, 0..) |protocol, i| {
        if (i > 0) fbs.print(",", .{}) catch return buf[0..fbs.end];
        fbs.print("{s}", .{@tagName(protocol)}) catch return buf[0..fbs.end];
    }
    return buf[0..fbs.end];
}

pub fn addressesEqual(a: []const SocketAddr, b: []const SocketAddr) bool {
    if (a.len != b.len) return false;
    for (a, b) |addr_a, addr_b| {
        if (!addr_a.eql(addr_b)) return false;
    }
    return true;
}

/// Shared protocol list validation: non-empty, no duplicates. `path` is the
/// key path used in diagnostics ("" for the global list, "rules[0]" for a
/// rule override).
pub fn validateProtocols(gpa: Allocator, diag: *Diagnostics, protocols: []const ForwardProtocol, path: []const u8) error{InvalidConfiguration}!void {
    const prefix: []const u8 = if (path.len == 0) "protocols" else path;
    if (protocols.len == 0) {
        setDiag(gpa, diag, "{s} must not be empty", .{prefix});
        return error.InvalidConfiguration;
    }
    for (protocols, 0..) |protocol, i| {
        for (protocols[i + 1 ..]) |other| {
            if (protocol == other) {
                setDiag(gpa, diag, "{s} must not contain duplicates", .{prefix});
                return error.InvalidConfiguration;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "socket address formatting and sockaddr conversion" {
    const v4 = SocketAddr.parseIp("1.2.3.4", 80).?;
    const v4_text = try std.fmt.allocPrint(testing.allocator, "{f}", .{v4});
    defer testing.allocator.free(v4_text);
    try testing.expectEqualStrings("1.2.3.4:80", v4_text);

    const v6 = SocketAddr.parseIp("::1", 8080).?;
    const v6_text = try std.fmt.allocPrint(testing.allocator, "{f}", .{v6});
    defer testing.allocator.free(v6_text);
    try testing.expectEqualStrings("[::1]:8080", v6_text);

    var storage: std.os.linux.sockaddr.storage = undefined;
    const len = v4.toSockaddrStorage(&storage);
    try testing.expectEqual(@as(std.os.linux.socklen_t, @sizeOf(std.os.linux.sockaddr.in)), len);
    const in: *std.os.linux.sockaddr.in = @ptrCast(@alignCast(&storage));
    try testing.expectEqual(std.os.linux.AF.INET, in.family);
    try testing.expectEqual(std.mem.nativeToBig(u16, 80), in.port);

    const v6_len = v6.toSockaddrStorage(&storage);
    try testing.expectEqual(@as(std.os.linux.socklen_t, @sizeOf(std.os.linux.sockaddr.in6)), v6_len);
    const in6: *std.os.linux.sockaddr.in6 = @ptrCast(@alignCast(&storage));
    try testing.expectEqual(std.os.linux.AF.INET6, in6.family);

    try testing.expect(v4.eql(SocketAddr.parseIp("1.2.3.4", 80).?));
    try testing.expect(!v4.eql(SocketAddr.parseIp("1.2.3.4", 81).?));
    try testing.expect(!v4.eql(v6));
}

test "wildcard listen resolves to dual-stack wildcards" {
    var diag = Diagnostics{};
    const addresses = try resolveListenAddresses(defaultResolver, testing.allocator, "*", 9000, testing.allocator, &diag);
    defer testing.allocator.free(addresses);
    try testing.expectEqual(@as(usize, 2), addresses.len);
    try testing.expectEqual(SocketAddr.Family.v4, addresses[0].family);
    try testing.expectEqual(SocketAddr.Family.v6, addresses[1].family);
    try testing.expectEqual(@as(u16, 9000), addresses[0].port);
    try testing.expect(std.mem.allEqual(u8, &addresses[1].addr, 0));
}

test "resolves IPv4, IPv6 and hostnames" {
    var diag = Diagnostics{};
    const v4 = try resolverAddress(defaultResolver, "127.0.0.1", 9001, testing.allocator, &diag);
    try testing.expectEqual(SocketAddr.Family.v4, v4.family);
    const v6 = try resolverAddress(defaultResolver, "::1", 9001, testing.allocator, &diag);
    try testing.expectEqual(SocketAddr.Family.v6, v6.family);
    const hostname = try resolverAddress(defaultResolver, "localhost", 9001, testing.allocator, &diag);
    try testing.expectEqual(@as(u16, 9001), hostname.port);
}

test "isLoopback recognizes ipv4 127/8 and ipv6 ::1" {
    try testing.expect(SocketAddr.parseIp("127.0.0.1", 80).?.isLoopback());
    try testing.expect(SocketAddr.parseIp("127.255.255.254", 80).?.isLoopback());
    try testing.expect(SocketAddr.parseIp("::1", 80).?.isLoopback());
    try testing.expect(!SocketAddr.parseIp("192.0.2.1", 80).?.isLoopback());
    try testing.expect(!SocketAddr.parseIp("::2", 80).?.isLoopback());
    try testing.expect(!SocketAddr.parseIp("::ffff:127.0.0.1", 80).?.isLoopback());
}
