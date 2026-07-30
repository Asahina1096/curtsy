//! Configuration model, YAML-subset loader, validation and address resolution.
//!
//! The YAML parser supports exactly what config.example.yaml needs: nested
//! block mappings by indentation, flow mappings `{ a: b }`, block and flow
//! sequences, bare and double-quoted scalars, and `#` comments (full-line and
//! trailing, never inside quoted strings). Unknown keys are rejected with
//! dotted paths and all defaults/ranges match the documented configuration.

const std = @import("std");
const autotune = @import("autotune.zig");

const Allocator = std.mem.Allocator;

pub const LoadError = error{
    InvalidConfiguration,
    ReadFailed,
    OutOfMemory,
};

/// Carries the human-readable failure reason after a LoadError.
/// `message` is allocated with the allocator passed to the load function;
/// the caller owns it.
pub const Diagnostics = struct {
    message: ?[]const u8 = null,
};

pub const ForwardProtocol = enum { tcp, udp };

pub const SockmapAccelerationMode = enum { auto, enabled, disabled };

pub const EndpointConfiguration = struct {
    host: []const u8,
    port: i64,
};

pub const TimeoutConfiguration = struct {
    connect_seconds: i64 = 5,
    tcp_idle_seconds: i64 = 300,
    udp_session_seconds: i64 = 60,
    shutdown_grace_seconds: i64 = 10,
};

pub const LimitAutoTuning = struct {
    tcp_listen_backlog: bool = true,
    max_tcp_buffered_bytes: bool = true,
    max_udp_associations: bool = true,
    max_udp_pending_datagrams: bool = true,
    max_udp_pending_bytes: bool = true,
};

pub const LimitConfiguration = struct {
    tcp_listen_backlog: i64,
    max_tcp_buffered_bytes: i64,
    max_udp_associations: i64,
    max_udp_pending_datagrams: i64,
    max_udp_pending_bytes: i64,
    auto_tuning: LimitAutoTuning = .{},
};

pub const LogConfiguration = struct {
    level: []const u8 = "info",
};

pub const RuntimeOptions = struct {
    worker_threads: i64 = 0,
    tuning_daemon: bool = true,
    tuning_interval_seconds: i64 = 5,
};

pub const PerformanceConfiguration = struct {
    pub const default_udp_socket_buffer_bytes: i64 = 4 * 1_024 * 1_024;

    tcp_sockmap_acceleration: SockmapAccelerationMode = .auto,
    udp_sockmap_acceleration: SockmapAccelerationMode = .auto,
    // Zero keeps the kernel default socket buffers; any positive value is
    // silently clamped to net.core.rmem_max/wmem_max without CAP_NET_ADMIN.
    udp_socket_buffer_bytes: i64 = default_udp_socket_buffer_bytes,
    // Zero auto-tunes to the worker thread count.
    udp_io_threads: i64 = 0,
};

pub const ForwarderConfiguration = struct {
    version: i64,
    protocols: []ForwardProtocol,
    listen: EndpointConfiguration,
    upstream: EndpointConfiguration,
    timeouts: TimeoutConfiguration = .{},
    limits: LimitConfiguration,
    logging: LogConfiguration = .{},
    runtime: RuntimeOptions = .{},
    performance: PerformanceConfiguration = .{},
};

/// A parsed configuration plus the arena owning all strings/slices inside it.
pub const LoadedConfiguration = struct {
    arena: std.heap.ArenaAllocator,
    value: ForwarderConfiguration,

    pub fn deinit(self: *LoadedConfiguration) void {
        self.arena.deinit();
    }
};

/// Load and fully validate a configuration from a YAML file.
pub fn loadFile(gpa: Allocator, path: []const u8, diag: *Diagnostics) LoadError!LoadedConfiguration {
    const text = readFileAlloc(gpa, path, 16 * 1_024 * 1_024) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            setDiag(gpa, diag, "unable to read configuration file: {s}", .{path});
            return error.ReadFailed;
        },
    };
    defer gpa.free(text);
    return loadYaml(gpa, text, diag);
}

/// Load and fully validate a configuration from YAML text.
pub fn loadYaml(gpa: Allocator, text: []const u8, diag: *Diagnostics) LoadError!LoadedConfiguration {
    var loaded = LoadedConfiguration{
        .arena = std.heap.ArenaAllocator.init(gpa),
        .value = undefined,
    };
    errdefer loaded.arena.deinit();
    const arena = loaded.arena.allocator();

    var parser = Parser{
        .arena = arena,
        .gpa = gpa,
        .diag = diag,
        .lines = try splitLines(arena, gpa, text, diag),
    };
    const root = try parser.parseDocument();
    if (root.* != .mapping) {
        setDiag(gpa, diag, "YAML root must be a mapping", .{});
        return error.InvalidConfiguration;
    }
    try validateKeys(gpa, diag, root.mapping, "");
    var decoder = Decoder{ .arena = arena, .gpa = gpa, .diag = diag };
    loaded.value = try decoder.decodeConfiguration(root);
    try validate(gpa, diag, loaded.value);
    return loaded;
}

fn setDiag(gpa: Allocator, diag: *Diagnostics, comptime fmt: []const u8, args: anytype) void {
    diag.message = std.fmt.allocPrint(gpa, fmt, args) catch "out of memory while reporting error";
}

fn readFileAlloc(gpa: Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{}, 0);
    defer _ = std.os.linux.close(fd);
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var buf: [16 * 1_024]u8 = undefined;
    while (true) {
        const n = try std.posix.read(fd, &buf);
        if (n == 0) break;
        if (list.items.len + n > max_bytes) return error.FileTooBig;
        try list.appendSlice(gpa, buf[0..n]);
    }
    return list.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// YAML subset parser
// ---------------------------------------------------------------------------

const Scalar = struct {
    text: []const u8,
    /// True when the scalar was double-quoted; quoted scalars never decode as
    /// ints or bools, matching YAML semantics.
    quoted: bool,
};

const Entry = struct {
    key: []const u8,
    value: *Value,
};

const Value = union(enum) {
    null_value,
    scalar: Scalar,
    mapping: []Entry,
    sequence: []*Value,
};

const Line = struct {
    indent: usize,
    content: []const u8,
    number: usize,
};

/// Split the document into significant lines: comments stripped, blank lines
/// dropped, indentation measured. Comment stripping respects double quotes.
fn splitLines(arena: Allocator, gpa: Allocator, text: []const u8, diag: *Diagnostics) LoadError![]Line {
    var lines: std.ArrayList(Line) = .empty;
    errdefer lines.deinit(arena);

    var raw_lines = std.mem.splitScalar(u8, text, '\n');
    var number: usize = 0;
    while (raw_lines.next()) |raw| {
        number += 1;
        var line = raw;
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];

        var indent: usize = 0;
        while (indent < line.len and line[indent] == ' ') indent += 1;
        if (indent < line.len and line[indent] == '\t') {
            setDiag(gpa, diag, "line {d}: tabs are not allowed for indentation", .{number});
            return error.InvalidConfiguration;
        }

        // Strip trailing comment: a '#' preceded by whitespace (or at line
        // start) starts a comment unless inside a double-quoted string.
        var content = line[indent..];
        var in_quote = false;
        var escaped = false;
        for (content, 0..) |c, i| {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (in_quote and c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') in_quote = !in_quote;
            if (!in_quote and c == '#' and (i == 0 or content[i - 1] == ' ' or content[i - 1] == '\t')) {
                content = content[0..i];
                break;
            }
        }
        content = std.mem.trimEnd(u8, content, " \t");
        if (content.len == 0) continue;
        try lines.append(arena, .{ .indent = indent, .content = content, .number = number });
    }
    return lines.toOwnedSlice(arena);
}

const Parser = struct {
    arena: Allocator,
    gpa: Allocator,
    diag: *Diagnostics,
    lines: []Line,
    index: usize = 0,

    fn fail(self: *Parser, line: ?usize, comptime fmt: []const u8, args: anytype) error{InvalidConfiguration} {
        if (line) |n| {
            setDiag(self.gpa, self.diag, "line {d}: " ++ fmt, .{n} ++ args);
        } else {
            setDiag(self.gpa, self.diag, fmt, args);
        }
        return error.InvalidConfiguration;
    }

    fn newValue(self: *Parser, value: Value) error{OutOfMemory}!*Value {
        const ptr = try self.arena.create(Value);
        ptr.* = value;
        return ptr;
    }

    fn parseDocument(self: *Parser) error{ InvalidConfiguration, OutOfMemory }!*Value {
        if (self.lines.len == 0) return self.newValue(.null_value);
        const root = try self.parseBlock(self.lines[0].indent);
        if (self.index < self.lines.len) {
            return self.fail(self.lines[self.index].number, "unexpected content", .{});
        }
        return root;
    }

    fn parseBlock(self: *Parser, indent: usize) error{ InvalidConfiguration, OutOfMemory }!*Value {
        if (isSequenceItem(self.lines[self.index].content)) {
            return self.parseSequence(indent);
        }
        return self.parseMapping(indent);
    }

    fn parseMapping(self: *Parser, indent: usize) error{ InvalidConfiguration, OutOfMemory }!*Value {
        var entries: std.ArrayList(Entry) = .empty;
        while (self.index < self.lines.len) {
            const line = self.lines[self.index];
            if (line.indent != indent or isSequenceItem(line.content)) break;

            const colon = findMappingColon(line.content) orelse
                return self.fail(line.number, "expected a 'key: value' mapping entry", .{});
            const key = try self.parseKey(line.content[0..colon], line.number);
            const rest = std.mem.trimStart(u8, line.content[colon + 1 ..], " ");
            self.index += 1;

            var value: *Value = undefined;
            if (rest.len == 0) {
                // Nested block (deeper indent), a same-indent block sequence,
                // or an empty value.
                if (self.index < self.lines.len and self.lines[self.index].indent > indent) {
                    value = try self.parseBlock(self.lines[self.index].indent);
                } else if (self.index < self.lines.len and
                    self.lines[self.index].indent == indent and
                    isSequenceItem(self.lines[self.index].content))
                {
                    value = try self.parseSequence(indent);
                } else {
                    value = try self.newValue(.null_value);
                }
            } else {
                value = try self.parseInlineValue(rest, line.number);
            }
            try entries.append(self.arena, .{ .key = key, .value = value });
        }
        return self.newValue(.{ .mapping = try entries.toOwnedSlice(self.arena) });
    }

    fn parseSequence(self: *Parser, indent: usize) error{ InvalidConfiguration, OutOfMemory }!*Value {
        var items: std.ArrayList(*Value) = .empty;
        while (self.index < self.lines.len) {
            const line = self.lines[self.index];
            if (line.indent != indent or !isSequenceItem(line.content)) break;
            const rest = std.mem.trimStart(u8, line.content[1..], " ");
            self.index += 1;
            var value: *Value = undefined;
            if (rest.len == 0) {
                if (self.index < self.lines.len and self.lines[self.index].indent > indent) {
                    value = try self.parseBlock(self.lines[self.index].indent);
                } else {
                    value = try self.newValue(.null_value);
                }
            } else {
                value = try self.parseInlineValue(rest, line.number);
            }
            try items.append(self.arena, value);
        }
        return self.newValue(.{ .sequence = try items.toOwnedSlice(self.arena) });
    }

    /// Parse a value that appears inline on the current line: a flow
    /// mapping/sequence or a scalar.
    fn parseInlineValue(self: *Parser, text: []const u8, line: usize) error{ InvalidConfiguration, OutOfMemory }!*Value {
        var flow = FlowParser{ .parser = self, .text = text, .line = line };
        const value = try flow.parseValue();
        flow.skipSpaces();
        if (flow.pos != text.len) {
            return self.fail(line, "unexpected trailing characters after value", .{});
        }
        return value;
    }

    fn parseKey(self: *Parser, text: []const u8, line: usize) error{ InvalidConfiguration, OutOfMemory }![]const u8 {
        const key = std.mem.trim(u8, text, " ");
        if (key.len == 0) return self.fail(line, "empty mapping key", .{});
        if (key[0] == '"') {
            var flow = FlowParser{ .parser = self, .text = key, .line = line };
            const value = try flow.parseQuoted();
            flow.skipSpaces();
            if (flow.pos != key.len) return self.fail(line, "invalid quoted mapping key", .{});
            return value;
        }
        return key;
    }
};

fn isSequenceItem(content: []const u8) bool {
    return content.len >= 1 and content[0] == '-' and (content.len == 1 or content[1] == ' ');
}

/// Find the colon that separates a mapping key from its value: the first ':'
/// that is at end of line or followed by a space, outside double quotes.
fn findMappingColon(content: []const u8) ?usize {
    var in_quote = false;
    var escaped = false;
    for (content, 0..) |c, i| {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (in_quote and c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '"') in_quote = !in_quote;
        if (!in_quote and c == ':' and (i + 1 == content.len or content[i + 1] == ' ')) return i;
    }
    return null;
}

/// Recursive-descent parser for flow collections and scalars within one line.
const FlowParser = struct {
    parser: *Parser,
    text: []const u8,
    line: usize,
    pos: usize = 0,

    fn skipSpaces(self: *FlowParser) void {
        while (self.pos < self.text.len and self.text[self.pos] == ' ') self.pos += 1;
    }

    fn parseValue(self: *FlowParser) error{ InvalidConfiguration, OutOfMemory }!*Value {
        self.skipSpaces();
        if (self.pos >= self.text.len) {
            return self.parser.fail(self.line, "expected a value", .{});
        }
        return switch (self.text[self.pos]) {
            '{' => self.parseFlowMapping(),
            '[' => self.parseFlowSequence(),
            '"' => self.parser.newValue(.{ .scalar = .{ .text = try self.parseQuoted(), .quoted = true } }),
            else => self.parser.newValue(.{ .scalar = .{ .text = self.parseBare(), .quoted = false } }),
        };
    }

    fn parseFlowMapping(self: *FlowParser) error{ InvalidConfiguration, OutOfMemory }!*Value {
        self.pos += 1; // '{'
        var entries: std.ArrayList(Entry) = .empty;
        self.skipSpaces();
        if (self.pos < self.text.len and self.text[self.pos] == '}') {
            self.pos += 1;
            return self.parser.newValue(.{ .mapping = &.{} });
        }
        while (true) {
            self.skipSpaces();
            const key_start = self.pos;
            var key: []const u8 = undefined;
            if (self.pos < self.text.len and self.text[self.pos] == '"') {
                key = try self.parseQuoted();
            } else {
                while (self.pos < self.text.len and self.text[self.pos] != ':' and
                    self.text[self.pos] != ',' and self.text[self.pos] != '}') self.pos += 1;
                key = std.mem.trim(u8, self.text[key_start..self.pos], " ");
            }
            if (key.len == 0) return self.parser.fail(self.line, "empty key in flow mapping", .{});
            self.skipSpaces();
            if (self.pos >= self.text.len or self.text[self.pos] != ':') {
                return self.parser.fail(self.line, "expected ':' after flow mapping key", .{});
            }
            self.pos += 1;
            const value = try self.parseValue();
            try entries.append(self.parser.arena, .{ .key = key, .value = value });
            self.skipSpaces();
            if (self.pos >= self.text.len) {
                return self.parser.fail(self.line, "unterminated flow mapping", .{});
            }
            switch (self.text[self.pos]) {
                ',' => self.pos += 1,
                '}' => {
                    self.pos += 1;
                    return self.parser.newValue(.{ .mapping = try entries.toOwnedSlice(self.parser.arena) });
                },
                else => return self.parser.fail(self.line, "expected ',' or '}}' in flow mapping", .{}),
            }
        }
    }

    fn parseFlowSequence(self: *FlowParser) error{ InvalidConfiguration, OutOfMemory }!*Value {
        self.pos += 1; // '['
        var items: std.ArrayList(*Value) = .empty;
        self.skipSpaces();
        if (self.pos < self.text.len and self.text[self.pos] == ']') {
            self.pos += 1;
            return self.parser.newValue(.{ .sequence = &.{} });
        }
        while (true) {
            const value = try self.parseValue();
            try items.append(self.parser.arena, value);
            self.skipSpaces();
            if (self.pos >= self.text.len) {
                return self.parser.fail(self.line, "unterminated flow sequence", .{});
            }
            switch (self.text[self.pos]) {
                ',' => self.pos += 1,
                ']' => {
                    self.pos += 1;
                    return self.parser.newValue(.{ .sequence = try items.toOwnedSlice(self.parser.arena) });
                },
                else => return self.parser.fail(self.line, "expected ',' or ']' in flow sequence", .{}),
            }
        }
    }

    /// Parse a double-quoted scalar starting at `self.pos`; handles the
    /// common escapes and stops past the closing quote.
    fn parseQuoted(self: *FlowParser) error{ InvalidConfiguration, OutOfMemory }![]const u8 {
        self.pos += 1; // opening quote
        var out: std.ArrayList(u8) = .empty;
        while (true) {
            if (self.pos >= self.text.len) {
                return self.parser.fail(self.line, "unterminated quoted string", .{});
            }
            const c = self.text[self.pos];
            self.pos += 1;
            switch (c) {
                '"' => return out.toOwnedSlice(self.parser.arena),
                '\\' => {
                    if (self.pos >= self.text.len) {
                        return self.parser.fail(self.line, "unterminated escape sequence", .{});
                    }
                    const esc = self.text[self.pos];
                    self.pos += 1;
                    const decoded: u8 = switch (esc) {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        '0' => 0,
                        '"' => '"',
                        '\\' => '\\',
                        '/' => '/',
                        else => return self.parser.fail(self.line, "unsupported escape '\\{c}'", .{esc}),
                    };
                    try out.append(self.parser.arena, decoded);
                },
                else => try out.append(self.parser.arena, c),
            }
        }
    }

    /// Bare flow scalar: runs until a flow delimiter, then trimmed.
    fn parseBare(self: *FlowParser) []const u8 {
        const start = self.pos;
        while (self.pos < self.text.len and self.text[self.pos] != ',' and
            self.text[self.pos] != '}' and self.text[self.pos] != ']') self.pos += 1;
        return std.mem.trim(u8, self.text[start..self.pos], " ");
    }
};

// ---------------------------------------------------------------------------
// Key whitelist (mirrors ConfigurationLoader.allowedKeys)
// ---------------------------------------------------------------------------

const allowed_keys = [_]struct { path: []const u8, keys: []const []const u8 }{
    .{ .path = "", .keys = &.{ "version", "protocols", "listen", "upstream", "timeouts", "limits", "logging", "runtime", "performance" } },
    .{ .path = "listen", .keys = &.{ "host", "port" } },
    .{ .path = "upstream", .keys = &.{ "host", "port" } },
    .{ .path = "timeouts", .keys = &.{ "connectSeconds", "tcpIdleSeconds", "udpSessionSeconds", "shutdownGraceSeconds" } },
    .{ .path = "limits", .keys = &.{ "tcpListenBacklog", "maxTCPBufferedBytes", "maxUDPAssociations", "maxUDPPendingDatagrams", "maxUDPPendingBytes" } },
    .{ .path = "logging", .keys = &.{"level"} },
    .{ .path = "runtime", .keys = &.{ "workerThreads", "tuningDaemon", "tuningIntervalSeconds" } },
    .{ .path = "performance", .keys = &.{ "tcpSockmapAcceleration", "udpSockmapAcceleration", "udpSocketBufferBytes", "udpIOThreads" } },
};

fn allowedKeysFor(path: []const u8) ?[]const []const u8 {
    for (allowed_keys) |entry| {
        if (std.mem.eql(u8, entry.path, path)) return entry.keys;
    }
    return null;
}

fn validateKeys(gpa: Allocator, diag: *Diagnostics, mapping: []const Entry, path: []const u8) LoadError!void {
    const allowed = allowedKeysFor(path) orelse return;
    for (mapping) |entry| {
        var known = false;
        for (allowed) |key| {
            if (std.mem.eql(u8, key, entry.key)) {
                known = true;
                break;
            }
        }
        if (!known) {
            if (path.len == 0) {
                setDiag(gpa, diag, "unknown configuration key: {s}", .{entry.key});
            } else {
                setDiag(gpa, diag, "unknown configuration key: {s}.{s}", .{ path, entry.key });
            }
            return error.InvalidConfiguration;
        }
        if (entry.value.* == .mapping and allowedKeysFor(entry.key) != null) {
            try validateKeys(gpa, diag, entry.value.mapping, entry.key);
        }
    }
}

// ---------------------------------------------------------------------------
// Decoder: map the Value tree onto the typed configuration model
// ---------------------------------------------------------------------------

const Decoder = struct {
    arena: Allocator,
    gpa: Allocator,
    diag: *Diagnostics,

    fn fail(self: *Decoder, comptime fmt: []const u8, args: anytype) error{InvalidConfiguration} {
        setDiag(self.gpa, self.diag, fmt, args);
        return error.InvalidConfiguration;
    }

    fn decodeConfiguration(self: *Decoder, root: *Value) LoadError!ForwarderConfiguration {
        const map = root.mapping;
        const auto_limits = autotune.limits(.system());

        var config = ForwarderConfiguration{
            .version = 1,
            .protocols = try self.arena.dupe(ForwardProtocol, &.{ .tcp, .udp }),
            .listen = .{ .host = "*", .port = 0 },
            .upstream = .{ .host = "", .port = 0 },
            .limits = .{
                .tcp_listen_backlog = auto_limits.tcp_listen_backlog,
                .max_tcp_buffered_bytes = auto_limits.max_tcp_buffered_bytes,
                .max_udp_associations = auto_limits.max_udp_associations,
                .max_udp_pending_datagrams = auto_limits.max_udp_pending_datagrams,
                .max_udp_pending_bytes = auto_limits.max_udp_pending_bytes,
            },
        };

        if (mappingGet(map, "version")) |v| {
            config.version = try self.decodeInt(v, "version");
        }
        if (mappingGet(map, "protocols")) |v| {
            config.protocols = try self.decodeProtocols(v);
        }

        const listen_value = mappingGet(map, "listen") orelse
            return self.fail("missing required key: listen", .{});
        config.listen = try self.decodeListen(listen_value);

        const upstream_value = mappingGet(map, "upstream") orelse
            return self.fail("missing required key: upstream", .{});
        config.upstream = try self.decodeUpstream(upstream_value, config.listen.port);

        if (mappingGet(map, "timeouts")) |v| {
            config.timeouts = try self.decodeTimeouts(v);
        }
        if (mappingGet(map, "limits")) |v| {
            config.limits = try self.decodeLimits(v, auto_limits);
        }
        if (mappingGet(map, "logging")) |v| {
            config.logging = try self.decodeLogging(v);
        }
        if (mappingGet(map, "runtime")) |v| {
            config.runtime = try self.decodeRuntime(v);
        }
        if (mappingGet(map, "performance")) |v| {
            config.performance = try self.decodePerformance(v);
        }
        return config;
    }

    fn requireMapping(self: *Decoder, value: *Value, path: []const u8) LoadError![]Entry {
        if (value.* != .mapping) {
            return self.fail("{s}: expected a mapping", .{path});
        }
        return value.mapping;
    }

    fn decodeInt(self: *Decoder, value: *Value, path: []const u8) LoadError!i64 {
        if (value.* == .scalar and !value.scalar.quoted) {
            if (std.fmt.parseInt(i64, value.scalar.text, 10)) |v| {
                return v;
            } else |_| {}
        }
        return self.fail("{s}: expected an integer", .{path});
    }

    fn decodeBool(self: *Decoder, value: *Value, path: []const u8) LoadError!bool {
        if (value.* == .scalar and !value.scalar.quoted) {
            if (std.mem.eql(u8, value.scalar.text, "true")) return true;
            if (std.mem.eql(u8, value.scalar.text, "false")) return false;
        }
        return self.fail("{s}: expected a boolean", .{path});
    }

    fn decodeString(self: *Decoder, value: *Value, path: []const u8) LoadError![]const u8 {
        if (value.* == .scalar) return value.scalar.text;
        return self.fail("{s}: expected a string", .{path});
    }

    /// Decode an integer field that also accepts the string "auto".
    /// Returns the value and whether it is auto-tuned (absent counts as auto).
    fn decodeAutoTunedInt(self: *Decoder, map: []const Entry, key: []const u8, path: []const u8, default: i64) LoadError!struct { value: i64, is_auto: bool } {
        const value = mappingGet(map, key) orelse return .{ .value = default, .is_auto = true };
        if (value.* == .scalar) {
            if (!value.scalar.quoted) {
                if (std.fmt.parseInt(i64, value.scalar.text, 10)) |v| {
                    return .{ .value = v, .is_auto = false };
                } else |_| {}
            }
            var buf: [8]u8 = undefined;
            const text = value.scalar.text;
            if (text.len <= buf.len) {
                if (std.mem.eql(u8, "auto", std.ascii.lowerString(&buf, text))) {
                    return .{ .value = default, .is_auto = true };
                }
            }
        }
        return self.fail("{s}: expected an integer or auto", .{path});
    }

    fn decodeProtocols(self: *Decoder, value: *Value) LoadError![]ForwardProtocol {
        if (value.* != .sequence) {
            return self.fail("protocols: expected a sequence", .{});
        }
        var protocols: std.ArrayList(ForwardProtocol) = .empty;
        for (value.sequence) |item| {
            if (item.* != .scalar) {
                return self.fail("protocols: expected a sequence of tcp/udp", .{});
            }
            const text = item.scalar.text;
            if (std.mem.eql(u8, text, "tcp")) {
                try protocols.append(self.arena, .tcp);
            } else if (std.mem.eql(u8, text, "udp")) {
                try protocols.append(self.arena, .udp);
            } else {
                return self.fail("protocols: unknown protocol '{s}'", .{text});
            }
        }
        return protocols.toOwnedSlice(self.arena);
    }

    fn decodeSockmapMode(self: *Decoder, value: *Value, path: []const u8) LoadError!SockmapAccelerationMode {
        const text = try self.decodeString(value, path);
        const map = std.StaticStringMap(SockmapAccelerationMode).initComptime(.{
            .{ "auto", .auto },
            .{ "enabled", .enabled },
            .{ "disabled", .disabled },
        });
        return map.get(text) orelse
            self.fail("{s}: expected one of auto, enabled, disabled", .{path});
    }

    fn decodeListen(self: *Decoder, value: *Value) LoadError!EndpointConfiguration {
        const map = try self.requireMapping(value, "listen");
        var endpoint = EndpointConfiguration{ .host = "*", .port = 0 };
        if (mappingGet(map, "host")) |v| {
            endpoint.host = try self.decodeString(v, "listen.host");
        }
        const port_value = mappingGet(map, "port") orelse
            return self.fail("missing required key: listen.port", .{});
        endpoint.port = try self.decodeInt(port_value, "listen.port");
        return endpoint;
    }

    fn decodeUpstream(self: *Decoder, value: *Value, listen_port: i64) LoadError!EndpointConfiguration {
        const map = try self.requireMapping(value, "upstream");
        const host_value = mappingGet(map, "host") orelse
            return self.fail("missing required key: upstream.host", .{});
        const host = try self.decodeString(host_value, "upstream.host");
        var port = listen_port;
        if (mappingGet(map, "port")) |v| {
            port = try self.decodeInt(v, "upstream.port");
        }
        return .{ .host = host, .port = port };
    }

    fn decodeTimeouts(self: *Decoder, value: *Value) LoadError!TimeoutConfiguration {
        const map = try self.requireMapping(value, "timeouts");
        var timeouts = TimeoutConfiguration{};
        if (mappingGet(map, "connectSeconds")) |v| {
            timeouts.connect_seconds = try self.decodeInt(v, "timeouts.connectSeconds");
        }
        if (mappingGet(map, "tcpIdleSeconds")) |v| {
            timeouts.tcp_idle_seconds = try self.decodeInt(v, "timeouts.tcpIdleSeconds");
        }
        if (mappingGet(map, "udpSessionSeconds")) |v| {
            timeouts.udp_session_seconds = try self.decodeInt(v, "timeouts.udpSessionSeconds");
        }
        if (mappingGet(map, "shutdownGraceSeconds")) |v| {
            timeouts.shutdown_grace_seconds = try self.decodeInt(v, "timeouts.shutdownGraceSeconds");
        }
        return timeouts;
    }

    fn decodeLimits(self: *Decoder, value: *Value, auto_limits: autotune.AutoTunedLimits) LoadError!LimitConfiguration {
        const map = try self.requireMapping(value, "limits");
        const backlog = try self.decodeAutoTunedInt(map, "tcpListenBacklog", "limits.tcpListenBacklog", auto_limits.tcp_listen_backlog);
        const tcp_bytes = try self.decodeAutoTunedInt(map, "maxTCPBufferedBytes", "limits.maxTCPBufferedBytes", auto_limits.max_tcp_buffered_bytes);
        const udp_associations = try self.decodeAutoTunedInt(map, "maxUDPAssociations", "limits.maxUDPAssociations", auto_limits.max_udp_associations);
        const pending_datagrams = try self.decodeAutoTunedInt(map, "maxUDPPendingDatagrams", "limits.maxUDPPendingDatagrams", auto_limits.max_udp_pending_datagrams);
        const pending_bytes = try self.decodeAutoTunedInt(map, "maxUDPPendingBytes", "limits.maxUDPPendingBytes", auto_limits.max_udp_pending_bytes);
        return .{
            .tcp_listen_backlog = backlog.value,
            .max_tcp_buffered_bytes = tcp_bytes.value,
            .max_udp_associations = udp_associations.value,
            .max_udp_pending_datagrams = pending_datagrams.value,
            .max_udp_pending_bytes = pending_bytes.value,
            .auto_tuning = .{
                .tcp_listen_backlog = backlog.is_auto,
                .max_tcp_buffered_bytes = tcp_bytes.is_auto,
                .max_udp_associations = udp_associations.is_auto,
                .max_udp_pending_datagrams = pending_datagrams.is_auto,
                .max_udp_pending_bytes = pending_bytes.is_auto,
            },
        };
    }

    fn decodeLogging(self: *Decoder, value: *Value) LoadError!LogConfiguration {
        const map = try self.requireMapping(value, "logging");
        var logging = LogConfiguration{};
        if (mappingGet(map, "level")) |v| {
            logging.level = try self.decodeString(v, "logging.level");
        }
        return logging;
    }

    fn decodeRuntime(self: *Decoder, value: *Value) LoadError!RuntimeOptions {
        const map = try self.requireMapping(value, "runtime");
        var runtime = RuntimeOptions{};
        const workers = try self.decodeAutoTunedInt(map, "workerThreads", "runtime.workerThreads", 0);
        runtime.worker_threads = workers.value;
        if (mappingGet(map, "tuningDaemon")) |v| {
            runtime.tuning_daemon = try self.decodeBool(v, "runtime.tuningDaemon");
        }
        if (mappingGet(map, "tuningIntervalSeconds")) |v| {
            runtime.tuning_interval_seconds = try self.decodeInt(v, "runtime.tuningIntervalSeconds");
        }
        return runtime;
    }

    fn decodePerformance(self: *Decoder, value: *Value) LoadError!PerformanceConfiguration {
        const map = try self.requireMapping(value, "performance");
        var performance = PerformanceConfiguration{};
        if (mappingGet(map, "tcpSockmapAcceleration")) |v| {
            performance.tcp_sockmap_acceleration = try self.decodeSockmapMode(v, "performance.tcpSockmapAcceleration");
        }
        if (mappingGet(map, "udpSockmapAcceleration")) |v| {
            performance.udp_sockmap_acceleration = try self.decodeSockmapMode(v, "performance.udpSockmapAcceleration");
        }
        if (mappingGet(map, "udpSocketBufferBytes")) |v| {
            performance.udp_socket_buffer_bytes = try self.decodeInt(v, "performance.udpSocketBufferBytes");
        }
        const io_threads = try self.decodeAutoTunedInt(map, "udpIOThreads", "performance.udpIOThreads", 0);
        performance.udp_io_threads = io_threads.value;
        return performance;
    }
};

fn mappingGet(map: []const Entry, key: []const u8) ?*Value {
    for (map) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry.value;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Validation (mirrors ConfigurationLoader.validate, same order and messages)
// ---------------------------------------------------------------------------

const max_timeout_seconds: i64 = std.math.maxInt(i64) / 1_000_000_000; // 9223372036
const max_udp_associations: i64 = std.math.maxInt(u32) / 2; // 2147483647
const max_udp_socket_buffer_bytes: i64 = 1 << 28; // 268435456

fn validate(gpa: Allocator, diag: *Diagnostics, config: ForwarderConfiguration) LoadError!void {
    if (config.version != 1) {
        setDiag(gpa, diag, "unsupported configuration version: {d}", .{config.version});
        return error.InvalidConfiguration;
    }
    if (config.protocols.len == 0) {
        setDiag(gpa, diag, "protocols must not be empty", .{});
        return error.InvalidConfiguration;
    }
    for (config.protocols, 0..) |protocol, i| {
        for (config.protocols[i + 1 ..]) |other| {
            if (protocol == other) {
                setDiag(gpa, diag, "protocols must not contain duplicates", .{});
                return error.InvalidConfiguration;
            }
        }
    }
    if (std.mem.trim(u8, config.listen.host, " \t\n\r").len == 0) {
        setDiag(gpa, diag, "listen.host must not be empty", .{});
        return error.InvalidConfiguration;
    }
    if (std.mem.trim(u8, config.upstream.host, " \t\n\r").len == 0) {
        setDiag(gpa, diag, "upstream.host must not be empty", .{});
        return error.InvalidConfiguration;
    }
    if (config.listen.port < 1 or config.listen.port > 65_535) {
        setDiag(gpa, diag, "listen.port must be between 1 and 65535", .{});
        return error.InvalidConfiguration;
    }
    if (config.upstream.port < 1 or config.upstream.port > 65_535) {
        setDiag(gpa, diag, "upstream.port must be between 1 and 65535", .{});
        return error.InvalidConfiguration;
    }
    const timeout_values = [_]i64{
        config.timeouts.connect_seconds,
        config.timeouts.tcp_idle_seconds,
        config.timeouts.udp_session_seconds,
        config.timeouts.shutdown_grace_seconds,
    };
    for (timeout_values) |value| {
        if (value <= 0) {
            setDiag(gpa, diag, "all timeout values must be positive", .{});
            return error.InvalidConfiguration;
        }
    }
    for (timeout_values) |value| {
        if (value > max_timeout_seconds) {
            setDiag(gpa, diag, "all timeout values must be no greater than {d} seconds", .{max_timeout_seconds});
            return error.InvalidConfiguration;
        }
    }
    if (config.limits.tcp_listen_backlog < 1 or config.limits.tcp_listen_backlog > std.math.maxInt(i32)) {
        setDiag(gpa, diag, "limits.tcpListenBacklog must be between 1 and {d}", .{std.math.maxInt(i32)});
        return error.InvalidConfiguration;
    }
    if (config.limits.max_tcp_buffered_bytes <= 0) {
        setDiag(gpa, diag, "limits.maxTCPBufferedBytes must be positive", .{});
        return error.InvalidConfiguration;
    }
    if (config.limits.max_udp_associations < 1 or config.limits.max_udp_associations > max_udp_associations) {
        setDiag(gpa, diag, "limits.maxUDPAssociations must be between 1 and {d}", .{max_udp_associations});
        return error.InvalidConfiguration;
    }
    if (config.limits.max_udp_pending_datagrams <= 0) {
        setDiag(gpa, diag, "limits.maxUDPPendingDatagrams must be positive", .{});
        return error.InvalidConfiguration;
    }
    if (config.limits.max_udp_pending_bytes <= 0) {
        setDiag(gpa, diag, "limits.maxUDPPendingBytes must be positive", .{});
        return error.InvalidConfiguration;
    }
    if (config.runtime.worker_threads < 0) {
        setDiag(gpa, diag, "runtime.workerThreads must be zero for auto or positive", .{});
        return error.InvalidConfiguration;
    }
    if (config.runtime.tuning_interval_seconds <= 0) {
        setDiag(gpa, diag, "runtime.tuningIntervalSeconds must be positive", .{});
        return error.InvalidConfiguration;
    }
    if (config.performance.udp_socket_buffer_bytes < 0 or
        config.performance.udp_socket_buffer_bytes > max_udp_socket_buffer_bytes)
    {
        setDiag(gpa, diag, "performance.udpSocketBufferBytes must be between 0 (kernel default) and {d}", .{max_udp_socket_buffer_bytes});
        return error.InvalidConfiguration;
    }
    if (config.performance.udp_io_threads < 0) {
        setDiag(gpa, diag, "performance.udpIOThreads must be zero for auto or positive", .{});
        return error.InvalidConfiguration;
    }
    if (!isValidLogLevel(config.logging.level)) {
        setDiag(gpa, diag, "logging.level is invalid", .{});
        return error.InvalidConfiguration;
    }
}

fn isValidLogLevel(level: []const u8) bool {
    var buf: [16]u8 = undefined;
    if (level.len > buf.len) return false;
    const lower = std.ascii.lowerString(&buf, level);
    const valid = [_][]const u8{ "trace", "debug", "info", "notice", "warning", "error", "critical" };
    for (valid) |name| {
        if (std.mem.eql(u8, name, lower)) return true;
    }
    return false;
}

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
// ResolvedConfiguration (mirrors RuntimeSupport.ResolvedConfiguration)
// ---------------------------------------------------------------------------

pub const ResolveError = error{
    ResolutionFailed,
    OutOfMemory,
};

/// Maps a host name or IP literal plus port to a concrete SocketAddr.
/// Injectable for tests.
pub const Resolver = *const fn (host: []const u8, port: u16) anyerror!SocketAddr;

pub const ResolvedConfiguration = struct {
    configuration: ForwarderConfiguration,
    /// One or two addresses; "*" listens dual-stack wildcard 0.0.0.0 and ::.
    listen_addresses: []SocketAddr,
    upstream_address: SocketAddr,

    pub fn listenBindingDiffers(self: *const ResolvedConfiguration, other: *const ResolvedConfiguration) bool {
        if (self.listen_addresses.len != other.listen_addresses.len) return true;
        for (self.listen_addresses, other.listen_addresses) |a, b| {
            if (!a.eql(b)) return true;
        }
        return false;
    }

    pub fn shouldEnableTCPSockmap(self: *const ResolvedConfiguration) bool {
        return self.configuration.performance.tcp_sockmap_acceleration != .disabled;
    }

    pub fn shouldEnableUDPSockmap(self: *const ResolvedConfiguration) bool {
        return self.configuration.performance.udp_sockmap_acceleration != .disabled;
    }
};

/// Resolve listen/upstream endpoints to concrete socket addresses.
/// `gpa` backs the diagnostic message (freed by the caller, same convention
/// as loadFile/loadYaml); `alloc` backs `listen_addresses` and must outlive
/// the returned struct (pass the configuration arena).
pub fn resolveConfiguration(
    gpa: Allocator,
    alloc: Allocator,
    configuration: ForwarderConfiguration,
    resolver: ?Resolver,
    diag: *Diagnostics,
) ResolveError!ResolvedConfiguration {
    const resolve = resolver orelse defaultResolver;

    var listen_addresses: []SocketAddr = undefined;
    const listen_port: u16 = @intCast(configuration.listen.port);
    if (std.mem.eql(u8, configuration.listen.host, "*")) {
        const pair = try alloc.alloc(SocketAddr, 2);
        pair[0] = SocketAddr.initV4(.{ 0, 0, 0, 0 }, listen_port);
        pair[1] = SocketAddr.initV6(@splat(0), listen_port);
        listen_addresses = pair;
    } else {
        const address = resolverAddress(resolve, configuration.listen.host, listen_port, gpa, diag) catch
            return error.ResolutionFailed;
        const single = try alloc.alloc(SocketAddr, 1);
        single[0] = address;
        listen_addresses = single;
    }

    const upstream_port: u16 = @intCast(configuration.upstream.port);
    const upstream = resolverAddress(resolve, configuration.upstream.host, upstream_port, gpa, diag) catch
        return error.ResolutionFailed;

    return .{
        .configuration = configuration,
        .listen_addresses = listen_addresses,
        .upstream_address = upstream,
    };
}

fn resolverAddress(
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
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn loadForTest(text: []const u8) !LoadedConfiguration {
    var diag = Diagnostics{};
    return loadYaml(testing.allocator, text, &diag) catch |err| {
        if (diag.message) |message| {
            std.debug.print("unexpected load failure: {s}\n", .{message});
            testing.allocator.free(message);
        }
        return err;
    };
}

fn expectLoadFailure(text: []const u8, expected_message: ?[]const u8) !void {
    var diag = Diagnostics{};
    const result = loadYaml(testing.allocator, text, &diag);
    if (result) |loaded_value| {
        var loaded = loaded_value;
        loaded.deinit();
        return error.TestExpectedFailureButLoaded;
    } else |_| {}
    if (expected_message) |expected| {
        try testing.expectEqualStrings(expected, diag.message.?);
    }
    if (diag.message) |message| testing.allocator.free(message);
}

test "loads defaults" {
    var loaded = try loadForTest(
        \\listen:
        \\  port: 9000
        \\upstream:
        \\  host: "localhost"
        \\
    );
    defer loaded.deinit();
    const config = loaded.value;
    const auto_limits = autotune.limits(.system());

    try testing.expectEqual(1, config.version);
    try testing.expectEqualSlices(ForwardProtocol, &.{ .tcp, .udp }, config.protocols);
    try testing.expectEqualStrings("*", config.listen.host);
    try testing.expectEqual(9000, config.listen.port);
    try testing.expectEqualStrings("localhost", config.upstream.host);
    try testing.expectEqual(9000, config.upstream.port);
    try testing.expectEqual(5, config.timeouts.connect_seconds);
    try testing.expectEqual(300, config.timeouts.tcp_idle_seconds);
    try testing.expectEqual(60, config.timeouts.udp_session_seconds);
    try testing.expectEqual(10, config.timeouts.shutdown_grace_seconds);
    try testing.expectEqual(auto_limits.tcp_listen_backlog, config.limits.tcp_listen_backlog);
    try testing.expectEqual(auto_limits.max_tcp_buffered_bytes, config.limits.max_tcp_buffered_bytes);
    try testing.expectEqual(auto_limits.max_udp_associations, config.limits.max_udp_associations);
    try testing.expectEqual(auto_limits.max_udp_pending_datagrams, config.limits.max_udp_pending_datagrams);
    try testing.expectEqual(auto_limits.max_udp_pending_bytes, config.limits.max_udp_pending_bytes);
    try testing.expectEqual(0, config.runtime.worker_threads);
    try testing.expect(config.runtime.tuning_daemon);
    try testing.expectEqual(5, config.runtime.tuning_interval_seconds);
    try testing.expect(config.limits.auto_tuning.max_tcp_buffered_bytes);
    try testing.expectEqualStrings("info", config.logging.level);
    try testing.expectEqual(SockmapAccelerationMode.auto, config.performance.tcp_sockmap_acceleration);
    try testing.expectEqual(SockmapAccelerationMode.auto, config.performance.udp_sockmap_acceleration);
    try testing.expectEqual(PerformanceConfiguration.default_udp_socket_buffer_bytes, config.performance.udp_socket_buffer_bytes);
    try testing.expectEqual(0, config.performance.udp_io_threads);
}

test "loads overrides" {
    var loaded = try loadForTest(
        \\version: 1
        \\protocols: [udp]
        \\listen: { host: "::1", port: 5353 }
        \\upstream: { host: "2001:4860:4860::8888", port: 53 }
        \\timeouts:
        \\  connectSeconds: 2
        \\  tcpIdleSeconds: 20
        \\  udpSessionSeconds: 15
        \\  shutdownGraceSeconds: 3
        \\limits:
        \\  tcpListenBacklog: 2048
        \\  maxTCPBufferedBytes: 67108864
        \\  maxUDPAssociations: 128
        \\  maxUDPPendingDatagrams: 8
        \\  maxUDPPendingBytes: 4096
        \\runtime: { workerThreads: 2, tuningDaemon: false, tuningIntervalSeconds: 10 }
        \\performance: { tcpSockmapAcceleration: enabled, udpSockmapAcceleration: disabled, udpSocketBufferBytes: 8388608, udpIOThreads: 2 }
        \\logging: { level: debug }
        \\
    );
    defer loaded.deinit();
    const config = loaded.value;

    try testing.expectEqualSlices(ForwardProtocol, &.{.udp}, config.protocols);
    try testing.expectEqualStrings("::1", config.listen.host);
    try testing.expectEqual(5353, config.listen.port);
    try testing.expectEqualStrings("2001:4860:4860::8888", config.upstream.host);
    try testing.expectEqual(53, config.upstream.port);
    try testing.expectEqual(15, config.timeouts.udp_session_seconds);
    try testing.expectEqual(2, config.timeouts.connect_seconds);
    try testing.expectEqual(20, config.timeouts.tcp_idle_seconds);
    try testing.expectEqual(3, config.timeouts.shutdown_grace_seconds);
    try testing.expectEqual(2_048, config.limits.tcp_listen_backlog);
    try testing.expectEqual(64 * 1_024 * 1_024, config.limits.max_tcp_buffered_bytes);
    try testing.expectEqual(128, config.limits.max_udp_associations);
    try testing.expectEqual(8, config.limits.max_udp_pending_datagrams);
    try testing.expectEqual(4_096, config.limits.max_udp_pending_bytes);
    try testing.expectEqualStrings("debug", config.logging.level);
    try testing.expectEqual(2, config.runtime.worker_threads);
    try testing.expect(!config.runtime.tuning_daemon);
    try testing.expectEqual(10, config.runtime.tuning_interval_seconds);
    try testing.expect(!config.limits.auto_tuning.max_tcp_buffered_bytes);
    try testing.expect(config.limits.auto_tuning.tcp_listen_backlog == false);
    try testing.expectEqual(SockmapAccelerationMode.enabled, config.performance.tcp_sockmap_acceleration);
    try testing.expectEqual(SockmapAccelerationMode.disabled, config.performance.udp_sockmap_acceleration);
    try testing.expectEqual(8 * 1_024 * 1_024, config.performance.udp_socket_buffer_bytes);
    try testing.expectEqual(2, config.performance.udp_io_threads);
}

test "accepts explicit auto values" {
    var loaded = try loadForTest(
        \\listen: { port: 9000 }
        \\upstream: { host: "localhost", port: 9001 }
        \\runtime: { workerThreads: auto }
        \\limits:
        \\  tcpListenBacklog: auto
        \\  maxTCPBufferedBytes: auto
        \\  maxUDPAssociations: auto
        \\  maxUDPPendingDatagrams: auto
        \\  maxUDPPendingBytes: auto
        \\
    );
    defer loaded.deinit();
    const config = loaded.value;
    const auto_limits = autotune.limits(.system());

    try testing.expectEqual(0, config.runtime.worker_threads);
    try testing.expectEqual(auto_limits.tcp_listen_backlog, config.limits.tcp_listen_backlog);
    try testing.expectEqual(auto_limits.max_tcp_buffered_bytes, config.limits.max_tcp_buffered_bytes);
    try testing.expectEqual(auto_limits.max_udp_associations, config.limits.max_udp_associations);
    try testing.expectEqual(auto_limits.max_udp_pending_datagrams, config.limits.max_udp_pending_datagrams);
    try testing.expectEqual(auto_limits.max_udp_pending_bytes, config.limits.max_udp_pending_bytes);
    try testing.expect(config.limits.auto_tuning.tcp_listen_backlog);
    try testing.expect(config.limits.auto_tuning.max_udp_pending_bytes);
}

test "accepts block sequences and comments" {
    var loaded = try loadForTest(
        \\# leading comment
        \\protocols:
        \\  - tcp   # trailing comment
        \\  - udp
        \\listen:
        \\  port: 9000 # inline
        \\upstream:
        \\  host: "example.com"
        \\
    );
    defer loaded.deinit();
    try testing.expectEqualSlices(ForwardProtocol, &.{ .tcp, .udp }, loaded.value.protocols);
    try testing.expectEqual(9000, loaded.value.listen.port);
    try testing.expectEqual(9000, loaded.value.upstream.port);
}

test "rejects unknown keys with dotted paths" {
    try expectLoadFailure(
        \\version: 1
        \\protocols: [tcp]
        \\listen: { host: "127.0.0.1", port: 9000, typo: true }
        \\upstream: { host: "127.0.0.1", port: 9001 }
        \\
    , "unknown configuration key: listen.typo");

    try expectLoadFailure(
        \\version: 1
        \\protocols: [tcp]
        \\listen: { host: "127.0.0.1", port: 9000 }
        \\upstream: { host: "127.0.0.1", port: 9001 }
        \\performance: { sockmap: enabled }
        \\
    , "unknown configuration key: performance.sockmap");

    try expectLoadFailure(
        \\listen: { port: 9000 }
        \\upstream: { host: "127.0.0.1", port: 9001 }
        \\bogus: true
        \\
    , "unknown configuration key: bogus");
}

test "rejects duplicate protocols" {
    try expectLoadFailure(
        \\version: 1
        \\protocols: [tcp, tcp]
        \\listen: { host: "127.0.0.1", port: 9000 }
        \\upstream: { host: "127.0.0.1", port: 9001 }
        \\
    , "protocols must not contain duplicates");
}

test "rejects invalid ranges and log levels" {
    const prefix =
        \\version: 1
        \\protocols: [tcp]
        \\listen: { host: "127.0.0.1", port: 9000 }
        \\upstream: { host: "127.0.0.1", port: 9001 }
        \\
    ;
    const cases = [_]struct { yaml: []const u8, message: []const u8 }{
        .{ .yaml = "version: 2\nlisten: { port: 9000 }\nupstream: { host: \"a\", port: 1 }\n", .message = "unsupported configuration version: 2" },
        .{ .yaml = "version: 1\nprotocols: []\nlisten: { host: \"127.0.0.1\", port: 9000 }\nupstream: { host: \"127.0.0.1\", port: 9001 }\n", .message = "protocols must not be empty" },
        .{ .yaml = prefix ++ "limits: { tcpListenBacklog: 0 }\n", .message = "limits.tcpListenBacklog must be between 1 and 2147483647" },
        .{ .yaml = prefix ++ "limits: { maxTCPBufferedBytes: 0 }\n", .message = "limits.maxTCPBufferedBytes must be positive" },
        .{ .yaml = prefix ++ "limits: { maxUDPPendingDatagrams: 0 }\n", .message = "limits.maxUDPPendingDatagrams must be positive" },
        .{ .yaml = prefix ++ "limits: { maxUDPPendingBytes: 0 }\n", .message = "limits.maxUDPPendingBytes must be positive" },
        .{ .yaml = "version: 1\nlisten: { host: \"127.0.0.1\", port: 0 }\nupstream: { host: \"127.0.0.1\", port: 9001 }\n", .message = "listen.port must be between 1 and 65535" },
        .{ .yaml = prefix ++ "timeouts: { udpSessionSeconds: 0 }\n", .message = "all timeout values must be positive" },
        .{ .yaml = prefix ++ "timeouts: { tcpIdleSeconds: 9223372037 }\n", .message = "all timeout values must be no greater than 9223372036 seconds" },
        .{ .yaml = prefix ++ "logging: { level: verbose }\n", .message = "logging.level is invalid" },
        .{ .yaml = prefix ++ "runtime: { workerThreads: -1 }\n", .message = "runtime.workerThreads must be zero for auto or positive" },
        .{ .yaml = prefix ++ "runtime: { tuningIntervalSeconds: 0 }\n", .message = "runtime.tuningIntervalSeconds must be positive" },
        .{ .yaml = prefix ++ "performance: { tcpSockmapAcceleration: sometimes }\n", .message = "performance.tcpSockmapAcceleration: expected one of auto, enabled, disabled" },
        .{ .yaml = prefix ++ "limits: { maxUDPAssociations: 2147483648 }\n", .message = "limits.maxUDPAssociations must be between 1 and 2147483647" },
        .{ .yaml = prefix ++ "performance: { udpSockmapAcceleration: sometimes }\n", .message = "performance.udpSockmapAcceleration: expected one of auto, enabled, disabled" },
        .{ .yaml = prefix ++ "performance: { udpSocketBufferBytes: -1 }\n", .message = "performance.udpSocketBufferBytes must be between 0 (kernel default) and 268435456" },
        .{ .yaml = prefix ++ "performance: { udpSocketBufferBytes: 536870912 }\n", .message = "performance.udpSocketBufferBytes must be between 0 (kernel default) and 268435456" },
        .{ .yaml = prefix ++ "performance: { udpIOThreads: -1 }\n", .message = "performance.udpIOThreads must be zero for auto or positive" },
        .{ .yaml = prefix ++ "runtime: { workerThreads: forever }\n", .message = "runtime.workerThreads: expected an integer or auto" },
    };
    for (cases) |case| {
        try expectLoadFailure(case.yaml, case.message);
    }
}

test "rejects missing required keys and non-mapping root" {
    try expectLoadFailure("upstream: { host: \"a\" }\n", "missing required key: listen");
    try expectLoadFailure("listen: { host: \"a\" }\nupstream: { host: \"a\" }\n", "missing required key: listen.port");
    try expectLoadFailure("listen: { port: 9000 }\nupstream: { port: 9001 }\n", "missing required key: upstream.host");
    try expectLoadFailure("- tcp\n- udp\n", "YAML root must be a mapping");
}

fn resolveForTest(config: ForwarderConfiguration, resolver: ?Resolver) !ResolvedConfiguration {
    var diag = Diagnostics{};
    return resolveConfiguration(testing.allocator, testing.allocator, config, resolver, &diag) catch |err| {
        if (diag.message) |message| {
            std.debug.print("unexpected resolve failure: {s}\n", .{message});
            testing.allocator.free(message);
        }
        return err;
    };
}

fn makeTestConfiguration(upstream_host: []const u8) ForwarderConfiguration {
    return .{
        .version = 1,
        .protocols = @constCast(&[_]ForwardProtocol{.tcp}),
        .listen = .{ .host = "127.0.0.1", .port = 9000 },
        .upstream = .{ .host = upstream_host, .port = 9001 },
        .limits = .{
            .tcp_listen_backlog = 4_096,
            .max_tcp_buffered_bytes = 64 * 1_024 * 1_024,
            .max_udp_associations = 1_024,
            .max_udp_pending_datagrams = 64,
            .max_udp_pending_bytes = 256 * 1_024,
        },
    };
}

test "resolves IPv4, IPv6 and hostnames" {
    const ipv4 = try resolveForTest(makeTestConfiguration("127.0.0.1"), null);
    defer testing.allocator.free(ipv4.listen_addresses);
    try testing.expectEqual(@as(u16, 9001), ipv4.upstream_address.port);
    try testing.expectEqual(SocketAddr.Family.v4, ipv4.upstream_address.family);

    const ipv6 = try resolveForTest(makeTestConfiguration("::1"), null);
    defer testing.allocator.free(ipv6.listen_addresses);
    try testing.expectEqual(SocketAddr.Family.v6, ipv6.upstream_address.family);
    try testing.expectEqual(@as(u16, 9001), ipv6.upstream_address.port);

    const hostname = try resolveForTest(makeTestConfiguration("localhost"), null);
    defer testing.allocator.free(hostname.listen_addresses);
    try testing.expectEqual(@as(u16, 9001), hostname.upstream_address.port);
}

test "wildcard listen resolves to dual-stack wildcards" {
    var config = makeTestConfiguration("127.0.0.1");
    config.listen.host = "*";
    const resolved = try resolveForTest(config, null);
    defer testing.allocator.free(resolved.listen_addresses);
    try testing.expectEqual(@as(usize, 2), resolved.listen_addresses.len);
    try testing.expectEqual(SocketAddr.Family.v4, resolved.listen_addresses[0].family);
    try testing.expectEqual(SocketAddr.Family.v6, resolved.listen_addresses[1].family);
    try testing.expectEqual(@as(u16, 9000), resolved.listen_addresses[0].port);
    try testing.expect(std.mem.allEqual(u8, &resolved.listen_addresses[1].addr, 0));
}

fn loopbackResolver(host: []const u8, port: u16) anyerror!SocketAddr {
    _ = host;
    return SocketAddr.parseIp("127.0.0.1", port).?;
}

test "sockmap auto enables loopback and remote upstreams" {
    const ipv4 = try resolveForTest(makeTestConfiguration("127.42.0.1"), null);
    defer testing.allocator.free(ipv4.listen_addresses);
    try testing.expect(ipv4.shouldEnableTCPSockmap());

    const ipv6 = try resolveForTest(makeTestConfiguration("::1"), null);
    defer testing.allocator.free(ipv6.listen_addresses);
    try testing.expect(ipv6.shouldEnableTCPSockmap());

    const hostname = try resolveForTest(makeTestConfiguration("loopback.internal"), loopbackResolver);
    defer testing.allocator.free(hostname.listen_addresses);
    try testing.expect(hostname.shouldEnableTCPSockmap());

    const remote = try resolveForTest(makeTestConfiguration("192.0.2.1"), null);
    defer testing.allocator.free(remote.listen_addresses);
    try testing.expect(remote.shouldEnableTCPSockmap());
    try testing.expect(remote.shouldEnableUDPSockmap());
}

test "sockmap explicit modes override auto" {
    var enabled = makeTestConfiguration("127.0.0.1");
    enabled.performance.tcp_sockmap_acceleration = .enabled;
    const enabled_resolved = try resolveForTest(enabled, null);
    defer testing.allocator.free(enabled_resolved.listen_addresses);
    try testing.expect(enabled_resolved.shouldEnableTCPSockmap());

    var disabled = makeTestConfiguration("192.0.2.1");
    disabled.performance.tcp_sockmap_acceleration = .disabled;
    const disabled_resolved = try resolveForTest(disabled, null);
    defer testing.allocator.free(disabled_resolved.listen_addresses);
    try testing.expect(!disabled_resolved.shouldEnableTCPSockmap());

    var udp_enabled = makeTestConfiguration("127.0.0.1");
    udp_enabled.performance.udp_sockmap_acceleration = .enabled;
    const udp_enabled_resolved = try resolveForTest(udp_enabled, null);
    defer testing.allocator.free(udp_enabled_resolved.listen_addresses);
    try testing.expect(udp_enabled_resolved.shouldEnableUDPSockmap());

    var udp_disabled = makeTestConfiguration("192.0.2.1");
    udp_disabled.performance.udp_sockmap_acceleration = .disabled;
    const udp_disabled_resolved = try resolveForTest(udp_disabled, null);
    defer testing.allocator.free(udp_disabled_resolved.listen_addresses);
    try testing.expect(!udp_disabled_resolved.shouldEnableUDPSockmap());
}

fn hostBasedResolver(comptime listener_ip: []const u8) Resolver {
    return struct {
        fn resolve(host: []const u8, port: u16) anyerror!SocketAddr {
            const ip = if (std.mem.eql(u8, host, "upstream.internal")) "127.0.0.10" else listener_ip;
            return SocketAddr.parseIp(ip, port).?;
        }
    }.resolve;
}

test "detects listen hostname resolution change" {
    var config = makeTestConfiguration("upstream.internal");
    config.listen.host = "listener.internal";

    const original = try resolveForTest(config, hostBasedResolver("127.0.0.1"));
    defer testing.allocator.free(original.listen_addresses);
    const changed = try resolveForTest(config, hostBasedResolver("127.0.0.2"));
    defer testing.allocator.free(changed.listen_addresses);

    try testing.expect(original.listenBindingDiffers(&changed));
}

test "treats listen aliases for same address as same binding" {
    var original_config = makeTestConfiguration("upstream.internal");
    original_config.listen.host = "listener.internal";
    var alias_config = makeTestConfiguration("upstream.internal");
    alias_config.listen.host = "listener-alias.internal";

    const original = try resolveForTest(original_config, hostBasedResolver("127.0.0.1"));
    defer testing.allocator.free(original.listen_addresses);
    const alias = try resolveForTest(alias_config, hostBasedResolver("127.0.0.1"));
    defer testing.allocator.free(alias.listen_addresses);

    try testing.expect(!original.listenBindingDiffers(&alias));
}

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

test "config.example.yaml parses with expected values" {
    // Inline copy of ../config.example.yaml (keep in sync).
    var loaded = try loadForTest(
        \\listen:
        \\  port: 9000
        \\
        \\upstream:
        \\  host: "example.com"
        \\
        \\# Optional overrides. Omitted values are auto-tuned continuously at runtime.
        \\# version: 1
        \\# protocols: [tcp, udp]
        \\# listen:
        \\#   host: "*"
        \\#   port: 9000
        \\# upstream:
        \\#   host: "example.com"
        \\#   port: 9000
        \\# runtime:
        \\#   workerThreads: auto
        \\#   tuningDaemon: true
        \\#   tuningIntervalSeconds: 5
        \\# timeouts:
        \\#   connectSeconds: 5
        \\#   tcpIdleSeconds: 300
        \\#   udpSessionSeconds: 60
        \\#   shutdownGraceSeconds: 10
        \\# limits:
        \\#   tcpListenBacklog: auto
        \\#   maxTCPBufferedBytes: auto
        \\#   maxUDPAssociations: auto
        \\#   maxUDPPendingDatagrams: auto   # legacy: unused by the batched UDP transport
        \\#   maxUDPPendingBytes: auto       # legacy: unused by the batched UDP transport
        \\# performance:
        \\#   tcpSockmapAcceleration: auto
        \\#   udpSockmapAcceleration: auto
        \\#   udpSocketBufferBytes: 4194304   # 0 keeps kernel defaults; clamped to
        \\#                                   # net.core.rmem_max/wmem_max without CAP_NET_ADMIN
        \\#   udpIOThreads: auto              # UDP relay threads; auto = worker count
        \\# logging:
        \\#   level: info
        \\
    );
    defer loaded.deinit();
    try testing.expectEqual(9000, loaded.value.listen.port);
    try testing.expectEqualStrings("example.com", loaded.value.upstream.host);
    try testing.expectEqual(9000, loaded.value.upstream.port);
}
