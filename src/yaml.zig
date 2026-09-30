//! YAML-subset parser and scalar decoding helpers.
//!
//! The parser supports exactly what config.example.yaml needs: nested block
//! mappings by indentation, flow mappings `{ a: b }`, block and flow
//! sequences, bare and double-quoted scalars, and `#` comments (full-line
//! and trailing, never inside quoted strings). This layer is pure mechanism:
//! it produces a Value tree and decodes scalars; every semantic decision
//! (which keys exist, what they mean) belongs to the modules.

const std = @import("std");
const net = @import("net.zig");

const Allocator = std.mem.Allocator;

pub const Diagnostics = net.Diagnostics;
pub const setDiag = net.setDiag;

pub const LoadError = error{
    InvalidConfiguration,
    ReadFailed,
    OutOfMemory,
};

pub const Scalar = struct {
    text: []const u8,
    /// True when the scalar was double-quoted; quoted scalars never decode as
    /// ints or bools, matching YAML semantics.
    quoted: bool,
};

pub const Entry = struct {
    key: []const u8,
    value: *Value,
};

pub const Value = union(enum) {
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

/// Read an entire file (capped at max_bytes) into gpa-owned memory.
pub fn readFileAlloc(gpa: Allocator, path: []const u8, max_bytes: usize) ![]u8 {
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

/// Parse YAML text into a Value tree allocated from `arena`. The root of a
/// valid document is a mapping; callers check that themselves.
pub fn parse(arena: Allocator, gpa: Allocator, text: []const u8, diag: *Diagnostics) LoadError!*Value {
    var parser = Parser{
        .arena = arena,
        .gpa = gpa,
        .diag = diag,
        .lines = try splitLines(arena, gpa, text, diag),
    };
    return parser.parseDocument();
}

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
            self.index += 1;
            try self.parseMappingEntry(&entries, line.content, line.number, indent);
        }
        return self.newValue(.{ .mapping = try entries.toOwnedSlice(self.arena) });
    }

    /// Parse one 'key: value' entry (content has no leading dash) into the
    /// entry list; nested blocks are consumed from following lines.
    fn parseMappingEntry(self: *Parser, entries: *std.ArrayList(Entry), content: []const u8, number: usize, indent: usize) error{ InvalidConfiguration, OutOfMemory }!void {
        const colon = findMappingColon(content) orelse
            return self.fail(number, "expected a 'key: value' mapping entry", .{});
        const key = try self.parseKey(content[0..colon], number);
        const rest = std.mem.trimStart(u8, content[colon + 1 ..], " ");

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
            value = try self.parseInlineValue(rest, number);
        }
        try entries.append(self.arena, .{ .key = key, .value = value });
    }

    /// A sequence item that directly starts a mapping (`- key: value`): the
    /// first entry comes from the dash line itself, following entries align
    /// at the column where the first key started.
    fn parseInlineMapping(self: *Parser, content: []const u8, number: usize, indent: usize) error{ InvalidConfiguration, OutOfMemory }!*Value {
        var entries: std.ArrayList(Entry) = .empty;
        try self.parseMappingEntry(&entries, content, number, indent);
        while (self.index < self.lines.len) {
            const line = self.lines[self.index];
            if (line.indent != indent or isSequenceItem(line.content)) break;
            self.index += 1;
            try self.parseMappingEntry(&entries, line.content, line.number, indent);
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
            } else if (rest[0] != '{' and rest[0] != '[' and rest[0] != '"' and
                findMappingColon(rest) != null)
            {
                // `- key: value`: the item is a mapping whose first entry is
                // inline; following keys align at the key's column.
                value = try self.parseInlineMapping(rest, line.number, indent + (line.content.len - rest.len));
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
// Decoding helpers: map Value nodes onto typed scalars
// ---------------------------------------------------------------------------

pub fn mappingGet(map: []const Entry, key: []const u8) ?*Value {
    for (map) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry.value;
    }
    return null;
}

pub fn keyKnown(known_keys: []const []const u8, key: []const u8) bool {
    for (known_keys) |candidate| {
        if (std.mem.eql(u8, candidate, key)) return true;
    }
    return false;
}

pub fn fail(gpa: Allocator, diag: *Diagnostics, comptime fmt: []const u8, args: anytype) error{InvalidConfiguration} {
    setDiag(gpa, diag, fmt, args);
    return error.InvalidConfiguration;
}

/// Reject unknown keys inside a nested mapping. `path` is the dotted prefix
/// shown in diagnostics ("" for the document root).
pub fn checkKeys(gpa: Allocator, diag: *Diagnostics, mapping: []const Entry, known_keys: []const []const u8, path: []const u8) LoadError!void {
    for (mapping) |entry| {
        if (!keyKnown(known_keys, entry.key)) {
            if (path.len == 0) {
                setDiag(gpa, diag, "unknown configuration key: {s}", .{entry.key});
            } else {
                setDiag(gpa, diag, "unknown configuration key: {s}.{s}", .{ path, entry.key });
            }
            return error.InvalidConfiguration;
        }
    }
}

pub fn requireMapping(gpa: Allocator, diag: *Diagnostics, value: *Value, path: []const u8) LoadError![]Entry {
    if (value.* != .mapping) {
        return fail(gpa, diag, "{s}: expected a mapping", .{path});
    }
    return value.mapping;
}

pub fn decodeInt(gpa: Allocator, diag: *Diagnostics, value: *Value, path: []const u8) LoadError!i64 {
    if (value.* == .scalar and !value.scalar.quoted) {
        if (std.fmt.parseInt(i64, value.scalar.text, 10)) |v| {
            return v;
        } else |_| {}
    }
    return fail(gpa, diag, "{s}: expected an integer", .{path});
}

pub fn decodeBool(gpa: Allocator, diag: *Diagnostics, value: *Value, path: []const u8) LoadError!bool {
    if (value.* == .scalar and !value.scalar.quoted) {
        if (std.mem.eql(u8, value.scalar.text, "true")) return true;
        if (std.mem.eql(u8, value.scalar.text, "false")) return false;
    }
    return fail(gpa, diag, "{s}: expected a boolean", .{path});
}

pub fn decodeString(gpa: Allocator, diag: *Diagnostics, value: *Value, path: []const u8) LoadError![]const u8 {
    if (value.* == .scalar) return value.scalar.text;
    return fail(gpa, diag, "{s}: expected a string", .{path});
}
