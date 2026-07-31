//! Pure Zig eBPF and Linux syscall support: raw bpf() syscall
//! wrappers, sockhash map runtimes with cookie pairing and activity
//! timestamps, the TCP sockmap loader (stream parser + verdict), the UDP
//! verdict-only loader (BPF_SK_SKB_VERDICT, kernel >= 5.12), the
//! SO_ATTACH_REUSEPORT_EBPF program loader, the kprobe-based BPF observer,
//! batched UDP I/O (recvmmsg/sendmmsg), and the epoll/eventfd/UDP socket
//! primitives the relay engines use.
//!
//! Linux-only, no external dependencies. Every eBPF loader fails with an
//! error when privileges or kernel support are missing; callers fall back
//! to userspace paths. Nothing here may crash on loader failure.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const BPF = linux.BPF;
const Insn = BPF.Insn;

pub const fd_t = linux.fd_t;
pub const socklen_t = linux.socklen_t;

/// Errors surfaced by this module. The concrete errno that produced an
/// error is available in `lastErrno` (thread-local) right after the call.
pub const Error = error{
    AccessDenied,
    AddressInUse,
    BadFileDescriptor,
    Fault,
    Interrupted,
    Invalid,
    NoEntry,
    NoMemory,
    NotSupported,
    PermissionDenied,
    TableFull,
    Unexpected,
};

/// Errno of the most recent failed syscall on this thread. Mirrors the
/// errno-based diagnostics of the C implementation for log messages.
pub threadlocal var lastErrno: linux.E = .SUCCESS;

fn errnoError(e: linux.E) Error {
    lastErrno = e;
    return switch (e) {
        .ACCES => error.AccessDenied,
        .ADDRINUSE => error.AddressInUse,
        .BADF => error.BadFileDescriptor,
        .FAULT => error.Fault,
        .INTR => error.Interrupted,
        .INVAL => error.Invalid,
        .NOENT => error.NoEntry,
        .NOMEM => error.NoMemory,
        .OPNOTSUPP, .NOSYS => error.NotSupported,
        .PERM => error.PermissionDenied,
        .@"2BIG" => error.TableFull,
        else => error.Unexpected,
    };
}

fn sys(rc: usize) Error!usize {
    const e = linux.errno(rc);
    if (e != .SUCCESS) return errnoError(e);
    return rc;
}

fn sysFd(rc: usize) Error!fd_t {
    return @intCast(try sys(rc));
}

// ---------------------------------------------------------------------------
// Raw bpf() syscall wrappers
// ---------------------------------------------------------------------------

fn bpfCall(cmd: BPF.Cmd, attr: *BPF.Attr) usize {
    return linux.bpf(cmd, attr, @sizeOf(BPF.Attr));
}

fn copyObjectName(dest: *[16]u8, name: []const u8) void {
    const length = @min(name.len, dest.len - 1);
    @memcpy(dest[0..length], name[0..length]);
}

fn createMap(
    map_type: BPF.MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    name: []const u8,
) Error!fd_t {
    var attr: BPF.Attr = std.mem.zeroes(BPF.Attr);
    attr.map_create.map_type = @intFromEnum(map_type);
    attr.map_create.key_size = key_size;
    attr.map_create.value_size = value_size;
    attr.map_create.max_entries = max_entries;
    copyObjectName(&attr.map_create.map_name, name);
    return sysFd(bpfCall(.map_create, &attr));
}

fn mapUpdate(map_fd: fd_t, key: *const anyopaque, value: *const anyopaque) Error!void {
    var attr: BPF.Attr = std.mem.zeroes(BPF.Attr);
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key);
    attr.map_elem.result.value = @intFromPtr(value);
    attr.map_elem.flags = BPF.ANY;
    _ = try sys(bpfCall(.map_update_elem, &attr));
}

fn mapLookup(map_fd: fd_t, key: *const anyopaque, value: *anyopaque) Error!void {
    var attr: BPF.Attr = std.mem.zeroes(BPF.Attr);
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key);
    attr.map_elem.result.value = @intFromPtr(value);
    _ = try sys(bpfCall(.map_lookup_elem, &attr));
}

fn mapDelete(map_fd: fd_t, key: *const anyopaque) void {
    var attr: BPF.Attr = std.mem.zeroes(BPF.Attr);
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key);
    _ = bpfCall(.map_delete_elem, &attr);
}

fn progAttach(target_fd: fd_t, program_fd: fd_t, attach_type: BPF.AttachType) Error!void {
    var attr: BPF.Attr = std.mem.zeroes(BPF.Attr);
    attr.prog_attach.target_fd = target_fd;
    attr.prog_attach.attach_bpf_fd = program_fd;
    attr.prog_attach.attach_type = @intFromEnum(attach_type);
    _ = try sys(bpfCall(.prog_attach, &attr));
}

fn progDetach(target_fd: fd_t, program_fd: fd_t, attach_type: BPF.AttachType) void {
    var attr: BPF.Attr = std.mem.zeroes(BPF.Attr);
    attr.prog_attach.target_fd = target_fd;
    attr.prog_attach.attach_bpf_fd = program_fd;
    attr.prog_attach.attach_type = @intFromEnum(attach_type);
    _ = bpfCall(.prog_detach, &attr);
}

/// Loads a GPL-licensed eBPF program, capturing the verifier log into the
/// caller-provided buffer (NUL-terminated, empty on entry when provided).
fn loadProgram(
    prog_type: BPF.ProgType,
    expected_attach_type: ?BPF.AttachType,
    program_name: []const u8,
    insns: []const Insn,
    verifier_log: ?[]u8,
) Error!fd_t {
    const license = "GPL";

    var attr: BPF.Attr = std.mem.zeroes(BPF.Attr);
    attr.prog_load.prog_type = @intFromEnum(prog_type);
    attr.prog_load.insn_cnt = @intCast(insns.len);
    attr.prog_load.insns = @intFromPtr(insns.ptr);
    attr.prog_load.license = @intFromPtr(license.ptr);
    if (expected_attach_type) |attach_type| {
        attr.prog_load.expected_attach_type = @intFromEnum(attach_type);
    }
    copyObjectName(&attr.prog_load.prog_name, program_name);
    if (verifier_log) |log| {
        if (log.len > 0) {
            log[0] = 0;
            attr.prog_load.log_level = 1;
            attr.prog_load.log_buf = @intFromPtr(log.ptr);
            attr.prog_load.log_size = @intCast(@min(log.len, std.math.maxInt(u32)));
        }
    }
    return sysFd(bpfCall(.prog_load, &attr));
}

fn getSocketCookie(socket_fd: fd_t) Error!u64 {
    var cookie: u64 = 0;
    var cookie_length: socklen_t = @sizeOf(u64);
    _ = try sys(linux.getsockopt(
        socket_fd,
        linux.SOL.SOCKET,
        linux.SO.COOKIE,
        std.mem.asBytes(&cookie).ptr,
        &cookie_length,
    ));
    if (cookie_length != @sizeOf(u64) or cookie == 0) return errnoError(.INVAL);
    return cookie;
}

fn monotonicNowNs() Error!u64 {
    var now: linux.timespec = undefined;
    _ = try sys(linux.clock_gettime(.MONOTONIC, &now));
    return @as(u64, @intCast(now.sec)) * 1_000_000_000 + @as(u64, @intCast(now.nsec));
}

// ---------------------------------------------------------------------------
// Shared sockmap verdict program
// ---------------------------------------------------------------------------

const PeerState = extern struct {
    peer_cookie: u64,
    last_activity_ns: u64,
};

const sk_pass = 1;
const activity_refresh_ns = 10 * 1000 * 1000;

/// Fills `instructions` with the shared sockmap verdict program: look up
/// the peer by socket cookie, throttle-refresh activity, redirect to the
/// peer's transmit path; fall back to SK_PASS until pairing completes.
/// Returns the populated instruction count (at most 32).
fn fillVerdictInstructions(instructions: *[32]Insn, sockhash_fd: fd_t, peer_fd: fd_t) usize {
    const program = [_]Insn{
        // r6 = skb; cookie at fp-8
        Insn.mov(.r6, .r1),
        Insn.call(.get_socket_cookie),
        Insn.jeq(.r0, 0, 24),
        Insn.stx(.double_word, .r10, -8, .r0),

        // state = peer_map[cookie]; peer key at fp-16
        Insn.ld_map_fd1(.r1, peer_fd),
        Insn.ld_map_fd2(peer_fd),
        Insn.mov(.r2, .r10),
        Insn.add(.r2, -8),
        Insn.call(.map_lookup_elem),
        Insn.jeq(.r0, 0, 17),
        Insn.mov(.r8, .r0),
        Insn.ldx(.double_word, .r7, .r8, 0),
        Insn.stx(.double_word, .r10, -16, .r7),

        // Keep the peer cacheline read-mostly; refresh activity at most
        // every 10 ms.
        Insn.ldx(.double_word, .r9, .r8, @offsetOf(PeerState, "last_activity_ns")),
        Insn.call(.ktime_get_coarse_ns),
        Insn.mov(.r1, .r0),
        Insn.sub(.r1, .r9),
        Insn.jlt(.r1, activity_refresh_ns, 1),
        Insn.stx(.double_word, .r8, @offsetOf(PeerState, "last_activity_ns"), .r0),

        // Redirect this received stream to the peer socket's transmit path.
        Insn.mov(.r1, .r6),
        Insn.ld_map_fd1(.r2, sockhash_fd),
        Insn.ld_map_fd2(sockhash_fd),
        Insn.mov(.r3, .r10),
        Insn.add(.r3, -16),
        Insn.mov(.r4, 0),
        Insn.call(.sk_redirect_hash),
        Insn.exit(),

        // No complete pairing: retain the userspace relay fallback.
        Insn.mov(.r0, sk_pass),
        Insn.exit(),
    };
    @memcpy(instructions[0..program.len], &program);
    return program.len;
}

fn loadVerdictProgram(
    sockhash_fd: fd_t,
    peer_fd: fd_t,
    attach_type: BPF.AttachType,
    program_name: []const u8,
    verifier_log: ?[]u8,
) Error!fd_t {
    var instructions: [32]Insn = undefined;
    const count = fillVerdictInstructions(&instructions, sockhash_fd, peer_fd);
    return loadProgram(.sk_skb, attach_type, program_name, instructions[0..count], verifier_log);
}

fn loadSockmapParser(verifier_log: ?[]u8) Error!fd_t {
    // offsetof(struct __sk_buff, len) == 0
    const instructions = [_]Insn{
        Insn.ldx(.word, .r0, .r1, 0),
        Insn.exit(),
    };
    return loadProgram(.sk_skb, .sk_skb_stream_parser, "curtsy_parser", &instructions, verifier_log);
}

// ---------------------------------------------------------------------------
// SO_ATTACH_REUSEPORT_EBPF program
// ---------------------------------------------------------------------------

pub const so_attach_reuseport_ebpf: i32 = linux.SO.ATTACH_REUSEPORT_EBPF;

/// Loads the reuseport steering program: `skb->hash % socket_count`.
/// The returned fd is attached to listener sockets with
/// SO_ATTACH_REUSEPORT_EBPF. Fails with an error when lacking privileges
/// or kernel support; callers fall back to kernel-native reuseport hashing.
pub fn loadReusePortBpf(socket_count: u32, verifier_log: ?[]u8) Error!fd_t {
    if (socket_count == 0) return errnoError(.INVAL);

    // offsetof(struct __sk_buff, hash) == 68
    const instructions = [_]Insn{
        Insn.ldx(.word, .r0, .r1, 68),
        .{
            .code = BPF.ALU | BPF.MOD | BPF.K,
            .dst = 0,
            .src = 0,
            .off = 0,
            .imm = @bitCast(socket_count),
        },
        Insn.exit(),
    };
    return loadProgram(.socket_filter, null, "curtsy_reuse", &instructions, verifier_log);
}

// ---------------------------------------------------------------------------
// Sockmap runtime (TCP and UDP variants)
// ---------------------------------------------------------------------------

/// Owns the sockhash map, the peer-state map and the attached SK_SKB
/// programs used for kernel-level forwarding between paired sockets.
/// TCP pairs use a stream parser + stream verdict; UDP pairs use a
/// verdict-only program (BPF_SK_SKB_VERDICT, kernel >= 5.12).
pub const SockmapRuntime = struct {
    sockhash_fd: fd_t,
    peer_fd: fd_t,
    parser_fd: fd_t, // -1 for the UDP variant
    program_fd: fd_t,
    verdict_attach_type: BPF.AttachType,

    pub const Pairing = struct {
        client_cookie: u64,
        upstream_cookie: u64,
    };

    /// TCP variant: stream parser + stream verdict attached to the sockhash.
    /// Each proxied TCP connection consumes two map entries.
    pub fn createTcp(max_entries: u32, verifier_log: ?[]u8) Error!SockmapRuntime {
        return create(max_entries, false, verifier_log);
    }

    /// UDP variant: attaches only a BPF_SK_SKB_VERDICT program (no stream
    /// parser), which steers whole datagrams between paired connected UDP
    /// sockets. Requires kernel >= 5.12 for UDP verdict support.
    /// Each accelerated UDP association consumes two map entries.
    pub fn createUdp(max_entries: u32, verifier_log: ?[]u8) Error!SockmapRuntime {
        return create(max_entries, true, verifier_log);
    }

    fn create(max_entries: u32, for_udp: bool, verifier_log: ?[]u8) Error!SockmapRuntime {
        if (max_entries == 0) return errnoError(.INVAL);

        var runtime = SockmapRuntime{
            .sockhash_fd = -1,
            .peer_fd = -1,
            .parser_fd = -1,
            .program_fd = -1,
            .verdict_attach_type = if (for_udp) .sk_skb_verdict else .sk_skb_stream_verdict,
        };
        errdefer {
            const saved = lastErrno;
            runtime.destroy();
            lastErrno = saved;
        }

        runtime.sockhash_fd = try createMap(
            .sockhash,
            @sizeOf(u64),
            @sizeOf(u32),
            max_entries,
            if (for_udp) "curtsy_udpsocks" else "curtsy_socks",
        );
        runtime.peer_fd = try createMap(
            .hash,
            @sizeOf(u64),
            @sizeOf(PeerState),
            max_entries,
            if (for_udp) "curtsy_udppeer" else "curtsy_peers",
        );
        if (!for_udp) {
            runtime.parser_fd = try loadSockmapParser(verifier_log);
        }
        runtime.program_fd = try loadVerdictProgram(
            runtime.sockhash_fd,
            runtime.peer_fd,
            runtime.verdict_attach_type,
            if (for_udp) "curtsy_udp" else "curtsy_sockmap",
            verifier_log,
        );

        if (runtime.parser_fd >= 0) {
            try progAttach(runtime.sockhash_fd, runtime.parser_fd, .sk_skb_stream_parser);
        }
        try progAttach(runtime.sockhash_fd, runtime.program_fd, runtime.verdict_attach_type);
        return runtime;
    }

    pub fn destroy(self: *SockmapRuntime) void {
        if (self.program_fd >= 0 and self.sockhash_fd >= 0) {
            progDetach(self.sockhash_fd, self.program_fd, self.verdict_attach_type);
        }
        if (self.parser_fd >= 0 and self.sockhash_fd >= 0) {
            progDetach(self.sockhash_fd, self.parser_fd, .sk_skb_stream_parser);
        }
        if (self.program_fd >= 0) _ = linux.close(self.program_fd);
        if (self.parser_fd >= 0) _ = linux.close(self.parser_fd);
        if (self.peer_fd >= 0) _ = linux.close(self.peer_fd);
        if (self.sockhash_fd >= 0) _ = linux.close(self.sockhash_fd);
        self.* = .{
            .sockhash_fd = -1,
            .peer_fd = -1,
            .parser_fd = -1,
            .program_fd = -1,
            .verdict_attach_type = self.verdict_attach_type,
        };
    }

    /// Pairs a client socket with its upstream socket inside the kernel:
    /// both fds go into the sockhash keyed by socket cookie, and the peer
    /// map records the opposite cookie plus the initial activity timestamp.
    pub fn pair(self: *const SockmapRuntime, client_fd: fd_t, upstream_fd: fd_t) Error!Pairing {
        if (client_fd < 0 or upstream_fd < 0) return errnoError(.INVAL);

        const client_cookie = try getSocketCookie(client_fd);
        const upstream_cookie = try getSocketCookie(upstream_fd);
        if (client_cookie == upstream_cookie) return errnoError(.INVAL);

        const timestamp = try monotonicNowNs();
        const client_state = PeerState{
            .peer_cookie = upstream_cookie,
            .last_activity_ns = timestamp,
        };
        const upstream_state = PeerState{
            .peer_cookie = client_cookie,
            .last_activity_ns = timestamp,
        };
        const client_fd_value: u32 = @intCast(client_fd);
        const upstream_fd_value: u32 = @intCast(upstream_fd);

        mapUpdate(self.sockhash_fd, &client_cookie, &client_fd_value) catch |err| {
            return err;
        };
        mapUpdate(self.sockhash_fd, &upstream_cookie, &upstream_fd_value) catch |err| {
            self.unpair(client_cookie, upstream_cookie);
            return err;
        };
        mapUpdate(self.peer_fd, &client_cookie, &client_state) catch |err| {
            self.unpair(client_cookie, upstream_cookie);
            return err;
        };
        mapUpdate(self.peer_fd, &upstream_cookie, &upstream_state) catch |err| {
            self.unpair(client_cookie, upstream_cookie);
            return err;
        };
        return .{
            .client_cookie = client_cookie,
            .upstream_cookie = upstream_cookie,
        };
    }

    /// Removes both directions of a pairing. Redirection stops first;
    /// subsequent data falls through to the userspace relay.
    pub fn unpair(self: *const SockmapRuntime, client_cookie: u64, upstream_cookie: u64) void {
        mapDelete(self.peer_fd, &client_cookie);
        mapDelete(self.peer_fd, &upstream_cookie);
        mapDelete(self.sockhash_fd, &client_cookie);
        mapDelete(self.sockhash_fd, &upstream_cookie);
    }

    /// Remaining idle time in nanoseconds before `idle_timeout_ns` elapses
    /// since the latest activity recorded by the verdict program on either
    /// side of the pairing. Returns 0 when already expired.
    pub fn idleRemainingNs(
        self: *const SockmapRuntime,
        client_cookie: u64,
        upstream_cookie: u64,
        idle_timeout_ns: u64,
    ) Error!u64 {
        if (idle_timeout_ns == 0) return errnoError(.INVAL);
        var client_state: PeerState = undefined;
        var upstream_state: PeerState = undefined;
        try mapLookup(self.peer_fd, &client_cookie, &client_state);
        try mapLookup(self.peer_fd, &upstream_cookie, &upstream_state);
        const now_ns = try monotonicNowNs();
        const latest = @max(client_state.last_activity_ns, upstream_state.last_activity_ns);
        const elapsed = if (now_ns >= latest) now_ns - latest else 0;
        return if (elapsed >= idle_timeout_ns) 0 else idle_timeout_ns - elapsed;
    }
};

// ---------------------------------------------------------------------------
// BPF observer: per-process tcp/udp sendmsg/recvmsg kprobe counters
// ---------------------------------------------------------------------------

const observer_counter_count = 4;

pub const BpfObserver = struct {
    pub const Counters = struct {
        tcp_sendmsg: u64 = 0,
        tcp_recvmsg: u64 = 0,
        udp_sendmsg: u64 = 0,
        udp_recvmsg: u64 = 0,
    };

    counters_fd: fd_t,
    program_fds: [observer_counter_count]fd_t,
    event_fds: [observer_counter_count][]fd_t,

    const functions = [observer_counter_count][:0]const u8{
        "tcp_sendmsg",
        "tcp_recvmsg",
        "udp_sendmsg",
        "udp_recvmsg",
    };

    /// Loads one kprobe program per counter and attaches it to the
    /// matching kernel function on every online CPU, filtered to
    /// `target_pid`. Fails with an error when lacking privileges or
    /// kprobe/BPF support.
    pub fn create(target_pid: u32, verifier_log: ?[]u8) Error!BpfObserver {
        if (target_pid == 0) return errnoError(.INVAL);

        var observer = BpfObserver{
            .counters_fd = -1,
            .program_fds = .{ -1, -1, -1, -1 },
            .event_fds = .{ &.{}, &.{}, &.{}, &.{} },
        };
        errdefer {
            const saved = lastErrno;
            observer.destroy();
            lastErrno = saved;
        }

        observer.counters_fd = try createMap(
            .array,
            @sizeOf(u32),
            @sizeOf(u64),
            observer_counter_count,
            "curtsy_tune",
        );

        for (0..observer_counter_count) |i| {
            observer.program_fds[i] = try loadObserverProgram(
                observer.counters_fd,
                target_pid,
                @intCast(i),
                verifier_log,
            );
            observer.event_fds[i] = attachKprobe(observer.program_fds[i], functions[i]) catch |err| {
                // The verifier log still holds the successful load output,
                // which is noise at this point; report the failing stage.
                if (verifier_log) |log| {
                    if (log.len > 0) {
                        const text = std.fmt.bufPrint(log, "stage=kprobe_attach function={s}", .{functions[i]}) catch null;
                        if (text != null and log.len > 0) {
                            log[@min(text.?.len, log.len - 1)] = 0;
                        }
                    }
                }
                return err;
            };
        }
        return observer;
    }

    pub fn destroy(self: *BpfObserver) void {
        for (0..observer_counter_count) |i| {
            for (self.event_fds[i]) |fd| {
                _ = linux.close(fd);
            }
            if (self.event_fds[i].len > 0) std.heap.c_allocator.free(self.event_fds[i]);
            self.event_fds[i] = &.{};
            if (self.program_fds[i] >= 0) {
                _ = linux.close(self.program_fds[i]);
                self.program_fds[i] = -1;
            }
        }
        if (self.counters_fd >= 0) {
            _ = linux.close(self.counters_fd);
            self.counters_fd = -1;
        }
    }

    pub fn read(self: *const BpfObserver) Error!Counters {
        var values = [4]u64{ 0, 0, 0, 0 };
        for (0..observer_counter_count) |i| {
            const key: u32 = @intCast(i);
            try mapLookup(self.counters_fd, &key, &values[i]);
        }
        return .{
            .tcp_sendmsg = values[0],
            .tcp_recvmsg = values[1],
            .udp_sendmsg = values[2],
            .udp_recvmsg = values[3],
        };
    }
};

fn loadObserverProgram(
    counters_fd: fd_t,
    target_pid: u32,
    counter_index: u32,
    verifier_log: ?[]u8,
) Error!fd_t {
    const instructions = [_]Insn{
        // Ignore events not caused by this Curtsy process: jump straight to
        // the return-0 tail (instruction 14), not the counter increment.
        Insn.call(.get_current_pid_tgid),
        Insn.rsh(.r0, 32),
        Insn.jne(.r0, @as(i32, @bitCast(target_pid)), 11),

        // key = counter_index
        Insn.mov(.r6, .r10),
        Insn.add(.r6, -4),
        Insn.mov(.r1, @as(i32, @intCast(counter_index))),
        Insn.stx(.word, .r10, -4, .r1),

        // counter = counters[key]
        Insn.ld_map_fd1(.r1, counters_fd),
        Insn.ld_map_fd2(counters_fd),
        Insn.mov(.r2, .r6),
        Insn.call(.map_lookup_elem),
        Insn.jeq(.r0, 0, 2),

        // (*counter)++
        Insn.mov(.r1, 1),
        Insn.xadd(.r0, .r1),

        Insn.mov(.r0, 0),
        Insn.exit(),
    };
    return loadProgram(.kprobe, null, "curtsy_tune", &instructions, verifier_log);
}

fn readUintFromFile(path: [*:0]const u8) Error!i32 {
    const fd = try sysFd(linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0));
    defer _ = linux.close(fd);
    var buffer: [32]u8 = undefined;
    const count = try sys(linux.read(fd, &buffer, buffer.len));
    const text = std.mem.trim(u8, buffer[0..count], " \t\r\n");
    return std.fmt.parseInt(i32, text, 10) catch errnoError(.INVAL);
}

/// All kprobe attaches happen on the tuning thread; cache the PMU type
/// instead of re-reading the sysfs file for every probe.
threadlocal var cached_kprobe_type: i32 = -1;

/// Attaches the program to a kprobe PMU event on every online CPU
/// (pid == -1 with cpu == -1 is rejected by perf_event_open). Returns the
/// per-CPU event fds (allocated with the C allocator; owned by the caller).
fn attachKprobe(program_fd: fd_t, function_name: [:0]const u8) Error![]fd_t {
    if (cached_kprobe_type < 0) {
        cached_kprobe_type = readUintFromFile("/sys/bus/event_source/devices/kprobe/type") catch {
            return errnoError(.OPNOTSUPP);
        };
    }
    const kprobe_type = cached_kprobe_type;
    if (kprobe_type < 0) return errnoError(.OPNOTSUPP);

    const cpu_count = std.Thread.getCpuCount() catch return errnoError(.OPNOTSUPP);
    if (cpu_count < 1) return errnoError(.OPNOTSUPP);

    const fds = std.heap.c_allocator.alloc(fd_t, cpu_count) catch return error.NoMemory;
    errdefer std.heap.c_allocator.free(fds);

    var attached: usize = 0;
    errdefer {
        for (fds[0..attached]) |fd| {
            _ = linux.close(fd);
        }
    }

    for (0..cpu_count) |cpu| {
        var attributes = std.mem.zeroes(linux.perf_event_attr);
        attributes.type = @enumFromInt(@as(u32, @intCast(kprobe_type)));
        attributes.size = @sizeOf(linux.perf_event_attr);
        attributes.config1 = @intFromPtr(function_name.ptr);
        attributes.sample_period_or_freq = 1;
        attributes.wakeup_events_or_watermark = 1;

        const event_fd = try sysFd(linux.perf_event_open(
            &attributes,
            -1,
            @intCast(cpu),
            -1,
            linux.PERF.FLAG.FD_CLOEXEC,
        ));
        errdefer _ = linux.close(event_fd);
        _ = try sys(linux.ioctl(event_fd, linux.PERF.EVENT_IOC.SET_BPF, @intCast(program_fd)));
        _ = try sys(linux.ioctl(event_fd, linux.PERF.EVENT_IOC.ENABLE, 0));
        fds[cpu] = event_fd;
        attached += 1;
    }
    return fds[0..attached];
}

// ---------------------------------------------------------------------------
// Batched UDP I/O (recvmmsg/sendmmsg, 64-datagram batches)
// ---------------------------------------------------------------------------

/// Maximum number of datagrams handled per batched syscall.
pub const udp_batch_capacity = 64;

/// One slot describes a single datagram buffer: the caller fills
/// data/capacity, recv fills length and the source address.
pub const UdpSlot = extern struct {
    data: [*]u8,
    capacity: u32 = 0,
    length: u32 = 0,
    address: posix.sockaddr.storage = undefined,
    address_length: socklen_t = 0,
};

/// Receives up to slots.len datagrams (at most 64) from fd (nonblocking)
/// into slots. Returns the datagram count, 0 when the socket would block
/// or was interrupted (matching the C contract).
pub fn udpRecvBatch(fd: fd_t, slots: []UdpSlot) Error!usize {
    if (slots.len == 0) return errnoError(.INVAL);
    var io: UdpRecvBatchIo = undefined;
    io.init(slots);
    return io.recv(fd, slots);
}

/// Reusable recvmmsg header set for a fixed slot array: slot data pointers
/// never change between calls, so only the per-call fields (namelen, len)
/// are reset instead of rebuilding all 64 headers every batch.
pub const UdpRecvBatchIo = struct {
    headers: [udp_batch_capacity]linux.mmsghdr = undefined,
    vectors: [udp_batch_capacity]posix.iovec = undefined,

    pub fn init(self: *UdpRecvBatchIo, slots: []const UdpSlot) void {
        const count = @min(slots.len, udp_batch_capacity);
        for (slots[0..count], 0..) |*slot, i| {
            self.vectors[i] = .{ .base = slot.data, .len = slot.capacity };
            self.headers[i] = .{
                .hdr = .{
                    .name = @ptrCast(@constCast(&slot.address)),
                    .namelen = @sizeOf(posix.sockaddr.storage),
                    .iov = @ptrCast(&self.vectors[i]),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .len = 0,
            };
        }
    }

    pub fn recv(self: *UdpRecvBatchIo, fd: fd_t, slots: []UdpSlot) Error!usize {
        if (slots.len == 0) return errnoError(.INVAL);
        const count = @min(slots.len, udp_batch_capacity);
        for (self.headers[0..count]) |*header| {
            header.hdr.namelen = @sizeOf(posix.sockaddr.storage);
            header.len = 0;
        }
        const rc = linux.recvmmsg(fd, &self.headers, @intCast(count), linux.MSG.DONTWAIT, null);
        const e = linux.errno(rc);
        switch (e) {
            .SUCCESS => {},
            .AGAIN, .INTR => return 0,
            else => return errnoError(e),
        }
        const received: usize = @intCast(rc);
        for (slots[0..received], 0..) |*slot, i| {
            slot.length = self.headers[i].len;
            slot.address_length = self.headers[i].hdr.namelen;
        }
        return received;
    }
};

/// Sends slots.len datagrams (at most 64) described by slots (data/length
/// only) to address. Pass address == null for connected sockets. Returns
/// the number of datagrams handed to the kernel.
pub fn udpSendBatch(
    fd: fd_t,
    address: ?*const posix.sockaddr,
    address_length: socklen_t,
    slots: []const UdpSlot,
) Error!usize {
    if (slots.len == 0) return errnoError(.INVAL);
    var headers: [udp_batch_capacity]linux.mmsghdr = undefined;
    var vectors: [udp_batch_capacity]posix.iovec = undefined;
    const count = @min(slots.len, udp_batch_capacity);
    for (slots[0..count], 0..) |*slot, i| {
        vectors[i] = .{ .base = slot.data, .len = slot.length };
        headers[i] = .{
            .hdr = .{
                .name = @constCast(address),
                .namelen = address_length,
                .iov = @ptrCast(&vectors[i]),
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            },
            .len = 0,
        };
    }
    const sent = try sys(linux.sendmmsg(fd, &headers, @intCast(count), linux.MSG.DONTWAIT));
    return sent;
}

// ---------------------------------------------------------------------------
// epoll / eventfd primitives
// ---------------------------------------------------------------------------

pub fn epollCreate() Error!fd_t {
    return sysFd(linux.epoll_create1(linux.EPOLL.CLOEXEC));
}

/// Registers fd for EPOLLIN with data.fd = fd.
pub fn epollAdd(epoll_fd: fd_t, fd: fd_t) Error!void {
    var event = linux.epoll_event{
        .events = linux.EPOLL.IN,
        .data = .{ .fd = fd },
    };
    _ = try sys(linux.epoll_ctl(epoll_fd, linux.EPOLL.CTL_ADD, fd, &event));
}

/// Fills ready_fds and returns the number of ready fds (0 on timeout).
/// Retries on EINTR. At most 65 fds are reported per call.
pub fn epollWait(epoll_fd: fd_t, ready_fds: []fd_t, timeout_ms: i32) Error!usize {
    if (ready_fds.len == 0) return errnoError(.INVAL);
    var events: [65]linux.epoll_event = undefined;
    const max_events = @min(ready_fds.len, events.len);
    while (true) {
        const rc = linux.epoll_wait(epoll_fd, &events, @intCast(max_events), timeout_ms);
        const e = linux.errno(rc);
        if (e == .INTR) continue;
        if (e != .SUCCESS) return errnoError(e);
        const ready: usize = @intCast(rc);
        for (ready_fds[0..ready], 0..) |*slot, i| {
            slot.* = events[i].data.fd;
        }
        return ready;
    }
}

pub fn eventfdCreate() Error!fd_t {
    return sysFd(linux.eventfd(0, linux.EFD.NONBLOCK | linux.EFD.CLOEXEC));
}

pub fn eventfdSignal(fd: fd_t) void {
    const one: u64 = 1;
    _ = linux.write(fd, std.mem.asBytes(&one), @sizeOf(u64));
}

pub fn eventfdDrain(fd: fd_t) void {
    var value: u64 = 0;
    _ = linux.read(fd, std.mem.asBytes(&value), @sizeOf(u64));
}

// ---------------------------------------------------------------------------
// UDP socket creators
// ---------------------------------------------------------------------------

pub const BoundAddress = struct {
    address: posix.sockaddr.storage,
    length: socklen_t,
};

fn makeDatagramSocket(family: u32) Error!fd_t {
    return sysFd(linux.socket(family, linux.SOCK.DGRAM | linux.SOCK.NONBLOCK | linux.SOCK.CLOEXEC, 0));
}

fn setReuseOptions(fd: fd_t, family: u32) Error!void {
    const yes: i32 = 1;
    _ = try sys(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, std.mem.asBytes(&yes), @sizeOf(i32)));
    // SO_REUSEPORT lets one engine thread per worker bind the same address;
    // the kernel then hashes each client four-tuple to a stable listener.
    _ = try sys(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, std.mem.asBytes(&yes), @sizeOf(i32)));
    if (family == linux.AF.INET6) {
        _ = try sys(linux.setsockopt(fd, linux.SOL.IPV6, linux.IPV6.V6ONLY, std.mem.asBytes(&yes), @sizeOf(i32)));
    }
}

/// Creates a bound datagram socket for address. Sets SO_REUSEADDR and
/// SO_REUSEPORT (one engine thread per worker binds the same address) and,
/// for AF_INET6, IPV6_V6ONLY. On success the bound address (getsockname)
/// is stored in `bound` when provided and the fd is returned.
pub fn udpListenSocket(
    address: *const posix.sockaddr,
    address_length: socklen_t,
    bound: ?*BoundAddress,
) Error!fd_t {
    const fd = try makeDatagramSocket(address.family);
    errdefer _ = linux.close(fd);

    try setReuseOptions(fd, address.family);
    _ = try sys(linux.bind(fd, address, address_length));
    if (bound) |out| {
        out.length = @sizeOf(posix.sockaddr.storage);
        _ = try sys(linux.getsockname(fd, @ptrCast(&out.address), &out.length));
    }
    return fd;
}

/// Creates a datagram socket connected to address (default destination).
pub fn udpUpstreamSocket(address: *const posix.sockaddr, address_length: socklen_t) Error!fd_t {
    const fd = try makeDatagramSocket(address.family);
    errdefer _ = linux.close(fd);
    _ = try sys(linux.connect(fd, address, address_length));
    return fd;
}

/// Creates a datagram socket bound to bind_address (SO_REUSEADDR and
/// SO_REUSEPORT, matching the listen sockets it shares the port with;
/// IPV6_V6ONLY for AF_INET6) and connected to peer_address. Used for
/// per-client UDP sockets: the kernel demux prefers this connected
/// four-tuple socket over the wildcard listener, so the client's
/// datagrams land here once it exists.
pub fn udpConnectedClientSocket(
    bind_address: *const posix.sockaddr,
    bind_address_length: socklen_t,
    peer_address: *const posix.sockaddr,
    peer_address_length: socklen_t,
) Error!fd_t {
    if (bind_address.family != peer_address.family) return errnoError(.INVAL);
    const fd = try makeDatagramSocket(bind_address.family);
    errdefer _ = linux.close(fd);

    // Listen sockets carry SO_REUSEPORT; every socket sharing the port must
    // set it too, otherwise this bind fails with EADDRINUSE. Connected
    // sockets never join wildcard delivery: the kernel exact-matches their
    // four-tuple first, so only their peer's datagrams land here.
    // SO_REUSEADDR is not needed for a connected four-tuple socket.
    const yes: i32 = 1;
    _ = try sys(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, std.mem.asBytes(&yes), @sizeOf(i32)));
    if (bind_address.family == linux.AF.INET6) {
        _ = try sys(linux.setsockopt(fd, linux.SOL.IPV6, linux.IPV6.V6ONLY, std.mem.asBytes(&yes), @sizeOf(i32)));
    }
    _ = try sys(linux.bind(fd, bind_address, bind_address_length));
    _ = try sys(linux.connect(fd, peer_address, peer_address_length));
    return fd;
}

/// Sets SO_RCVBUF and SO_SNDBUF to bytes on a datagram socket. Without
/// CAP_NET_ADMIN the kernel silently clamps each to rmem_max/wmem_max, so
/// an oversized request is not an error; genuine failures return an error.
pub fn udpSetSocketBuffers(fd: fd_t, bytes: i32) Error!void {
    if (bytes <= 0) return errnoError(.INVAL);
    _ = try sys(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, std.mem.asBytes(&bytes), @sizeOf(i32)));
    _ = try sys(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.SNDBUF, std.mem.asBytes(&bytes), @sizeOf(i32)));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn loopbackV4(port: u16) posix.sockaddr.in {
    return .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
    };
}

fn loopbackV4Generic(port: u16) posix.sockaddr {
    const addr = loopbackV4(port);
    return @bitCast(addr);
}

fn closeFd(fd: fd_t) void {
    _ = linux.close(fd);
}

test "eventfd signal and drain roundtrip" {
    const fd = try eventfdCreate();
    defer closeFd(fd);

    eventfdSignal(fd);
    eventfdSignal(fd);

    var value: u64 = 0;
    const count = linux.read(fd, std.mem.asBytes(&value), @sizeOf(u64));
    try testing.expectEqual(@as(usize, @sizeOf(u64)), count);
    try testing.expectEqual(@as(u64, 2), value);

    // Draining an empty nonblocking eventfd must not block or crash.
    eventfdDrain(fd);
}

test "epoll create/add/wait roundtrip" {
    const epoll_fd = try epollCreate();
    defer closeFd(epoll_fd);
    const wake_fd = try eventfdCreate();
    defer closeFd(wake_fd);

    try epollAdd(epoll_fd, wake_fd);

    var ready: [4]fd_t = undefined;
    // Nothing pending: immediate timeout reports zero ready fds.
    try testing.expectEqual(@as(usize, 0), try epollWait(epoll_fd, &ready, 0));

    eventfdSignal(wake_fd);
    try testing.expectEqual(@as(usize, 1), try epollWait(epoll_fd, &ready, 1000));
    try testing.expectEqual(wake_fd, ready[0]);

    eventfdDrain(wake_fd);
    try testing.expectEqual(@as(usize, 0), try epollWait(epoll_fd, &ready, 0));
}

test "udp listen socket on loopback wildcard port" {
    const address = loopbackV4Generic(0);
    var bound: BoundAddress = undefined;
    const fd = try udpListenSocket(&address, @sizeOf(posix.sockaddr.in), &bound);
    defer closeFd(fd);

    try testing.expectEqual(linux.AF.INET, bound.address.family);
    try testing.expectEqual(@sizeOf(posix.sockaddr.in), bound.length);
    const bound_in: *const posix.sockaddr.in = @ptrCast(&bound.address);
    try testing.expect(std.mem.bigToNative(u16, bound_in.port) != 0);
}

test "batched udp send/recv roundtrip between loopback sockets" {
    const listen_address = loopbackV4Generic(0);
    var bound: BoundAddress = undefined;
    const listen_fd = try udpListenSocket(&listen_address, @sizeOf(posix.sockaddr.in), &bound);
    defer closeFd(listen_fd);

    const bound_in: *const posix.sockaddr.in = @ptrCast(&bound.address);
    const destination = loopbackV4Generic(std.mem.bigToNative(u16, bound_in.port));
    const send_fd = try udpUpstreamSocket(&destination, @sizeOf(posix.sockaddr.in));
    defer closeFd(send_fd);

    var payload_one = "hello".*;
    var payload_two = "world-12345".*;
    const send_slots = [_]UdpSlot{
        .{ .data = &payload_one, .capacity = payload_one.len, .length = payload_one.len },
        .{ .data = &payload_two, .capacity = payload_two.len, .length = payload_two.len },
    };
    try testing.expectEqual(@as(usize, 2), try udpSendBatch(send_fd, null, 0, &send_slots));

    var buffer_one: [64]u8 = undefined;
    var buffer_two: [64]u8 = undefined;
    var recv_slots = [_]UdpSlot{
        .{ .data = &buffer_one, .capacity = buffer_one.len },
        .{ .data = &buffer_two, .capacity = buffer_two.len },
    };

    // Delivery on loopback is fast but not synchronous; poll briefly.
    var received: usize = 0;
    for (0..100) |_| {
        received = try udpRecvBatch(listen_fd, &recv_slots);
        if (received > 0) break;
        const delay = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&delay, null);
    }
    try testing.expectEqual(@as(usize, 2), received);
    try testing.expectEqual(@as(u32, 5), recv_slots[0].length);
    try testing.expectEqualStrings("hello", buffer_one[0..recv_slots[0].length]);
    try testing.expectEqualStrings("world-12345", buffer_two[0..recv_slots[1].length]);
    try testing.expectEqual(linux.AF.INET, recv_slots[0].address.family);

    // Both datagrams consumed: next batch reports "would block" as 0.
    try testing.expectEqual(@as(usize, 0), try udpRecvBatch(listen_fd, &recv_slots));
}

test "udp set socket buffers" {
    const destination = loopbackV4Generic(9); // unbound port is fine for connect()
    const fd = try udpUpstreamSocket(&destination, @sizeOf(posix.sockaddr.in));
    defer closeFd(fd);

    try udpSetSocketBuffers(fd, 1 << 20);

    var receive_buffer: i32 = 0;
    var length: socklen_t = @sizeOf(i32);
    _ = try sys(linux.getsockopt(
        fd,
        linux.SOL.SOCKET,
        linux.SO.RCVBUF,
        std.mem.asBytes(&receive_buffer).ptr,
        &length,
    ));
    // The kernel reports the doubled value, possibly clamped to rmem_max.
    try testing.expect(receive_buffer > 0);

    try testing.expectError(error.Invalid, udpSetSocketBuffers(fd, 0));
    try testing.expectError(error.Invalid, udpSetSocketBuffers(fd, -1));
}

test "udp connected client socket shares the listen port" {
    const listen_address = loopbackV4Generic(0);
    var bound: BoundAddress = undefined;
    const listen_fd = try udpListenSocket(&listen_address, @sizeOf(posix.sockaddr.in), &bound);
    defer closeFd(listen_fd);

    // Bind a second socket to the exact listen address/port and connect it
    // to a fixed peer; requires SO_REUSEPORT to coexist with the listener.
    const client_fd = try udpConnectedClientSocket(
        @ptrCast(&bound.address),
        bound.length,
        &listen_address,
        @sizeOf(posix.sockaddr.in),
    );
    defer closeFd(client_fd);
}

test "sockmap loader rejects invalid arguments without privileges" {
    try testing.expectError(error.Invalid, loadReusePortBpf(0, null));
    try testing.expectError(error.Invalid, SockmapRuntime.createTcp(0, null));
    try testing.expectError(error.Invalid, SockmapRuntime.createUdp(0, null));
    try testing.expectError(error.Invalid, BpfObserver.create(0, null));
}

test "eBPF loaders (gated: CURTSY_ENABLE_EBPF_TESTS)" {
    if (std.c.getenv("CURTSY_ENABLE_EBPF_TESTS") == null) return;

    var verifier_log: [256 * 1024]u8 = undefined;

    // Reuseport steering program. When the gate is set but the process
    // still lacks CAP_BPF/CAP_NET_ADMIN, treat it as a skip: loader
    // failures must stay graceful everywhere.
    const reuse_fd = loadReusePortBpf(2, &verifier_log) catch |err| switch (err) {
        error.PermissionDenied, error.AccessDenied, error.NotSupported => return,
        else => return err,
    };
    closeFd(reuse_fd);

    // TCP sockmap runtime: maps + parser + verdict program.
    var tcp_runtime = SockmapRuntime.createTcp(1024, &verifier_log) catch |err| switch (err) {
        error.PermissionDenied, error.AccessDenied, error.NotSupported => return,
        else => return err,
    };
    tcp_runtime.destroy();

    // UDP verdict-only runtime, plus a full pair/idle/unpair cycle on two
    // connected loopback UDP sockets.
    const udp_runtime = try SockmapRuntime.createUdp(1024, &verifier_log);
    defer {
        var runtime = udp_runtime;
        runtime.destroy();
    }

    const listen_address = loopbackV4Generic(0);
    var bound: BoundAddress = undefined;
    const listen_fd = try udpListenSocket(&listen_address, @sizeOf(posix.sockaddr.in), &bound);
    defer closeFd(listen_fd);
    const bound_in: *const posix.sockaddr.in = @ptrCast(&bound.address);

    const client_fd = try udpUpstreamSocket(
        &loopbackV4Generic(std.mem.bigToNative(u16, bound_in.port)),
        @sizeOf(posix.sockaddr.in),
    );
    defer closeFd(client_fd);

    const pairing = try udp_runtime.pair(client_fd, listen_fd);
    try testing.expect(pairing.client_cookie != 0);
    try testing.expect(pairing.upstream_cookie != 0);

    const remaining = try udp_runtime.idleRemainingNs(
        pairing.client_cookie,
        pairing.upstream_cookie,
        60 * std.time.ns_per_s,
    );
    try testing.expect(remaining > 0);

    udp_runtime.unpair(pairing.client_cookie, pairing.upstream_cookie);
    try testing.expectError(
        error.NoEntry,
        udp_runtime.idleRemainingNs(pairing.client_cookie, pairing.upstream_cookie, 60 * std.time.ns_per_s),
    );
}
