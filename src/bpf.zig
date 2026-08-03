//! Linux syscall and eBPF runtime support. Kernel programs are written in C
//! under src/ebpf, compiled by Clang into standard BPF ELF objects, and loaded
//! through libbpf (ELF relocations, maps, BTF and verifier logs). This module
//! owns their runtime handles and also provides batched UDP I/O plus the
//! epoll/eventfd/socket primitives used by the relay engines.
//!
//! Linux-only. Every eBPF loader fails with an error when privileges or kernel
//! support are missing; callers fall back to userspace paths. Nothing here may
//! crash on loader failure.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const BPF = linux.BPF;
const bpf_programs = @import("bpf_programs");

const embedded_programs = struct {
    const tcp_sockmap = bpf_programs.tcp_sockmap;
    const udp_sockmap = bpf_programs.udp_sockmap;
    const reuseport = bpf_programs.reuseport;
    const observer = bpf_programs.observer;
};

const LibbpfObject = opaque {};
const LibbpfLink = opaque {};

extern fn curtsy_libbpf_open(
    data: *const anyopaque,
    size: usize,
    kernel_log: ?[*]u8,
    kernel_log_size: usize,
    error_out: *c_int,
) ?*LibbpfObject;
extern fn curtsy_libbpf_close(object: *LibbpfObject) void;
extern fn curtsy_libbpf_set_map_max_entries(object: *LibbpfObject, map_name: [*:0]const u8, max_entries: u32) c_int;
extern fn curtsy_libbpf_set_rodata(object: *LibbpfObject, data: *const anyopaque, size: usize) c_int;
extern fn curtsy_libbpf_set_expected_attach_type(object: *LibbpfObject, program_name: [*:0]const u8, attach_type: u32) c_int;
extern fn curtsy_libbpf_load(object: *LibbpfObject) c_int;
extern fn curtsy_libbpf_map_fd(object: *LibbpfObject, map_name: [*:0]const u8) c_int;
extern fn curtsy_libbpf_program_fd(object: *LibbpfObject, program_name: [*:0]const u8) c_int;
extern fn curtsy_libbpf_has_program(object: *LibbpfObject, program_name: [*:0]const u8) c_int;
extern fn curtsy_libbpf_program_type(object: *LibbpfObject, program_name: [*:0]const u8) c_int;
extern fn curtsy_libbpf_dup_program_fd(object: *LibbpfObject, program_name: [*:0]const u8) c_int;
extern fn curtsy_libbpf_attach_kprobe(
    object: *LibbpfObject,
    program_name: [*:0]const u8,
    function_name: [*:0]const u8,
    error_out: *c_int,
) ?*LibbpfLink;
extern fn curtsy_libbpf_destroy_link(link: *LibbpfLink) void;

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

fn libbpfError(return_code: c_int) Error {
    const positive: u32 = @intCast(-@as(i64, return_code));
    const errno_code: u16 = @intCast(@min(positive, std.math.maxInt(u16)));
    return errnoError(@enumFromInt(errno_code));
}

fn libbpfStatus(return_code: c_int) Error!void {
    if (return_code < 0) return libbpfError(return_code);
}

fn libbpfFd(return_code: c_int) Error!fd_t {
    if (return_code < 0) return libbpfError(return_code);
    return @intCast(return_code);
}

fn openBpfObject(bytes: []const u8, verifier_log: ?[]u8) Error!*LibbpfObject {
    var error_code: c_int = 0;
    var log_pointer: ?[*]u8 = null;
    var log_size: usize = 0;
    if (verifier_log) |log| {
        if (log.len > 0) {
            log_pointer = log.ptr;
            log_size = log.len;
        }
    }
    return curtsy_libbpf_open(bytes.ptr, bytes.len, log_pointer, log_size, &error_code) orelse {
        if (error_code >= 0) error_code = -@as(c_int, @intFromEnum(linux.E.INVAL));
        return libbpfError(error_code);
    };
}

// ---------------------------------------------------------------------------
// Raw bpf() syscall wrappers
// ---------------------------------------------------------------------------

fn bpfCall(cmd: BPF.Cmd, attr: *BPF.Attr) usize {
    return linux.bpf(cmd, attr, @sizeOf(BPF.Attr));
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

    const object = try openBpfObject(embedded_programs.reuseport, verifier_log);
    defer curtsy_libbpf_close(object);
    try libbpfStatus(curtsy_libbpf_set_rodata(object, &socket_count, @sizeOf(u32)));
    try libbpfStatus(curtsy_libbpf_load(object));
    return libbpfFd(curtsy_libbpf_dup_program_fd(object, "reuseport_select"));
}

// ---------------------------------------------------------------------------
// Sockmap runtime (TCP and UDP variants)
// ---------------------------------------------------------------------------

/// Owns the sockhash map, the peer-state map and the attached SK_SKB
/// programs used for kernel-level forwarding between paired sockets.
/// TCP pairs use a stream parser + stream verdict; UDP pairs use a
/// verdict-only program (BPF_SK_SKB_VERDICT, kernel >= 5.12).
pub const SockmapRuntime = struct {
    object: ?*LibbpfObject,
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
            .object = null,
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

        const bytes = if (for_udp) embedded_programs.udp_sockmap else embedded_programs.tcp_sockmap;
        runtime.object = try openBpfObject(bytes, verifier_log);
        const object = runtime.object.?;
        try libbpfStatus(curtsy_libbpf_set_map_max_entries(object, "sockhash", max_entries));
        try libbpfStatus(curtsy_libbpf_set_map_max_entries(object, "peer_map", max_entries));
        if (for_udp) {
            try libbpfStatus(curtsy_libbpf_set_expected_attach_type(
                object,
                "udp_verdict",
                @intFromEnum(BPF.AttachType.sk_skb_verdict),
            ));
        }
        try libbpfStatus(curtsy_libbpf_load(object));

        runtime.sockhash_fd = try libbpfFd(curtsy_libbpf_map_fd(object, "sockhash"));
        runtime.peer_fd = try libbpfFd(curtsy_libbpf_map_fd(object, "peer_map"));
        if (!for_udp) runtime.parser_fd = try libbpfFd(curtsy_libbpf_program_fd(object, "tcp_stream_parser"));
        runtime.program_fd = try libbpfFd(curtsy_libbpf_program_fd(
            object,
            if (for_udp) "udp_verdict" else "tcp_stream_verdict",
        ));

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
        if (self.object) |object| curtsy_libbpf_close(object);
        self.* = .{
            .object = null,
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

    object: ?*LibbpfObject,
    counters_fd: fd_t,
    links: [observer_counter_count]?*LibbpfLink,

    const functions = [observer_counter_count][:0]const u8{
        "tcp_sendmsg",
        "tcp_recvmsg",
        "udp_sendmsg",
        "udp_recvmsg",
    };
    const programs = [observer_counter_count][:0]const u8{
        "observe_tcp_sendmsg",
        "observe_tcp_recvmsg",
        "observe_udp_sendmsg",
        "observe_udp_recvmsg",
    };

    /// Loads one kprobe program per counter and attaches it to the
    /// matching kernel function on every online CPU, filtered to
    /// `target_pid`. Fails with an error when lacking privileges or
    /// kprobe/BPF support.
    pub fn create(target_pid: u32, verifier_log: ?[]u8) Error!BpfObserver {
        if (target_pid == 0) return errnoError(.INVAL);

        var observer = BpfObserver{
            .object = null,
            .counters_fd = -1,
            .links = .{ null, null, null, null },
        };
        errdefer {
            const saved = lastErrno;
            observer.destroy();
            lastErrno = saved;
        }

        observer.object = try openBpfObject(embedded_programs.observer, verifier_log);
        const object = observer.object.?;
        try libbpfStatus(curtsy_libbpf_set_rodata(object, &target_pid, @sizeOf(u32)));
        try libbpfStatus(curtsy_libbpf_load(object));
        observer.counters_fd = try libbpfFd(curtsy_libbpf_map_fd(object, "counters"));

        for (0..observer_counter_count) |i| {
            var attach_error: c_int = 0;
            observer.links[i] = curtsy_libbpf_attach_kprobe(
                object,
                programs[i],
                functions[i],
                &attach_error,
            ) orelse {
                if (verifier_log) |log| {
                    if (log.len > 0) {
                        const text = std.fmt.bufPrint(log, "stage=kprobe_attach function={s}", .{functions[i]}) catch null;
                        if (text != null and log.len > 0) {
                            log[@min(text.?.len, log.len - 1)] = 0;
                        }
                    }
                }
                if (attach_error >= 0) attach_error = -@as(c_int, @intFromEnum(linux.E.INVAL));
                return libbpfError(attach_error);
            };
        }
        return observer;
    }

    pub fn destroy(self: *BpfObserver) void {
        for (0..observer_counter_count) |i| {
            if (self.links[i]) |link| curtsy_libbpf_destroy_link(link);
            self.links[i] = null;
        }
        if (self.object) |object| curtsy_libbpf_close(object);
        self.object = null;
        self.counters_fd = -1;
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
    /// Number of slots/headers initialized by init(). recv/recvInto reject any
    /// request that would reach past this count, so uninitialized headers are
    /// never reset or read back into slots.
    initialized_count: usize = 0,

    pub fn init(self: *UdpRecvBatchIo, slots: []const UdpSlot) void {
        const count = @min(slots.len, udp_batch_capacity);
        self.initialized_count = count;
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
        return self.recvInto(fd, slots, 0);
    }

    /// Receives into the suffix `slots[offset..]`, appending at most
    /// `slots.len - offset` datagrams behind previously received ones without
    /// touching the earlier slots or their headers. `offset` must be within
    /// the slot array the instance was initialized with; slots beyond the
    /// array never have their headers reset, so a caller can coalesce several
    /// nonblocking recvmmsg calls into one 64-slot batch before forwarding.
    /// Returns the datagram count received by this call (0 on EAGAIN/EINTR).
    /// Rejects empty slices, slices longer than init() initialized or than the
    /// 64-slot syscall capacity, and offsets at or past the end, all before
    /// any header is touched or syscall issued.
    pub fn recvInto(self: *UdpRecvBatchIo, fd: fd_t, slots: []UdpSlot, offset: usize) Error!usize {
        if (slots.len == 0 or
            slots.len > self.initialized_count or
            slots.len > udp_batch_capacity or
            offset >= slots.len)
        {
            return errnoError(.INVAL);
        }
        const count = slots.len - offset;
        for (self.headers[offset .. offset + count]) |*header| {
            header.hdr.namelen = @sizeOf(posix.sockaddr.storage);
            header.len = 0;
        }
        const rc = linux.recvmmsg(fd, self.headers[offset..].ptr, @intCast(count), linux.MSG.DONTWAIT, null);
        const e = linux.errno(rc);
        switch (e) {
            .SUCCESS => {},
            .AGAIN, .INTR => return 0,
            else => return errnoError(e),
        }
        const received: usize = @intCast(rc);
        for (slots[offset .. offset + received], 0..) |*slot, i| {
            slot.length = self.headers[offset + i].len;
            slot.address_length = self.headers[offset + i].hdr.namelen;
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
    var io: UdpSendBatchIo = undefined;
    return io.send(fd, address, address_length, slots);
}

/// Reusable sendmmsg header set for a fixed slot array: headers and iovecs
/// live here instead of being rebuilt on the caller's stack on every batch,
/// so an engine that sends repeatedly only rewrites the entries for the
/// slots it is about to send.
pub const UdpSendBatchIo = struct {
    headers: [udp_batch_capacity]linux.mmsghdr = undefined,
    vectors: [udp_batch_capacity]posix.iovec = undefined,

    /// Sends slots.len datagrams (at most 64) to address (null for connected
    /// sockets), reusing this instance's header/iovec storage. Returns the
    /// number of datagrams handed to the kernel, which may be less than
    /// slots.len on partial batches.
    pub fn send(
        self: *UdpSendBatchIo,
        fd: fd_t,
        address: ?*const posix.sockaddr,
        address_length: socklen_t,
        slots: []const UdpSlot,
    ) Error!usize {
        if (slots.len == 0) return errnoError(.INVAL);
        const count = @min(slots.len, udp_batch_capacity);
        for (slots[0..count], 0..) |*slot, i| {
            self.vectors[i] = .{ .base = slot.data, .len = slot.length };
            self.headers[i] = .{
                .hdr = .{
                    .name = @constCast(address),
                    .namelen = address_length,
                    .iov = @ptrCast(&self.vectors[i]),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .len = 0,
            };
        }
        return sys(linux.sendmmsg(fd, &self.headers, @intCast(count), linux.MSG.DONTWAIT));
    }
};

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

test "udp recv batch io appends into unused slots without overwriting" {
    const listen_address = loopbackV4Generic(0);
    var bound: BoundAddress = undefined;
    const listen_fd = try udpListenSocket(&listen_address, @sizeOf(posix.sockaddr.in), &bound);
    defer closeFd(listen_fd);

    const bound_in: *const posix.sockaddr.in = @ptrCast(&bound.address);
    const destination = loopbackV4Generic(std.mem.bigToNative(u16, bound_in.port));
    const send_fd = try udpUpstreamSocket(&destination, @sizeOf(posix.sockaddr.in));
    defer closeFd(send_fd);

    var buffers: [8][16]u8 = undefined;
    var recv_slots: [8]UdpSlot = undefined;
    for (&recv_slots, 0..) |*slot, i| {
        slot.* = .{ .data = &buffers[i], .capacity = buffers[i].len };
    }
    var io = UdpRecvBatchIo{};
    io.init(&recv_slots);

    // Wave 1: two datagrams land before the first recvmmsg.
    var first = "first-a".*;
    var second = "second-b".*;
    const wave_one = [_]UdpSlot{
        .{ .data = &first, .length = first.len },
        .{ .data = &second, .length = second.len },
    };
    try testing.expectEqual(@as(usize, 2), try udpSendBatch(send_fd, null, 0, &wave_one));

    var offset: usize = 0;
    for (0..100) |_| {
        const received = try io.recvInto(listen_fd, &recv_slots, offset);
        offset += received;
        if (offset == 2) break;
        if (received == 0) {
            const delay = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&delay, null);
        }
    }
    try testing.expectEqual(@as(usize, 2), offset);

    // Wave 2: three more datagrams append behind the first two without
    // touching the earlier slots' lengths.
    var third = "third-c".*;
    var fourth = "fourth-d".*;
    var fifth = "fifth-e".*;
    const wave_two = [_]UdpSlot{
        .{ .data = &third, .length = third.len },
        .{ .data = &fourth, .length = fourth.len },
        .{ .data = &fifth, .length = fifth.len },
    };
    try testing.expectEqual(@as(usize, 3), try udpSendBatch(send_fd, null, 0, &wave_two));
    while (offset < 5) {
        const received = try io.recvInto(listen_fd, &recv_slots, offset);
        if (received == 0) {
            const delay = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
            _ = linux.nanosleep(&delay, null);
            continue;
        }
        offset += received;
    }
    try testing.expectEqual(@as(usize, 5), offset);

    try testing.expectEqualStrings("first-a", buffers[0][0..recv_slots[0].length]);
    try testing.expectEqualStrings("second-b", buffers[1][0..recv_slots[1].length]);
    try testing.expectEqualStrings("third-c", buffers[2][0..recv_slots[2].length]);
    try testing.expectEqualStrings("fourth-d", buffers[3][0..recv_slots[3].length]);
    try testing.expectEqualStrings("fifth-e", buffers[4][0..recv_slots[4].length]);
}

test "udp recv batch io rejects out-of-range slots and offsets without a syscall" {
    var buffers: [8][16]u8 = undefined;
    var recv_slots: [8]UdpSlot = undefined;
    for (&recv_slots, 0..) |*slot, i| {
        slot.* = .{ .data = &buffers[i], .capacity = buffers[i].len };
    }
    var io = UdpRecvBatchIo{};
    io.init(&recv_slots);

    // A slice longer than init() recorded is rejected; the invalid fd proves
    // the check fires before any recvmmsg (and before touching headers).
    var extra_buffers: [4][16]u8 = undefined;
    var oversized: [12]UdpSlot = undefined;
    for (&oversized, 0..) |*slot, i| {
        slot.* = .{ .data = if (i < 8) &buffers[i] else &extra_buffers[i - 8], .capacity = 16 };
    }
    try testing.expectError(error.Invalid, io.recv(-1, &oversized));
    try testing.expectError(error.Invalid, io.recvInto(-1, &oversized, 0));

    // Empty slices and offsets at or past the end are rejected.
    const empty: []UdpSlot = &.{};
    try testing.expectError(error.Invalid, io.recv(-1, empty));
    try testing.expectError(error.Invalid, io.recvInto(-1, &recv_slots, recv_slots.len));
    try testing.expectError(error.Invalid, io.recvInto(-1, &recv_slots, recv_slots.len + 1));

    // Over the 64-slot syscall capacity is rejected even though init() clamps
    // to 64; the uninitialized tail must never be reachable.
    var huge_buffers: [65][16]u8 = undefined;
    var over_capacity: [65]UdpSlot = undefined;
    for (&over_capacity, 0..) |*slot, i| {
        slot.* = .{ .data = &huge_buffers[i], .capacity = huge_buffers[i].len };
    }
    var big_io = UdpRecvBatchIo{};
    big_io.init(&over_capacity);
    try testing.expectEqual(@as(usize, 64), big_io.initialized_count);
    try testing.expectError(error.Invalid, big_io.recv(-1, &over_capacity));
    try testing.expectError(error.Invalid, big_io.recvInto(-1, &over_capacity, 0));

    // An offset that would reach into the uninitialized tail of a smaller
    // instance is rejected too.
    var small: [4]UdpSlot = undefined;
    for (&small, 0..) |*slot, i| {
        slot.* = .{ .data = &buffers[i], .capacity = buffers[i].len };
    }
    var small_io = UdpRecvBatchIo{};
    small_io.init(&small);
    try testing.expectError(error.Invalid, small_io.recvInto(-1, &small, small.len));
    try testing.expectError(error.Invalid, small_io.recvInto(-1, &small, small.len + 1));
}

test "udp send batch io reuses storage across addressed, connected and partial sends" {
    // Destination A receives addressed sends; destination B receives a
    // connected send.
    const bound_a = blk: {
        const address = loopbackV4Generic(0);
        var bound: BoundAddress = undefined;
        const fd = try udpListenSocket(&address, @sizeOf(posix.sockaddr.in), &bound);
        errdefer closeFd(fd);
        const in: *const posix.sockaddr.in = @ptrCast(&bound.address);
        break :blk .{ .fd = fd, .port = std.mem.bigToNative(u16, in.port) };
    };
    defer closeFd(bound_a.fd);
    const bound_b = blk: {
        const address = loopbackV4Generic(0);
        var bound: BoundAddress = undefined;
        const fd = try udpListenSocket(&address, @sizeOf(posix.sockaddr.in), &bound);
        errdefer closeFd(fd);
        const in: *const posix.sockaddr.in = @ptrCast(&bound.address);
        break :blk .{ .fd = fd, .port = std.mem.bigToNative(u16, in.port) };
    };
    defer closeFd(bound_b.fd);

    // Unconnected sender for addressed sends; connected socket for B.
    const sender = try udpListenSocket(&loopbackV4Generic(0), @sizeOf(posix.sockaddr.in), null);
    defer closeFd(sender);
    const connected = try udpUpstreamSocket(&loopbackV4Generic(bound_b.port), @sizeOf(posix.sockaddr.in));
    defer closeFd(connected);

    var payload_one = "addressed-one".*;
    var payload_two = "addressed-two".*;
    var payload_connected = "connected-send".*;
    var payload_partial = "partial-slice".*;
    const dest_a = loopbackV4Generic(bound_a.port);
    const dest_a_ptr: *const posix.sockaddr = @ptrCast(&dest_a);

    var io = UdpSendBatchIo{};

    // Addressed batch to A.
    var slots_a = [_]UdpSlot{
        .{ .data = &payload_one, .length = payload_one.len },
        .{ .data = &payload_two, .length = payload_two.len },
    };
    try testing.expectEqual(@as(usize, 2), try io.send(sender, dest_a_ptr, @sizeOf(posix.sockaddr.in), &slots_a));

    // Connected send to B, reusing the same helper storage.
    var slots_b = [_]UdpSlot{
        .{ .data = &payload_connected, .length = payload_connected.len },
    };
    try testing.expectEqual(@as(usize, 1), try io.send(connected, null, 0, &slots_b));

    // Partial slice: only slots[1..2] of a 3-entry array reaches the kernel.
    var slots_c = [_]UdpSlot{
        .{ .data = &payload_one, .length = payload_one.len },
        .{ .data = &payload_partial, .length = payload_partial.len },
        .{ .data = &payload_two, .length = payload_two.len },
    };
    try testing.expectEqual(@as(usize, 1), try io.send(sender, dest_a_ptr, @sizeOf(posix.sockaddr.in), slots_c[1..2]));

    // A must receive all three addressed datagrams in send order.
    var buffer_a_one: [64]u8 = undefined;
    var buffer_a_two: [64]u8 = undefined;
    var buffer_a_three: [64]u8 = undefined;
    var recv_slots_a = [_]UdpSlot{
        .{ .data = &buffer_a_one, .capacity = buffer_a_one.len },
        .{ .data = &buffer_a_two, .capacity = buffer_a_two.len },
        .{ .data = &buffer_a_three, .capacity = buffer_a_three.len },
    };
    var received_a: usize = 0;
    for (0..100) |_| {
        received_a += try udpRecvBatch(bound_a.fd, recv_slots_a[received_a..]);
        if (received_a == recv_slots_a.len) break;
        const delay = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&delay, null);
    }
    try testing.expectEqual(recv_slots_a.len, received_a);
    try testing.expectEqualStrings("addressed-one", buffer_a_one[0..recv_slots_a[0].length]);
    try testing.expectEqualStrings("addressed-two", buffer_a_two[0..recv_slots_a[1].length]);
    try testing.expectEqualStrings("partial-slice", buffer_a_three[0..recv_slots_a[2].length]);

    // B must receive the connected-send datagram.
    var buffer_b: [64]u8 = undefined;
    var recv_slots_b = [_]UdpSlot{
        .{ .data = &buffer_b, .capacity = buffer_b.len },
    };
    var received_b: usize = 0;
    for (0..100) |_| {
        received_b += try udpRecvBatch(bound_b.fd, recv_slots_b[received_b..]);
        if (received_b == recv_slots_b.len) break;
        const delay = linux.timespec{ .sec = 0, .nsec = 1_000_000 };
        _ = linux.nanosleep(&delay, null);
    }
    try testing.expectEqual(recv_slots_b.len, received_b);
    try testing.expectEqualStrings("connected-send", buffer_b[0..recv_slots_b[0].length]);
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

test "embedded BPF ELF objects open through libbpf" {
    const tcp = try openBpfObject(embedded_programs.tcp_sockmap, null);
    defer curtsy_libbpf_close(tcp);
    try libbpfStatus(curtsy_libbpf_set_map_max_entries(tcp, "sockhash", 16));
    try libbpfStatus(curtsy_libbpf_set_map_max_entries(tcp, "peer_map", 16));
    try libbpfStatus(curtsy_libbpf_has_program(tcp, "tcp_stream_parser"));
    try libbpfStatus(curtsy_libbpf_has_program(tcp, "tcp_stream_verdict"));

    const udp = try openBpfObject(embedded_programs.udp_sockmap, null);
    defer curtsy_libbpf_close(udp);
    try libbpfStatus(curtsy_libbpf_set_map_max_entries(udp, "sockhash", 16));
    try libbpfStatus(curtsy_libbpf_set_map_max_entries(udp, "peer_map", 16));
    try libbpfStatus(curtsy_libbpf_has_program(udp, "udp_verdict"));

    const socket_count: u32 = 7;
    const reuseport = try openBpfObject(embedded_programs.reuseport, null);
    defer curtsy_libbpf_close(reuseport);
    try libbpfStatus(curtsy_libbpf_set_rodata(reuseport, &socket_count, @sizeOf(u32)));
    try libbpfStatus(curtsy_libbpf_has_program(reuseport, "reuseport_select"));
    try testing.expectEqual(
        @as(c_int, @intFromEnum(BPF.ProgType.socket_filter)),
        curtsy_libbpf_program_type(reuseport, "reuseport_select"),
    );

    const target_pid: u32 = 1234;
    const observer = try openBpfObject(embedded_programs.observer, null);
    defer curtsy_libbpf_close(observer);
    try libbpfStatus(curtsy_libbpf_set_rodata(observer, &target_pid, @sizeOf(u32)));
    try libbpfStatus(curtsy_libbpf_has_program(observer, "observe_tcp_sendmsg"));
    try libbpfStatus(curtsy_libbpf_has_program(observer, "observe_udp_recvmsg"));
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
