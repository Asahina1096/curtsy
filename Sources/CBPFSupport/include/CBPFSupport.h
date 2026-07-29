#ifndef CURTSY_CBPF_SUPPORT_H
#define CURTSY_CBPF_SUPPORT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

int32_t curtsy_socket_level(void);
int32_t curtsy_so_reuseport(void);
int32_t curtsy_so_attach_reuseport_ebpf(void);

int32_t curtsy_load_reuseport_bpf(
    uint32_t socket_count,
    char *verifier_log,
    size_t verifier_log_capacity
);

typedef struct curtsy_sockmap_runtime curtsy_sockmap_runtime;

curtsy_sockmap_runtime *curtsy_sockmap_create(
    uint32_t max_entries,
    char *verifier_log,
    size_t verifier_log_capacity
);

// UDP variant: attaches only a BPF_SK_SKB_VERDICT program (no stream
// parser), which steers whole datagrams between paired connected UDP
// sockets. Requires kernel >= 5.12 for UDP verdict support.
curtsy_sockmap_runtime *curtsy_udp_sockmap_create(
    uint32_t max_entries,
    char *verifier_log,
    size_t verifier_log_capacity
);

void curtsy_sockmap_destroy(curtsy_sockmap_runtime *runtime);

int32_t curtsy_sockmap_pair(
    curtsy_sockmap_runtime *runtime,
    int32_t client_fd,
    int32_t upstream_fd,
    uint64_t *client_cookie,
    uint64_t *upstream_cookie
);

void curtsy_sockmap_unpair(
    curtsy_sockmap_runtime *runtime,
    uint64_t client_cookie,
    uint64_t upstream_cookie
);

int32_t curtsy_sockmap_idle_remaining_ns(
    curtsy_sockmap_runtime *runtime,
    uint64_t client_cookie,
    uint64_t upstream_cookie,
    uint64_t idle_timeout_ns,
    uint64_t *remaining_ns
);

typedef struct curtsy_bpf_observer curtsy_bpf_observer;

typedef struct curtsy_bpf_observer_counters {
    uint64_t tcp_sendmsg;
    uint64_t tcp_recvmsg;
    uint64_t udp_sendmsg;
    uint64_t udp_recvmsg;
} curtsy_bpf_observer_counters;

curtsy_bpf_observer *curtsy_bpf_observer_create(
    uint32_t target_pid,
    char *verifier_log,
    size_t verifier_log_capacity
);

void curtsy_bpf_observer_destroy(curtsy_bpf_observer *observer);

int32_t curtsy_bpf_observer_read(
    curtsy_bpf_observer *observer,
    curtsy_bpf_observer_counters *counters
);

// Batched UDP I/O. One slot describes a single datagram buffer: the caller
// fills data/capacity, recv fills length and the source address.
typedef struct curtsy_udp_slot {
    uint8_t *data;
    uint32_t capacity;
    uint32_t length;
    struct sockaddr_storage address;
    socklen_t address_length;
} curtsy_udp_slot;

// Receives up to max_slots datagrams from fd (nonblocking) into slots.
// Returns the datagram count, 0 when the socket would block, or -1 with
// errno set for other errors.
int32_t curtsy_udp_recv_batch(int fd, curtsy_udp_slot *slots, uint32_t max_slots);

// Sends count datagrams described by slots (data/length only) to address.
// Pass address == NULL for connected sockets. Returns the number of
// datagrams handed to the kernel, or -1 with errno set.
int32_t curtsy_udp_send_batch(
    int fd,
    const struct sockaddr *address,
    socklen_t address_length,
    const curtsy_udp_slot *slots,
    uint32_t count
);

// Minimal event-loop primitives for the batched UDP transport, kept in C so
// the Swift side never touches epoll/eventfd/socket type details.
// All returned fds are nonblocking and close-on-exec; every function returns
// -1 with errno set on failure.

int32_t curtsy_epoll_create(void);
int32_t curtsy_epoll_add(int32_t epoll_fd, int32_t fd);
// Fills ready_fds and returns the number of ready fds (0 on timeout).
int32_t curtsy_epoll_wait(int32_t epoll_fd, int32_t *ready_fds, uint32_t max_fds, int32_t timeout_ms);

int32_t curtsy_eventfd_create(void);
void curtsy_eventfd_signal(int32_t fd);
void curtsy_eventfd_drain(int32_t fd);

// Creates a bound datagram socket for address. Sets SO_REUSEADDR and, for
// AF_INET6, IPV6_V6ONLY. On success the bound address (getsockname) is stored
// in bound/bound_length and the fd is returned.
int32_t curtsy_udp_listen_socket(
    const struct sockaddr *address,
    socklen_t address_length,
    struct sockaddr_storage *bound,
    socklen_t *bound_length
);

// Creates a datagram socket connected to address (default destination).
int32_t curtsy_udp_upstream_socket(const struct sockaddr *address, socklen_t address_length);

// Creates a datagram socket bound to bind_address (SO_REUSEADDR; IPV6_V6ONLY
// for AF_INET6) and connected to peer_address. Used for per-client UDP
// sockets: the kernel demux prefers this connected four-tuple socket over the
// wildcard listener, so the client's datagrams land here once it exists.
int32_t curtsy_udp_connected_client_socket(
    const struct sockaddr *bind_address,
    socklen_t bind_address_length,
    const struct sockaddr *peer_address,
    socklen_t peer_address_length
);

#endif
