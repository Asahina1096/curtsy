#ifndef CURTSY_CBPF_SUPPORT_H
#define CURTSY_CBPF_SUPPORT_H

#include <stddef.h>
#include <stdint.h>

int32_t curtsy_socket_level(void);
int32_t curtsy_so_reuseport(void);
int32_t curtsy_so_attach_reuseport_ebpf(void);
int32_t curtsy_so_cookie(void);

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

void curtsy_sockmap_destroy(curtsy_sockmap_runtime *runtime);

int32_t curtsy_sockmap_pair(
    curtsy_sockmap_runtime *runtime,
    uint64_t client_cookie,
    uint64_t upstream_cookie
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

#endif
