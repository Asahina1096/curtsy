#define _GNU_SOURCE

#include "CBPFSupport.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

int32_t curtsy_socket_level(void) {
    return SOL_SOCKET;
}

int32_t curtsy_so_reuseport(void) {
    return SO_REUSEPORT;
}

#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct curtsy_sockmap_runtime {
    int sockhash_fd;
    int peer_fd;
    int parser_fd;
    int program_fd;
    int verdict_attach_type;
};

struct curtsy_peer_state {
    uint64_t peer_cookie;
    uint64_t last_activity_ns;
};

static int curtsy_bpf(enum bpf_cmd command, union bpf_attr *attributes) {
    return (int)syscall(SYS_bpf, command, attributes, sizeof(*attributes));
}

static int curtsy_create_map(
    enum bpf_map_type type,
    uint32_t key_size,
    uint32_t value_size,
    uint32_t max_entries,
    const char *name
) {
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.map_type = type;
    attributes.key_size = key_size;
    attributes.value_size = value_size;
    attributes.max_entries = max_entries;
    strncpy(attributes.map_name, name, BPF_OBJ_NAME_LEN - 1);
    return curtsy_bpf(BPF_MAP_CREATE, &attributes);
}

static int curtsy_map_update(int map_fd, const void *key, const void *value) {
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.map_fd = (uint32_t)map_fd;
    attributes.key = (uint64_t)(uintptr_t)key;
    attributes.value = (uint64_t)(uintptr_t)value;
    attributes.flags = BPF_ANY;
    return curtsy_bpf(BPF_MAP_UPDATE_ELEM, &attributes);
}

static int curtsy_map_lookup(int map_fd, const void *key, void *value) {
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.map_fd = (uint32_t)map_fd;
    attributes.key = (uint64_t)(uintptr_t)key;
    attributes.value = (uint64_t)(uintptr_t)value;
    return curtsy_bpf(BPF_MAP_LOOKUP_ELEM, &attributes);
}

static void curtsy_map_delete(int map_fd, const void *key) {
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.map_fd = (uint32_t)map_fd;
    attributes.key = (uint64_t)(uintptr_t)key;
    (void)curtsy_bpf(BPF_MAP_DELETE_ELEM, &attributes);
}

static int curtsy_get_socket_cookie(int socket_fd, uint64_t *cookie) {
    socklen_t cookie_length = sizeof(*cookie);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_COOKIE, cookie, &cookie_length) != 0) {
        return -1;
    }
    if (cookie_length != sizeof(*cookie) || *cookie == 0) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

#define CURTSY_INSN(CODE, DST, SRC, OFF, IMM) \
    ((struct bpf_insn){ .code = (CODE), .dst_reg = (DST), .src_reg = (SRC), .off = (OFF), .imm = (IMM) })
#define CURTSY_MOV64_REG(DST, SRC) CURTSY_INSN(BPF_ALU64 | BPF_MOV | BPF_X, DST, SRC, 0, 0)
#define CURTSY_MOV64_IMM(DST, IMM) CURTSY_INSN(BPF_ALU64 | BPF_MOV | BPF_K, DST, 0, 0, IMM)
#define CURTSY_STX_MEM(SIZE, DST, SRC, OFF) CURTSY_INSN(BPF_STX | BPF_MEM | SIZE, DST, SRC, OFF, 0)
#define CURTSY_LDX_MEM(SIZE, DST, SRC, OFF) CURTSY_INSN(BPF_LDX | BPF_MEM | SIZE, DST, SRC, OFF, 0)
#define CURTSY_JMP_IMM(OP, DST, IMM, OFF) CURTSY_INSN(BPF_JMP | OP | BPF_K, DST, 0, OFF, IMM)
#define CURTSY_CALL(FUNC) CURTSY_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, FUNC)
#define CURTSY_EXIT() CURTSY_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
#define CURTSY_LD_MAP_FD(DST, FD) \
    CURTSY_INSN(BPF_LD | BPF_DW | BPF_IMM, DST, BPF_PSEUDO_MAP_FD, 0, FD), \
    CURTSY_INSN(0, 0, 0, 0, 0)

/* Fills instructions with the shared sockmap verdict program: look up the
 * peer by socket cookie, throttle-refresh activity, redirect to the peer's
 * transmit path; fall back to SK_PASS until pairing completes.
 * Returns the instruction count (at most 32). */
static size_t curtsy_fill_verdict_instructions(
    struct bpf_insn *instructions,
    int sockhash_fd,
    int peer_fd
) {
    struct bpf_insn program[] = {
        /* r6 = skb; cookie at fp-8 */
        CURTSY_MOV64_REG(BPF_REG_6, BPF_REG_1),
        CURTSY_CALL(BPF_FUNC_get_socket_cookie),
        CURTSY_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 24),
        CURTSY_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, -8),

        /* state = peer_map[cookie]; peer key at fp-16 */
        CURTSY_LD_MAP_FD(BPF_REG_1, peer_fd),
        CURTSY_MOV64_REG(BPF_REG_2, BPF_REG_10),
        CURTSY_INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -8),
        CURTSY_CALL(BPF_FUNC_map_lookup_elem),
        CURTSY_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 17),
        CURTSY_MOV64_REG(BPF_REG_8, BPF_REG_0),
        CURTSY_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_8, 0),
        CURTSY_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, -16),

        /* Keep the peer cacheline read-mostly; refresh activity at most every 10 ms. */
        CURTSY_LDX_MEM(
            BPF_DW,
            BPF_REG_9,
            BPF_REG_8,
            offsetof(struct curtsy_peer_state, last_activity_ns)
        ),
        CURTSY_CALL(BPF_FUNC_ktime_get_coarse_ns),
        CURTSY_MOV64_REG(BPF_REG_1, BPF_REG_0),
        CURTSY_INSN(BPF_ALU64 | BPF_SUB | BPF_X, BPF_REG_1, BPF_REG_9, 0, 0),
        CURTSY_JMP_IMM(BPF_JLT, BPF_REG_1, 10 * 1000 * 1000, 1),
        CURTSY_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_0, offsetof(struct curtsy_peer_state, last_activity_ns)),

        /* Redirect this received stream to the peer socket's transmit path. */
        CURTSY_MOV64_REG(BPF_REG_1, BPF_REG_6),
        CURTSY_LD_MAP_FD(BPF_REG_2, sockhash_fd),
        CURTSY_MOV64_REG(BPF_REG_3, BPF_REG_10),
        CURTSY_INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_3, 0, 0, -16),
        CURTSY_MOV64_IMM(BPF_REG_4, 0),
        CURTSY_CALL(BPF_FUNC_sk_redirect_hash),
        CURTSY_EXIT(),

        /* No complete pairing: retain the userspace relay fallback. */
        CURTSY_MOV64_IMM(BPF_REG_0, SK_PASS),
        CURTSY_EXIT(),
    };
    size_t count = sizeof(program) / sizeof(program[0]);
    memcpy(instructions, program, sizeof(program));
    return count;
}

static int curtsy_load_verdict_program(
    int sockhash_fd,
    int peer_fd,
    enum bpf_attach_type attach_type,
    const char *program_name,
    char *verifier_log,
    size_t verifier_log_capacity
) {
    struct bpf_insn instructions[32];
    size_t count = curtsy_fill_verdict_instructions(instructions, sockhash_fd, peer_fd);
    static const char license[] = "GPL";

    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.prog_type = BPF_PROG_TYPE_SK_SKB;
    attributes.expected_attach_type = attach_type;
    attributes.insn_cnt = (uint32_t)count;
    attributes.insns = (uint64_t)(uintptr_t)instructions;
    attributes.license = (uint64_t)(uintptr_t)license;
    strncpy(attributes.prog_name, program_name, BPF_OBJ_NAME_LEN - 1);
    if (verifier_log != NULL && verifier_log_capacity > 0) {
        verifier_log[0] = '\0';
        attributes.log_level = 1;
        attributes.log_buf = (uint64_t)(uintptr_t)verifier_log;
        attributes.log_size = verifier_log_capacity > UINT32_MAX
            ? UINT32_MAX
            : (uint32_t)verifier_log_capacity;
    }
    return curtsy_bpf(BPF_PROG_LOAD, &attributes);
}

static int curtsy_load_sockmap_parser(
    char *verifier_log,
    size_t verifier_log_capacity
) {
    struct bpf_insn instructions[] = {
        CURTSY_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, offsetof(struct __sk_buff, len)),
        CURTSY_EXIT(),
    };
    static const char license[] = "GPL";
    static const char program_name[] = "curtsy_parser";

    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.prog_type = BPF_PROG_TYPE_SK_SKB;
    attributes.expected_attach_type = BPF_SK_SKB_STREAM_PARSER;
    attributes.insn_cnt = (uint32_t)(sizeof(instructions) / sizeof(instructions[0]));
    attributes.insns = (uint64_t)(uintptr_t)instructions;
    attributes.license = (uint64_t)(uintptr_t)license;
    memcpy(attributes.prog_name, program_name, sizeof(program_name));
    if (verifier_log != NULL && verifier_log_capacity > 0) {
        verifier_log[0] = '\0';
        attributes.log_level = 1;
        attributes.log_buf = (uint64_t)(uintptr_t)verifier_log;
        attributes.log_size = verifier_log_capacity > UINT32_MAX
            ? UINT32_MAX
            : (uint32_t)verifier_log_capacity;
    }
    return curtsy_bpf(BPF_PROG_LOAD, &attributes);
}

int32_t curtsy_so_attach_reuseport_ebpf(void) {
    return SO_ATTACH_REUSEPORT_EBPF;
}

int32_t curtsy_load_reuseport_bpf(
    uint32_t socket_count,
    char *verifier_log,
    size_t verifier_log_capacity
) {
    if (socket_count == 0) {
        errno = EINVAL;
        return -1;
    }

    struct bpf_insn instructions[] = {
        {
            .code = BPF_LDX | BPF_W | BPF_MEM,
            .dst_reg = BPF_REG_0,
            .src_reg = BPF_REG_1,
            .off = offsetof(struct __sk_buff, hash),
            .imm = 0,
        },
        {
            .code = BPF_ALU | BPF_MOD | BPF_K,
            .dst_reg = BPF_REG_0,
            .src_reg = 0,
            .off = 0,
            .imm = (int32_t)socket_count,
        },
        {
            .code = BPF_JMP | BPF_EXIT,
            .dst_reg = 0,
            .src_reg = 0,
            .off = 0,
            .imm = 0,
        },
    };
    static const char license[] = "GPL";
    static const char program_name[] = "curtsy_reuse";

    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attributes.insn_cnt = (uint32_t)(sizeof(instructions) / sizeof(instructions[0]));
    attributes.insns = (uint64_t)(uintptr_t)instructions;
    attributes.license = (uint64_t)(uintptr_t)license;
    memcpy(attributes.prog_name, program_name, sizeof(program_name));

    if (verifier_log != NULL && verifier_log_capacity > 0) {
        verifier_log[0] = '\0';
        attributes.log_level = 1;
        attributes.log_buf = (uint64_t)(uintptr_t)verifier_log;
        attributes.log_size = verifier_log_capacity > UINT32_MAX
            ? UINT32_MAX
            : (uint32_t)verifier_log_capacity;
    }

    return (int32_t)syscall(SYS_bpf, BPF_PROG_LOAD, &attributes, sizeof(attributes));
}

static curtsy_sockmap_runtime *curtsy_sockmap_create_internal(
    uint32_t max_entries,
    int for_udp,
    char *verifier_log,
    size_t verifier_log_capacity
) {
    if (max_entries == 0) {
        errno = EINVAL;
        return NULL;
    }

    curtsy_sockmap_runtime *runtime = calloc(1, sizeof(*runtime));
    if (runtime == NULL) {
        return NULL;
    }
    runtime->sockhash_fd = -1;
    runtime->peer_fd = -1;
    runtime->parser_fd = -1;
    runtime->program_fd = -1;
    runtime->verdict_attach_type = for_udp ? BPF_SK_SKB_VERDICT : BPF_SK_SKB_STREAM_VERDICT;

    runtime->sockhash_fd = curtsy_create_map(
        BPF_MAP_TYPE_SOCKHASH,
        sizeof(uint64_t),
        sizeof(uint32_t),
        max_entries,
        for_udp ? "curtsy_udpsocks" : "curtsy_socks"
    );
    if (runtime->sockhash_fd < 0) {
        goto failure;
    }
    runtime->peer_fd = curtsy_create_map(
        BPF_MAP_TYPE_HASH,
        sizeof(uint64_t),
        sizeof(struct curtsy_peer_state),
        max_entries,
        for_udp ? "curtsy_udppeer" : "curtsy_peers"
    );
    if (runtime->peer_fd < 0) {
        goto failure;
    }
    if (!for_udp) {
        runtime->parser_fd = curtsy_load_sockmap_parser(verifier_log, verifier_log_capacity);
        if (runtime->parser_fd < 0) {
            goto failure;
        }
    }
    runtime->program_fd = curtsy_load_verdict_program(
        runtime->sockhash_fd,
        runtime->peer_fd,
        (enum bpf_attach_type)runtime->verdict_attach_type,
        for_udp ? "curtsy_udp" : "curtsy_sockmap",
        verifier_log,
        verifier_log_capacity
    );
    if (runtime->program_fd < 0) {
        goto failure;
    }

    if (runtime->parser_fd >= 0) {
        union bpf_attr attributes;
        memset(&attributes, 0, sizeof(attributes));
        attributes.target_fd = (uint32_t)runtime->sockhash_fd;
        attributes.attach_bpf_fd = (uint32_t)runtime->parser_fd;
        attributes.attach_type = BPF_SK_SKB_STREAM_PARSER;
        if (curtsy_bpf(BPF_PROG_ATTACH, &attributes) != 0) {
            goto failure;
        }
    }
    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.target_fd = (uint32_t)runtime->sockhash_fd;
    attributes.attach_bpf_fd = (uint32_t)runtime->program_fd;
    attributes.attach_type = (enum bpf_attach_type)runtime->verdict_attach_type;
    if (curtsy_bpf(BPF_PROG_ATTACH, &attributes) != 0) goto failure;
    return runtime;

failure: {
        int saved_errno = errno;
        curtsy_sockmap_destroy(runtime);
        errno = saved_errno;
        return NULL;
    }
}

curtsy_sockmap_runtime *curtsy_sockmap_create(
    uint32_t max_entries,
    char *verifier_log,
    size_t verifier_log_capacity
) {
    return curtsy_sockmap_create_internal(max_entries, 0, verifier_log, verifier_log_capacity);
}

curtsy_sockmap_runtime *curtsy_udp_sockmap_create(
    uint32_t max_entries,
    char *verifier_log,
    size_t verifier_log_capacity
) {
    return curtsy_sockmap_create_internal(max_entries, 1, verifier_log, verifier_log_capacity);
}

void curtsy_sockmap_destroy(curtsy_sockmap_runtime *runtime) {
    if (runtime == NULL) {
        return;
    }
    if (runtime->program_fd >= 0 && runtime->sockhash_fd >= 0) {
        union bpf_attr attributes;
        memset(&attributes, 0, sizeof(attributes));
        attributes.target_fd = (uint32_t)runtime->sockhash_fd;
        attributes.attach_bpf_fd = (uint32_t)runtime->program_fd;
        attributes.attach_type = (enum bpf_attach_type)runtime->verdict_attach_type;
        (void)curtsy_bpf(BPF_PROG_DETACH, &attributes);
    }
    if (runtime->parser_fd >= 0 && runtime->sockhash_fd >= 0) {
        union bpf_attr attributes;
        memset(&attributes, 0, sizeof(attributes));
        attributes.target_fd = (uint32_t)runtime->sockhash_fd;
        attributes.attach_bpf_fd = (uint32_t)runtime->parser_fd;
        attributes.attach_type = BPF_SK_SKB_STREAM_PARSER;
        (void)curtsy_bpf(BPF_PROG_DETACH, &attributes);
    }
    if (runtime->program_fd >= 0) close(runtime->program_fd);
    if (runtime->parser_fd >= 0) close(runtime->parser_fd);
    if (runtime->peer_fd >= 0) close(runtime->peer_fd);
    if (runtime->sockhash_fd >= 0) close(runtime->sockhash_fd);
    free(runtime);
}

int32_t curtsy_sockmap_pair(
    curtsy_sockmap_runtime *runtime,
    int32_t client_fd,
    int32_t upstream_fd,
    uint64_t *client_cookie_out,
    uint64_t *upstream_cookie_out
) {
    if (runtime == NULL || client_fd < 0 || upstream_fd < 0 ||
        client_cookie_out == NULL || upstream_cookie_out == NULL) {
        errno = EINVAL;
        return -1;
    }

    uint64_t client_cookie = 0;
    uint64_t upstream_cookie = 0;
    if (curtsy_get_socket_cookie(client_fd, &client_cookie) != 0) {
        return -1;
    }
    if (curtsy_get_socket_cookie(upstream_fd, &upstream_cookie) != 0) {
        return -1;
    }
    if (client_cookie == upstream_cookie) {
        errno = EINVAL;
        return -1;
    }

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        goto failure;
    }
    uint64_t timestamp = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
    struct curtsy_peer_state client_state = {
        .peer_cookie = upstream_cookie,
        .last_activity_ns = timestamp,
    };
    struct curtsy_peer_state upstream_state = {
        .peer_cookie = client_cookie,
        .last_activity_ns = timestamp,
    };

    if (curtsy_map_update(runtime->sockhash_fd, &client_cookie, &client_fd) != 0 ||
        curtsy_map_update(runtime->sockhash_fd, &upstream_cookie, &upstream_fd) != 0 ||
        curtsy_map_update(runtime->peer_fd, &client_cookie, &client_state) != 0 ||
        curtsy_map_update(runtime->peer_fd, &upstream_cookie, &upstream_state) != 0) {
        goto failure;
    }

    *client_cookie_out = client_cookie;
    *upstream_cookie_out = upstream_cookie;
    return 0;

failure: {
        int saved_errno = errno;
        curtsy_sockmap_unpair(runtime, client_cookie, upstream_cookie);
        errno = saved_errno;
        return -1;
    }
}

void curtsy_sockmap_unpair(
    curtsy_sockmap_runtime *runtime,
    uint64_t client_cookie,
    uint64_t upstream_cookie
) {
    if (runtime == NULL) {
        return;
    }
    /* Stop redirection first; subsequent data falls through to userspace. */
    curtsy_map_delete(runtime->peer_fd, &client_cookie);
    curtsy_map_delete(runtime->peer_fd, &upstream_cookie);
    curtsy_map_delete(runtime->sockhash_fd, &client_cookie);
    curtsy_map_delete(runtime->sockhash_fd, &upstream_cookie);
}

int32_t curtsy_sockmap_idle_remaining_ns(
    curtsy_sockmap_runtime *runtime,
    uint64_t client_cookie,
    uint64_t upstream_cookie,
    uint64_t idle_timeout_ns,
    uint64_t *remaining_ns
) {
    if (runtime == NULL || remaining_ns == NULL || idle_timeout_ns == 0) {
        errno = EINVAL;
        return -1;
    }
    struct curtsy_peer_state client_state;
    struct curtsy_peer_state upstream_state;
    if (curtsy_map_lookup(runtime->peer_fd, &client_cookie, &client_state) != 0 ||
        curtsy_map_lookup(runtime->peer_fd, &upstream_cookie, &upstream_state) != 0) {
        return -1;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    uint64_t now_ns = (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
    uint64_t latest = client_state.last_activity_ns > upstream_state.last_activity_ns
        ? client_state.last_activity_ns
        : upstream_state.last_activity_ns;
    uint64_t elapsed = now_ns >= latest ? now_ns - latest : 0;
    *remaining_ns = elapsed >= idle_timeout_ns ? 0 : idle_timeout_ns - elapsed;
    return 0;
}


enum curtsy_observer_counter_index {
    CURTSY_OBSERVER_TCP_SENDMSG = 0,
    CURTSY_OBSERVER_TCP_RECVMSG = 1,
    CURTSY_OBSERVER_UDP_SENDMSG = 2,
    CURTSY_OBSERVER_UDP_RECVMSG = 3,
    CURTSY_OBSERVER_COUNTER_COUNT = 4,
};

struct curtsy_bpf_observer {
    int counters_fd;
    int program_fds[CURTSY_OBSERVER_COUNTER_COUNT];
    int *event_fds[CURTSY_OBSERVER_COUNTER_COUNT];
    int event_fd_counts[CURTSY_OBSERVER_COUNTER_COUNT];
};

static int curtsy_perf_event_open(
    struct perf_event_attr *attributes,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags
) {
    return (int)syscall(SYS_perf_event_open, attributes, pid, cpu, group_fd, flags);
}

static int curtsy_read_uint_from_file(const char *path) {
    FILE *file = fopen(path, "r");
    if (file == NULL) return -1;
    int value = -1;
    if (fscanf(file, "%d", &value) != 1) value = -1;
    fclose(file);
    return value;
}

static int curtsy_load_observer_program(
    int counters_fd,
    uint32_t target_pid,
    uint32_t counter_index,
    char *verifier_log,
    size_t verifier_log_capacity
) {
    struct bpf_insn instructions[] = {
        /* Ignore events not caused by this Curtsy process: jump straight to
         * the return-0 tail (instruction 14), not the counter increment. */
        CURTSY_CALL(BPF_FUNC_get_current_pid_tgid),
        CURTSY_INSN(BPF_ALU64 | BPF_RSH | BPF_K, BPF_REG_0, 0, 0, 32),
        CURTSY_JMP_IMM(BPF_JNE, BPF_REG_0, (int32_t)target_pid, 11),

        /* key = counter_index */
        CURTSY_MOV64_REG(BPF_REG_6, BPF_REG_10),
        CURTSY_INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_6, 0, 0, -4),
        CURTSY_MOV64_IMM(BPF_REG_1, counter_index),
        CURTSY_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -4),

        /* counter = counters[key] */
        CURTSY_LD_MAP_FD(BPF_REG_1, counters_fd),
        CURTSY_MOV64_REG(BPF_REG_2, BPF_REG_6),
        CURTSY_CALL(BPF_FUNC_map_lookup_elem),
        CURTSY_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),

        /* (*counter)++ */
        CURTSY_MOV64_IMM(BPF_REG_1, 1),
        CURTSY_INSN(BPF_STX | BPF_XADD | BPF_DW, BPF_REG_0, BPF_REG_1, 0, 0),

        CURTSY_MOV64_IMM(BPF_REG_0, 0),
        CURTSY_EXIT(),
    };
    static const char license[] = "GPL";
    static const char program_name[] = "curtsy_tune";

    union bpf_attr attributes;
    memset(&attributes, 0, sizeof(attributes));
    attributes.prog_type = BPF_PROG_TYPE_KPROBE;
    attributes.insn_cnt = (uint32_t)(sizeof(instructions) / sizeof(instructions[0]));
    attributes.insns = (uint64_t)(uintptr_t)instructions;
    attributes.license = (uint64_t)(uintptr_t)license;
    memcpy(attributes.prog_name, program_name, sizeof(program_name));
    if (verifier_log != NULL && verifier_log_capacity > 0) {
        verifier_log[0] = '\0';
        attributes.log_level = 1;
        attributes.log_buf = (uint64_t)(uintptr_t)verifier_log;
        attributes.log_size = verifier_log_capacity > UINT32_MAX
            ? UINT32_MAX
            : (uint32_t)verifier_log_capacity;
    }
    return curtsy_bpf(BPF_PROG_LOAD, &attributes);
}

// Attaches the program to a kprobe PMU event on every online CPU
// (pid == -1 with cpu == -1 is rejected by perf_event_open). Returns 0 and
// hands the per-CPU event fds to the caller, or -1 with errno set.
static int curtsy_attach_kprobe(
    int program_fd,
    const char *function_name,
    int **event_fds_out,
    int *event_fd_count_out
) {
    int kprobe_type = curtsy_read_uint_from_file("/sys/bus/event_source/devices/kprobe/type");
    if (kprobe_type < 0) {
        errno = ENOTSUP;
        return -1;
    }

    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_count < 1) {
        errno = ENOTSUP;
        return -1;
    }

    int *fds = calloc((size_t)cpu_count, sizeof(int));
    if (fds == NULL) return -1;
    int attached = 0;
    for (long cpu = 0; cpu < cpu_count; cpu++) {
        struct perf_event_attr attributes;
        memset(&attributes, 0, sizeof(attributes));
        attributes.type = (uint32_t)kprobe_type;
        attributes.size = sizeof(attributes);
        attributes.config1 = (uint64_t)(uintptr_t)function_name;
        attributes.sample_period = 1;
        attributes.wakeup_events = 1;

        int event_fd = curtsy_perf_event_open(&attributes, -1, (int)cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (event_fd < 0) goto failure;
        if (ioctl(event_fd, PERF_EVENT_IOC_SET_BPF, program_fd) != 0) {
            int saved_errno = errno;
            close(event_fd);
            errno = saved_errno;
            goto failure;
        }
        if (ioctl(event_fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
            int saved_errno = errno;
            close(event_fd);
            errno = saved_errno;
            goto failure;
        }
        fds[cpu] = event_fd;
        attached++;
    }
    *event_fds_out = fds;
    *event_fd_count_out = attached;
    return 0;

failure: {
        int saved_errno = errno;
        for (int i = 0; i < attached; i++) {
            close(fds[i]);
        }
        free(fds);
        errno = saved_errno;
        return -1;
    }
}

curtsy_bpf_observer *curtsy_bpf_observer_create(
    uint32_t target_pid,
    char *verifier_log,
    size_t verifier_log_capacity
) {
    if (target_pid == 0) {
        errno = EINVAL;
        return NULL;
    }

    curtsy_bpf_observer *observer = calloc(1, sizeof(*observer));
    if (observer == NULL) return NULL;
    observer->counters_fd = -1;
    for (int i = 0; i < CURTSY_OBSERVER_COUNTER_COUNT; i++) {
        observer->program_fds[i] = -1;
    }

    observer->counters_fd = curtsy_create_map(
        BPF_MAP_TYPE_ARRAY,
        sizeof(uint32_t),
        sizeof(uint64_t),
        CURTSY_OBSERVER_COUNTER_COUNT,
        "curtsy_tune"
    );
    if (observer->counters_fd < 0) goto failure;

    static const char *functions[CURTSY_OBSERVER_COUNTER_COUNT] = {
        "tcp_sendmsg",
        "tcp_recvmsg",
        "udp_sendmsg",
        "udp_recvmsg",
    };
    for (uint32_t i = 0; i < CURTSY_OBSERVER_COUNTER_COUNT; i++) {
        observer->program_fds[i] = curtsy_load_observer_program(
            observer->counters_fd,
            target_pid,
            i,
            verifier_log,
            verifier_log_capacity
        );
        if (observer->program_fds[i] < 0) goto failure;
        if (curtsy_attach_kprobe(
                observer->program_fds[i],
                functions[i],
                &observer->event_fds[i],
                &observer->event_fd_counts[i]
            ) != 0) {
            /* The verifier log still holds the successful load output, which
             * is noise at this point; report the failing stage instead. */
            if (verifier_log != NULL && verifier_log_capacity > 0) {
                snprintf(
                    verifier_log,
                    verifier_log_capacity,
                    "stage=kprobe_attach function=%s",
                    functions[i]
                );
            }
            goto failure;
        }
    }
    return observer;

failure: {
        int saved_errno = errno;
        curtsy_bpf_observer_destroy(observer);
        errno = saved_errno;
        return NULL;
    }
}

void curtsy_bpf_observer_destroy(curtsy_bpf_observer *observer) {
    if (observer == NULL) return;
    for (int i = 0; i < CURTSY_OBSERVER_COUNTER_COUNT; i++) {
        for (int j = 0; j < observer->event_fd_counts[i]; j++) {
            close(observer->event_fds[i][j]);
        }
        free(observer->event_fds[i]);
        if (observer->program_fds[i] >= 0) close(observer->program_fds[i]);
    }
    if (observer->counters_fd >= 0) close(observer->counters_fd);
    free(observer);
}

int32_t curtsy_bpf_observer_read(
    curtsy_bpf_observer *observer,
    curtsy_bpf_observer_counters *counters
) {
    if (observer == NULL || counters == NULL) {
        errno = EINVAL;
        return -1;
    }
    uint64_t values[CURTSY_OBSERVER_COUNTER_COUNT] = {0, 0, 0, 0};
    for (uint32_t i = 0; i < CURTSY_OBSERVER_COUNTER_COUNT; i++) {
        if (curtsy_map_lookup(observer->counters_fd, &i, &values[i]) != 0) return -1;
    }
    counters->tcp_sendmsg = values[CURTSY_OBSERVER_TCP_SENDMSG];
    counters->tcp_recvmsg = values[CURTSY_OBSERVER_TCP_RECVMSG];
    counters->udp_sendmsg = values[CURTSY_OBSERVER_UDP_SENDMSG];
    counters->udp_recvmsg = values[CURTSY_OBSERVER_UDP_RECVMSG];
    return 0;
}

int32_t curtsy_udp_recv_batch(int fd, curtsy_udp_slot *slots, uint32_t max_slots) {
    if (slots == NULL || max_slots == 0) {
        errno = EINVAL;
        return -1;
    }
    struct mmsghdr headers[64];
    struct iovec vectors[64];
    if (max_slots > 64) max_slots = 64;
    for (uint32_t i = 0; i < max_slots; i++) {
        vectors[i].iov_base = slots[i].data;
        vectors[i].iov_len = slots[i].capacity;
        headers[i].msg_hdr.msg_name = &slots[i].address;
        headers[i].msg_hdr.msg_namelen = sizeof(slots[i].address);
        headers[i].msg_hdr.msg_iov = &vectors[i];
        headers[i].msg_hdr.msg_iovlen = 1;
        headers[i].msg_hdr.msg_control = NULL;
        headers[i].msg_hdr.msg_controllen = 0;
        headers[i].msg_hdr.msg_flags = 0;
        headers[i].msg_len = 0;
    }
    int received = recvmmsg(fd, headers, max_slots, MSG_DONTWAIT, NULL);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        return -1;
    }
    for (int i = 0; i < received; i++) {
        slots[i].length = headers[i].msg_len;
        slots[i].address_length = headers[i].msg_hdr.msg_namelen;
    }
    return received;
}

int32_t curtsy_udp_send_batch(
    int fd,
    const struct sockaddr *address,
    socklen_t address_length,
    const curtsy_udp_slot *slots,
    uint32_t count
) {
    if (slots == NULL || count == 0) {
        errno = EINVAL;
        return -1;
    }
    struct mmsghdr headers[64];
    struct iovec vectors[64];
    if (count > 64) count = 64;
    for (uint32_t i = 0; i < count; i++) {
        vectors[i].iov_base = slots[i].data;
        vectors[i].iov_len = slots[i].length;
        headers[i].msg_hdr.msg_name = (void *)address;
        headers[i].msg_hdr.msg_namelen = address_length;
        headers[i].msg_hdr.msg_iov = &vectors[i];
        headers[i].msg_hdr.msg_iovlen = 1;
        headers[i].msg_hdr.msg_control = NULL;
        headers[i].msg_hdr.msg_controllen = 0;
        headers[i].msg_hdr.msg_flags = 0;
        headers[i].msg_len = 0;
    }
    int sent = sendmmsg(fd, headers, count, MSG_DONTWAIT);
    if (sent < 0) return -1;
    return sent;
}

int32_t curtsy_epoll_create(void) {
    return epoll_create1(EPOLL_CLOEXEC);
}

int32_t curtsy_epoll_add(int32_t epoll_fd, int32_t fd) {
    struct epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = fd;
    return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event);
}

int32_t curtsy_epoll_wait(
    int32_t epoll_fd,
    int32_t *ready_fds,
    uint32_t max_fds,
    int32_t timeout_ms
) {
    if (ready_fds == NULL || max_fds == 0) {
        errno = EINVAL;
        return -1;
    }
    struct epoll_event events[65];
    if (max_fds > 65) max_fds = 65;
    int ready;
    do {
        ready = epoll_wait(epoll_fd, events, (int)max_fds, (int)timeout_ms);
    } while (ready < 0 && errno == EINTR);
    if (ready < 0) return -1;
    for (int i = 0; i < ready; i++) {
        ready_fds[i] = events[i].data.fd;
    }
    return ready;
}

int32_t curtsy_eventfd_create(void) {
    return eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
}

void curtsy_eventfd_signal(int32_t fd) {
    uint64_t one = 1;
    ssize_t ignored = write(fd, &one, sizeof(one));
    (void)ignored;
}

void curtsy_eventfd_drain(int32_t fd) {
    uint64_t value;
    ssize_t ignored = read(fd, &value, sizeof(value));
    (void)ignored;
}

int32_t curtsy_udp_listen_socket(
    const struct sockaddr *address,
    socklen_t address_length,
    struct sockaddr_storage *bound,
    socklen_t *bound_length
) {
    if (address == NULL) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(address->sa_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0) goto fail;
    // SO_REUSEPORT lets one engine thread per worker bind the same address;
    // the kernel then hashes each client four-tuple to a stable listener.
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) != 0) goto fail;
    if (address->sa_family == AF_INET6) {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) != 0) goto fail;
    }
    if (bind(fd, address, address_length) != 0) goto fail;
    if (bound != NULL && bound_length != NULL) {
        *bound_length = sizeof(*bound);
        if (getsockname(fd, (struct sockaddr *)bound, bound_length) != 0) goto fail;
    }
    return fd;

fail:
    {
        int saved = errno;
        close(fd);
        errno = saved;
    }
    return -1;
}

int32_t curtsy_udp_upstream_socket(const struct sockaddr *address, socklen_t address_length) {
    if (address == NULL) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(address->sa_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (connect(fd, address, address_length) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int32_t curtsy_udp_connected_client_socket(
    const struct sockaddr *bind_address,
    socklen_t bind_address_length,
    const struct sockaddr *peer_address,
    socklen_t peer_address_length
) {
    if (bind_address == NULL || peer_address == NULL ||
        bind_address->sa_family != peer_address->sa_family) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(bind_address->sa_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0) goto fail;
    // Listen sockets carry SO_REUSEPORT; every socket sharing the port must
    // set it too, otherwise this bind fails with EADDRINUSE. Connected
    // sockets never join wildcard delivery: the kernel exact-matches their
    // four-tuple first, so only their peer's datagrams land here.
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes)) != 0) goto fail;
    if (bind_address->sa_family == AF_INET6) {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) != 0) goto fail;
    }
    if (bind(fd, bind_address, bind_address_length) != 0) goto fail;
    if (connect(fd, peer_address, peer_address_length) != 0) goto fail;
    return fd;

fail:
    {
        int saved = errno;
        close(fd);
        errno = saved;
    }
    return -1;
}

// Sets SO_RCVBUF and SO_SNDBUF to bytes on a datagram socket. Without
// CAP_NET_ADMIN the kernel silently clamps each to rmem_max/wmem_max, so an
// oversized request is not an error; genuine failures return -1 with errno.
int32_t curtsy_udp_set_socket_buffers(int32_t fd, int32_t bytes) {
    if (bytes <= 0) {
        errno = EINVAL;
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) != 0) return -1;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof(bytes)) != 0) return -1;
    return 0;
}
