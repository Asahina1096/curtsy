#ifndef CURTSY_EBPF_COMMON_H
#define CURTSY_EBPF_COMMON_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

#include <bpf/bpf_helpers.h>

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_SOCKHASH 18
#define SK_PASS 1
#define ACTIVITY_REFRESH_NS (10ULL * 1000 * 1000)

struct peer_state {
    __u64 peer_cookie;
    __u64 last_activity_ns;
};

#define CURTSY_SOCKHASH_MAP(name)            \
    struct {                                 \
        __uint(type, BPF_MAP_TYPE_SOCKHASH); \
        __uint(max_entries, 1);              \
        __type(key, __u64);                  \
        __type(value, __u32);                \
    } name SEC(".maps")

#define CURTSY_PEER_MAP(name)           \
    struct {                            \
        __uint(type, BPF_MAP_TYPE_HASH); \
        __uint(max_entries, 1);         \
        __type(key, __u64);             \
        __type(value, struct peer_state); \
    } name SEC(".maps")

static __always_inline int curtsy_sockmap_verdict(
    struct __sk_buff *skb,
    void *sockhash,
    void *peer_map
) {
    __u64 cookie = bpf_get_socket_cookie(skb);
    if (cookie == 0)
        return SK_PASS;

    struct peer_state *state = bpf_map_lookup_elem(peer_map, &cookie);
    if (state == 0)
        return SK_PASS;

    __u64 peer_cookie = state->peer_cookie;
    __u64 now_ns = bpf_ktime_get_coarse_ns();
    if (now_ns - state->last_activity_ns >= ACTIVITY_REFRESH_NS)
        state->last_activity_ns = now_ns;

    return bpf_sk_redirect_hash(skb, sockhash, &peer_cookie, 0);
}

#endif
