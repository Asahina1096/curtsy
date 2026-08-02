#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

const volatile __u32 target_pid = 0;

static __always_inline int count_call(__u32 index) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (pid != target_pid)
        return 0;

    __u64 *counter = bpf_map_lookup_elem(&counters, &index);
    if (counter != 0)
        __sync_fetch_and_add(counter, 1);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int observe_tcp_sendmsg(void *ctx) {
    (void)ctx;
    return count_call(0);
}

SEC("kprobe/tcp_recvmsg")
int observe_tcp_recvmsg(void *ctx) {
    (void)ctx;
    return count_call(1);
}

SEC("kprobe/udp_sendmsg")
int observe_udp_sendmsg(void *ctx) {
    (void)ctx;
    return count_call(2);
}

SEC("kprobe/udp_recvmsg")
int observe_udp_recvmsg(void *ctx) {
    (void)ctx;
    return count_call(3);
}

char _license[] SEC("license") = "GPL";
