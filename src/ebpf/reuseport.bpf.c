#include "common.h"

/* SO_ATTACH_REUSEPORT_EBPF consumes a socket-filter program whose return
 * value is the socket index in the reuseport group. Keep the UAPI layout
 * through hash; this is the same field used by the previous Zig loader. */
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
};

const volatile __u32 socket_count = 1;

SEC("socket")
int reuseport_select(struct __sk_buff *skb) {
    return skb->hash % socket_count;
}

char _license[] SEC("license") = "GPL";
