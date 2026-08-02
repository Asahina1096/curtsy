#include "common.h"

struct __sk_buff {
    __u32 len;
};

CURTSY_SOCKHASH_MAP(sockhash);
CURTSY_PEER_MAP(peer_map);

SEC("sk_skb/stream_parser")
int tcp_stream_parser(struct __sk_buff *skb) {
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int tcp_stream_verdict(struct __sk_buff *skb) {
    return curtsy_sockmap_verdict(skb, &sockhash, &peer_map);
}

char _license[] SEC("license") = "GPL";
