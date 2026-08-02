#include "common.h"

CURTSY_SOCKHASH_MAP(sockhash);
CURTSY_PEER_MAP(peer_map);

SEC("sk_skb")
int udp_verdict(struct __sk_buff *skb) {
    return curtsy_sockmap_verdict(skb, &sockhash, &peer_map);
}

char _license[] SEC("license") = "GPL";
