/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define MAX_UDP_LENGTH 1480

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") redirect_params = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = ETH_ALEN,
	.value_size = ETH_ALEN,
	.max_entries = 1,
};

/*
 * Destination information is stored in a hash map.
 */
struct dest_info {
   __u32 daddr;
   __u16 dport;
   __u16 padding;
};

/*
 * Token forwading table. This table is used to map the token to the destination
 */
struct bpf_map_def SEC("maps") forward_params = {
   .type = BPF_MAP_TYPE_HASH,
   .key_size = 8,
   .value_size = sizeof(struct dest_info),
   .max_entries = 4096,
};

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

/*
 * The icmp_checksum_diff function takes pointers to old and new structures and
 * the old checksum and returns the new checksum.  It uses the bpf_csum_diff
 * helper to compute the checksum difference. Note that the sizes passed to the
 * bpf_csum_diff helper should be multiples of 4, as it operates on 32-bit
 * words.
 */
static __always_inline __u16 icmp_checksum_diff(
		__u16 seed,
		struct icmphdr_common *icmphdr_new,
		struct icmphdr_common *icmphdr_old)
{
	__u32 csum, size = sizeof(struct icmphdr_common);

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}


static __always_inline __u16 csum16_add(__u16 csum, __u16 addend)
{
	 csum += addend;
	 return csum + (csum < addend);
}

__attribute__((__always_inline__))
static inline __u16 csum_fold_helper64(__u64 csum) {
  int i;
  #pragma unroll
  for (i = 0; i < 4; i ++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }
  return ~csum;
}

__attribute__((__always_inline__))
static inline void update_csum(__u64 *csum, __be32 old_addr,__be32 new_addr ) {
    // ~HC 
    *csum = ~*csum;
    *csum = *csum & 0xffff;
    // + ~m
    __u32 tmp;
    tmp = ~old_addr;
    *csum += tmp;
    // + m
    *csum += new_addr;
    // then fold and complement result ! 
    *csum = csum_fold_helper64(*csum);
}


/*
 * Solution to the redirect UDP packet based on fingerprints token.
 */
SEC("xdp_patch_ports")
int xdp_patch_ports_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	struct tokenhdr *tokenhdr;
	struct dest_info *tnl;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	unsigned char *dst;
	struct hdr_cursor nh;
	__u64 tokenkey;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
	    dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
	    if (!dst)
		    goto out;
		/* Set a proper destination address, in GCP VPC works as proxy gateway mode, any packet will send the the subnet gateway MAC */
		eth->h_source[0] = 0x42;
        eth->h_source[1] = 0x01;
        eth->h_source[2] = 0xc0;
        eth->h_source[3] = 0xa8;
        eth->h_source[4] = 0x01;
        eth->h_source[5] = 0x04;
	    memcpy(eth->h_dest, dst, ETH_ALEN);
	    action = bpf_redirect_map(&tx_port, 0, 0);
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_PASS;
			goto out;
		} else {
            action = XDP_PASS;
            goto out;
        }
	}
        
	if (parse_tokenhdr(&nh, data_end, &tokenhdr) < 0) {
		action = XDP_ABORTED;
		goto out;
	}
        
	tokenkey = tokenhdr->token;
        tnl = bpf_map_lookup_elem(&forward_params, &tokenkey);
	if (!tnl) {
		action = XDP_DROP;
                goto out;
	} else {
	    iphdr = data + 14;
		if (iphdr + 1 > data_end)
            return -1;
		__be32 n0 = iphdr->daddr;
		__be32 n1 = tnl->daddr;
	    __u64 cs = iphdr->check;
		__u16 m0 = iphdr->daddr & 0xffff;
		__u16 m1 = iphdr->daddr >> 16;
		update_csum(&cs, n0, n1);
		iphdr->check = cs;
		iphdr->daddr = tnl->daddr;
		udphdr = data + 34;
		if (udphdr + 1 > data_end)
			return -1;
		__u16 m2 = iphdr->daddr & 0xffff;
		udphdr->check = ~(csum16_add(csum16_add(~udphdr->check, ~m0), m2));
		m2 = iphdr->daddr >> 16;
		udphdr->check = ~(csum16_add(csum16_add(~udphdr->check, ~m1), m2));
	}


out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
