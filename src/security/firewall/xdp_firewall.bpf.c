// SPDX-License-Identifier: GPL-2.0
// Vigil XDP firewall — kernel-level packet filter for Linux.
//
// Compile: clang -target bpf -O2 -g -D__TARGET_ARCH_x86 \
//          -I/usr/include/x86_64-linux-gnu -c xdp_firewall.bpf.c \
//          -o xdp_firewall.bpf.o
//
// Safety guarantees:
//   1. Default action is XDP_PASS — nothing is blocked unless explicitly
//      added to the blocked_ips map.
//   2. Auto-disable heartbeat — if Vigil's userspace process stops beating
//      for >auto_disable_timeout_secs, ALL traffic passes.
//   3. Only TCP and UDP are filtered — ICMP, ARP, and other protocols
//      always pass (preserving network diagnostics).
//   4. Loopback traffic is NOT filtered (XDP attaches to physical interfaces
//      only; lo is never targeted).
//   5. The block map starts empty — a newly loaded program passes everything.
//
// Maps:
//   blocked_ips  — hash: IPv4 addr → 1 (blocked). 10000 max entries.
//   config       — array: [0]=last_heartbeat_secs, [1]=auto_disable_timeout_secs

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u8);
} blocked_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} config SEC(".maps");

// ── Auto-disable: if heartbeat is stale, PASS everything ─────────────────────

static __always_inline int is_timeout_disabled(void) {
    __u32 k = 1;
    __u64 *timeout = bpf_map_lookup_elem(&config, &k);
    if (!timeout || *timeout == 0) return 0;

    k = 0;
    __u64 *hb = bpf_map_lookup_elem(&config, &k);
    if (!hb) return 1; // can't read heartbeat → safe to disable

    __u64 now = bpf_ktime_get_ns() / 1000000000ULL;
    if (now > *hb + *timeout) return 1;
    return 0;
}

// ── IPv4 filtering ───────────────────────────────────────────────────────────

static __always_inline int check_ip4(struct xdp_md *ctx, struct iphdr *iph) {
    // Only filter TCP and UDP
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Block outbound to blacklisted IPs
    __u32 daddr = iph->daddr;
    if (bpf_map_lookup_elem(&blocked_ips, &daddr)) return XDP_DROP;

    // Block inbound from blacklisted IPs (reply traffic)
    __u32 saddr = iph->saddr;
    if (bpf_map_lookup_elem(&blocked_ips, &saddr)) return XDP_DROP;

    return XDP_PASS;
}

// ── IPv6 filtering ──────────────────────────────────────────────────────────

// IPv6 filtering disabled by default — would require storing 128-bit keys.
// IPv6 traffic always passes.  Users should rely on iptables/nftables for
// IPv6 filtering until a future XDP extension adds IPv6 map support.

// ── Main XDP entry point ────────────────────────────────────────────────────

SEC("xdp")
int vigil_xdp_firewall(struct xdp_md *ctx) {
    // Safety guard: if userspace heartbeat is dead, pass everything.
    if (is_timeout_disabled()) return XDP_PASS;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 proto = eth->h_proto;

    // IPv4
    if (proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end) return XDP_PASS;
        return check_ip4(ctx, ip);
    }

    // IPv6 — pass through for now
    if (proto == __constant_htons(ETH_P_IPV6)) {
        return XDP_PASS;
    }

    // Everything else passes (ARP, etc.)
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
