// eBPF tracepoint: sock:inet_sock_set_state
// Reports TCP state transitions in real time.
//
// Compile:
//   clang -target bpf -O2 -g -D__TARGET_ARCH_x86 \
//     -I/usr/include/x86_64-linux-gnu \
//     -c ebpf_tcp_state.bpf.c -o ebpf_tcp_state.bpf.o
//
// Then generate Rust bytecode:
//   python3 -c "
//     data = open('ebpf_tcp_state.bpf.o', 'rb').read()
//     lines = []
//     for i in range(0, len(data), 12):
//       chunk = data[i:i+12]
//       hex_str = ', '.join(f'0x{b:02x}' for b in chunk)
//       lines.append('    ' + hex_str + ',')
//     print('/// Pre-compiled eBPF object for sock:inet_sock_set_state tracepoint.')
//     print('pub const BPF_OBJ: &[u8] = &[')
//     print(chr(10).join(lines))
//     print('];')
//   " > ebpf_bytecode.rs

#ifndef __BPF__
#define __BPF__
#endif

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Output event sent to userspace.
struct tcp_event {
    __u32 pid;
    __u16 family;
    __u16 sport;
    __u16 dport;
    __u16 _pad;
    __u32 saddr;
    __u32 daddr;
    __u8  saddr_v6[16];
    __u8  daddr_v6[16];
    int oldstate;
    int newstate;
};

// Ring buffer for events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Tracepoint context matching kernel ABI.
// See: /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
struct inet_sock_set_state_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    const void *skaddr;
    int oldstate;
    int newstate;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u16 protocol;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct inet_sock_set_state_ctx *ctx)
{
    // Only TCP (protocol == 6).
    if (ctx->protocol != 6)
        return 0;

    struct tcp_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->family = ctx->family;
    e->sport = ctx->sport;
    e->dport = ctx->dport;
    e->oldstate = ctx->oldstate;
    e->newstate = ctx->newstate;

    __builtin_memcpy(&e->saddr, ctx->saddr, 4);
    __builtin_memcpy(&e->daddr, ctx->daddr, 4);
    __builtin_memcpy(e->saddr_v6, ctx->saddr_v6, 16);
    __builtin_memcpy(e->daddr_v6, ctx->daddr_v6, 16);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
