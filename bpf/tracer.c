#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

//
typedef struct {
    u32 pid;
    u32 saddr; // Source IP
    u32 daddr; // Destination IP
    u16 dport; // Destination Port
    char comm[16]; // Process name
} kray_event_t;
kray_event_t *_force_btf __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, struct sock *);
} socks SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&socks, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret) {
    if (ret != 0) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&socks, &id);
    if (!skp) return 0;
    bpf_map_delete_elem(&socks, &id);

    kray_event_t *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    struct sock *sk = *skp;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";