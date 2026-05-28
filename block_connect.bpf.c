#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Карта запрещённых IPv4-адресов (адрес -> 1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   // IPv4 адрес в network byte order
    __type(value, __u8);
} blocked_ip_map SEC(".maps");

// Карта запрещённых TCP/UDP портов (порт -> 1)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);   // порт в network byte order
    __type(value, __u8);
} blocked_port_map SEC(".maps");

SEC("cgroup/connect4")
int block_connect(struct bpf_sock_addr *ctx)
{
    __u32 dst_ip = ctx->user_ip4;       // IP в network byte order
    __u16 dst_port = ctx->user_port;    // порт в network byte order (старшие байты, т.к. __be16)

    // Проверяем, есть ли IP в чёрном списке
    if (bpf_map_lookup_elem(&blocked_ip_map, &dst_ip))
        return 0;   // reject

    // Проверяем, есть ли порт в чёрном списке
    if (bpf_map_lookup_elem(&blocked_port_map, &dst_port))
        return 0;   // reject

    return 1;   // allow
}

char LICENSE[] SEC("license") = "GPL";