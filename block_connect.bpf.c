#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);  
    __type(value, __u8);
} blocked_ip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);   
    __type(value, __u8);
} blocked_port_map SEC(".maps");

SEC("cgroup/connect4")
int block_connect(struct bpf_sock_addr *ctx)
{
    __u32 dst_ip = ctx->user_ip4;       
    __u16 dst_port = ctx->user_port;    

    if (bpf_map_lookup_elem(&blocked_ip_map, &dst_ip))
        return 0;   

    if (bpf_map_lookup_elem(&blocked_port_map, &dst_port))
        return 0;  

    return 1;  
}

char LICENSE[] SEC("license") = "GPL";
