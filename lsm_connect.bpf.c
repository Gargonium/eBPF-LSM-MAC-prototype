#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>   
#include <bpf/bpf_core_read.h> 

#ifndef EPERM
#define EPERM 1
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

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

SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    if (address->sa_family != AF_INET)
        return 0;  

    struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
    __u32 dst_ip = 0;
    __u16 dst_port = 0;

    bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), &addr_in->sin_addr.s_addr);
    bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &addr_in->sin_port);

    if (bpf_map_lookup_elem(&blocked_ip_map, &dst_ip))
        return -EPERM;  
    if (bpf_map_lookup_elem(&blocked_port_map, &dst_port))
        return -EPERM;

    return 0;  
}

char LICENSE[] SEC("license") = "GPL";
