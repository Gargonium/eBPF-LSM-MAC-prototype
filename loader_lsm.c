#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "lsm_connect.skel.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ip|port> ...\n", argv[0]);
        return 1;
    }

    struct lsm_connect_bpf *skel = lsm_connect_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    int err = lsm_connect_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach LSM program\n");
        lsm_connect_bpf__destroy(skel);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        struct in_addr ip;
        if (inet_pton(AF_INET, argv[i], &ip) == 1) {
            __u32 key = ip.s_addr;
            __u8 val = 1;
            bpf_map__update_elem(skel->maps.blocked_ip_map, &key, sizeof(key),
                                 &val, sizeof(val), BPF_ANY);
            printf("Blocked IP: %s\n", argv[i]);
            continue;
        }
        int port = atoi(argv[i]);
        if (port > 0 && port < 65536) {
            __u16 key = htons((uint16_t)port);
            __u8 val = 1;
            bpf_map__update_elem(skel->maps.blocked_port_map, &key, sizeof(key),
                                 &val, sizeof(val), BPF_ANY);
            printf("Blocked port: %d\n", port);
        }
    }

    printf("LSM filter active globally. Press Ctrl-C to exit.\n");
    while (1) sleep(1);

    lsm_connect_bpf__destroy(skel);
    return 0;
}
