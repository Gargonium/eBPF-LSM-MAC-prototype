#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "block_connect.skel.h"

int main(int argc, char **argv)
{
    struct block_connect_bpf *skel;
    int cgroup_fd;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <cgroup_path> <ip|port> ...\n", argv[0]);
        return 1;
    }

    // Открываем cgroup (нужен файловый дескриптор)
    cgroup_fd = open(argv[1], O_DIRECTORY | O_RDONLY);
    if (cgroup_fd < 0) {
        perror("open cgroup");
        return 1;
    }

    // Загружаем eBPF-программу и карты
    skel = block_connect_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        close(cgroup_fd);
        return 1;
    }

    // Явно прикрепляем программу к cgroup
    struct bpf_program *prog = skel->progs.block_connect;
    struct bpf_link *link = bpf_program__attach_cgroup(prog, cgroup_fd);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach to cgroup: %ld\n", libbpf_get_error(link));
        block_connect_bpf__destroy(skel);
        close(cgroup_fd);
        return 1;
    }

    // Наполняем карты переданными IP/портами (как и раньше)
    for (int i = 2; i < argc; i++) {
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

    printf("eBPF program attached to cgroup %s. Press Ctrl-C to exit.\n", argv[1]);
    while (1) sleep(1);

    // Корректное завершение (недостижимо, но оставим для порядка)
    bpf_link__destroy(link);
    block_connect_bpf__destroy(skel);
    close(cgroup_fd);
    return 0;
}