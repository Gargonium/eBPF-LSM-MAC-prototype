cmake_minimum_required(VERSION 4.2)
project(eBPF_LSM_Access_control_system_prototype C)

set(CMAKE_C_STANDARD 11)

add_executable(eBPF_LSM_Access_control_system_prototype block_connect.bpf.c
        loader.c
        lsm_connect.bpf.c
        loader_lsm.c)
