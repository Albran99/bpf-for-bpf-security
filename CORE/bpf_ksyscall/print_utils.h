#ifndef _BPF_PRINT_UTILS_H
#define _BPF_PRINT_UTILS_H

#include <stdio.h>
#include <linux/capability.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <signal.h>
#include "bpf_trace.h"

static const char *capability_names[] = {
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
    "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
    "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", 
    "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE"
};


const char *bpf_cmd_name(int cmd) {
    switch (cmd) {
        case BPF_MAP_CREATE: return "BPF_MAP_CREATE";
        case BPF_MAP_LOOKUP_ELEM: return "BPF_MAP_LOOKUP_ELEM";
        case BPF_MAP_UPDATE_ELEM: return "BPF_MAP_UPDATE_ELEM";
        case BPF_MAP_DELETE_ELEM: return "BPF_MAP_DELETE_ELEM";
        case BPF_PROG_LOAD: return "BPF_PROG_LOAD";
        case BPF_OBJ_PIN: return "BPF_OBJ_PIN";
        case BPF_BTF_LOAD: return "BPF_BTF_LOAD";
        default: return "UNKNOWN";
    }
}

void print_program_type(unsigned int prog_type) {
    printf("  - Type: %s\n", 
    prog_type == BPF_PROG_TYPE_SOCKET_FILTER ? "Socket Filter" :
    prog_type == BPF_PROG_TYPE_KPROBE ? "Kprobe" : 
    prog_type == BPF_PROG_TYPE_SCHED_CLS ? "Scheduler Classifier" :
    prog_type == BPF_PROG_TYPE_SCHED_ACT ? "Scheduler Action" :
    prog_type == BPF_PROG_TYPE_TRACEPOINT ? "Tracepoint" : 
    prog_type == BPF_PROG_TYPE_XDP ? "XDP" :
    prog_type == BPF_PROG_TYPE_PERF_EVENT ? "Perf Event" :
    prog_type == BPF_PROG_TYPE_CGROUP_SKB ? "Cgroup SKB" :
    prog_type == BPF_PROG_TYPE_CGROUP_SOCK ? "Cgroup Socket" :
    prog_type == BPF_PROG_TYPE_LWT_IN ? "LWT Ingress" :
    prog_type == BPF_PROG_TYPE_LWT_OUT ? "LWT Egress" :
    prog_type == BPF_PROG_TYPE_LWT_XMIT ? "LWT Xmit" :
    prog_type == BPF_PROG_TYPE_SOCK_OPS ? "Socket Ops" :
    prog_type == BPF_PROG_TYPE_SK_SKB ? "SKB Socket" :
    prog_type == BPF_PROG_TYPE_CGROUP_DEVICE ? "Cgroup Device" :
    prog_type == BPF_PROG_TYPE_SK_MSG ? "SK Msg" :
    prog_type == BPF_PROG_TYPE_RAW_TRACEPOINT ? "Raw Tracepoint" :
    prog_type == BPF_PROG_TYPE_CGROUP_SOCK_ADDR ? "Cgroup Socket Addr" :
    prog_type == BPF_PROG_TYPE_LWT_SEG6LOCAL ? "LWT Seg6local" :
    prog_type == BPF_PROG_TYPE_LIRC_MODE2 ? "LIRC Mode2" :
    prog_type == BPF_PROG_TYPE_SK_REUSEPORT ? "SK Reuseport" :
    prog_type == BPF_PROG_TYPE_FLOW_DISSECTOR ? "Flow Dissector" :
    prog_type == BPF_PROG_TYPE_CGROUP_SYSCTL ? "Cgroup Sysctl" :
    prog_type == BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE ? "Raw Tracepoint Writable" :
    prog_type == BPF_PROG_TYPE_CGROUP_SOCKOPT ? "Cgroup Socket Option" :
    prog_type == BPF_PROG_TYPE_TRACING ? "Tracing" :
    prog_type == BPF_PROG_TYPE_STRUCT_OPS ? "Struct Ops" :
    prog_type == BPF_PROG_TYPE_EXT ? "Ext" :
    prog_type == BPF_PROG_TYPE_LSM ? "LSM" :
    prog_type == BPF_PROG_TYPE_SK_LOOKUP ? "SK Lookup" :
    prog_type == BPF_PROG_TYPE_SYSCALL ? "Syscall" :
    prog_type == BPF_PROG_TYPE_NETFILTER ? "Netfilter" :
    prog_type == BPF_PROG_TYPE_UNSPEC ? "Unspecified" :
    "Unknown");
    return;
}

void print_bpf_prog_load_attr(struct bpf_prog_load_attr *attr) {
    // extract the kernel version
    __u32 version = attr->kern_version;
    __u32 major = (version >> 16) & 0xFF;
    __u32 minor = (version >> 8) & 0xFF;
    __u32 patch = version & 0xFF;
    
    printf("  Prog Type: %u\n", attr->prog_type);
    print_program_type(attr->prog_type);
    printf("  Instruction Count: %u\n", attr->insn_cnt);
    printf("  Instructions Pointer: %p\n", attr->insns);
    printf("  License Pointer: %p\n", attr->license);
    printf("  Log Level: %u\n", attr->log_level);
    printf("  Log Size: %u bytes\n", attr->log_size);
    printf("  Log Buffer Pointer: 0x%llx\n", attr->log_buf);
    printf("Kernel Version: %u.%u.%u\n", major, minor, patch);
    printf("  Program Flags: 0x%x\n", attr->prog_flags);
    printf("  Program Name: %.*s\n", (int)sizeof(attr->prog_name), attr->prog_name);
    printf("  Program Ifindex: %u\n", attr->prog_ifindex);
    printf("  Expected Attach Type: %u\n", attr->expected_attach_type);
    printf("  Program BTF FD: %u\n", attr->prog_btf_fd);
    printf("  Function Info Rec Size: %u\n", attr->func_info_rec_size);
    printf("  Function Info Pointer: 0x%llx\n", attr->func_info);
    printf("  Function Info Count: %u\n", attr->func_info_cnt);
    printf("  Line Info Rec Size: %u\n", attr->line_info_rec_size);
    printf("  Line Info Pointer: 0x%llx\n", attr->line_info);
    printf("  Line Info Count: %u\n", attr->line_info_cnt);
    printf("  Attach BTF ID: %u\n", attr->attach_btf_id);
    printf("  Attach Prog FD: %u\n", attr->attach_prog_fd);
}

// Decode and print capabilities
void print_capabilities(uint64_t effective_cap) {
    printf("Effective Capabilities: 0x%llx\n", effective_cap);

    for (int i = 0; i <= 40; i++) {
        if (effective_cap & (1ULL << i)) {
            printf("  - %s\n", capability_names[i]);
        }
    }
}

bool check_capability(uint64_t effective_caps, int capability) {
    if (effective_caps & (1ULL << capability)) {
        printf("Capability %d is enabled\n", capability);
        return true;
    } else {
        printf("Capability %d is NOT enabled\n", capability);
        return false;
    }
}

#endif // _BPF_PRINT_UTILS_H