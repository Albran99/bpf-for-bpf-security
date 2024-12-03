#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MESSAGE_LEN 16
#define PATH_LEN 16

struct data_t {
    int pid;
    int uid;
    char comm[TASK_COMM_LEN];
    char message[MESSAGE_LEN];
    char path[PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct user_message {
    char message[MESSAGE_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct user_message);
    __uint(max_entries, 1024);
} my_config SEC(".maps");

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(hello, const char *pathname){
    struct data_t data = {};
    struct user_message *msg;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_core_read_user_str(&data.path, sizeof(data.path), (const void *)pathname);

    msg = bpf_map_lookup_elem(&my_config, &data.uid);
    if (msg != 0) {
        bpf_probe_read_user_str(&data.message, sizeof(data.message), msg->message);
    }
    else{
        bpf_probe_read_user_str(&data.message, sizeof(data.message), "No message");
    }

    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
    //bpf_printk("Hello from BPF_KPROBE_SYSCALL\n");
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";