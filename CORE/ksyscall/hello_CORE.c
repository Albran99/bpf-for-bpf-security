#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "hello_CORE.skel.h"

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

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz){
    struct data_t *event = data;
    printf("pid: %d, uid: %d, comm: %s, message: %s, path: %s\n", event->pid, event->uid, event->comm, event->message, event->path);
}

void lost_event(void *ctx, int cpu, __u64 cnt){
    printf("Lost %lld events\n", cnt);
}

int main(){
    struct hello_CORE_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    skel = hello_CORE_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = hello_CORE_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        hello_CORE_bpf__destroy(skel);
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8,  handle_event, lost_event, NULL, NULL);
    if (pb == NULL) {
        fprintf(stderr, "Failed to create perf buffer\n");
        hello_CORE_bpf__destroy(skel);
        return 1;
    }

    while (true) {
        err = perf_buffer__poll(pb, 100);
        if (err == -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
        
    }
    perf_buffer__free(pb);
    hello_CORE_bpf__destroy(skel);
    return -err;
}