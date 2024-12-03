
#include "print_utils.h"
#include "bpf_trace.skel.h"

void print_bpf_instructions(struct bpf_insn *insns, __u32 cnt) {
    for (__u32 i = 0; i < cnt; i++) {
        printf("Insn %u: code=0x%x, dst_reg=%u, src_reg=%u, off=%d, imm=0x%x\n",
               i, insns[i].code, insns[i].dst_reg, insns[i].src_reg,
               insns[i].off, insns[i].imm);
    }
}

static int handle_event(void * ctx, void * data, size_t data_sz){
    struct bpf_event * event = data;
    printf("Event: cmd=%s, pid=%u, size=%u, cred=%p, effective_cap=%llu, permitted_cap=%llu\n",
        bpf_cmd_name(event->cmd), event->pid, event->size, event->cred, event->effective_cap, event->permitted_cap);
    print_capabilities(event->effective_cap);
    print_capabilities(event->permitted_cap);
    if(event->cmd == BPF_PROG_LOAD && event->attr.prog_load.kern_version != 0){
        print_bpf_prog_load_attr(&event->attr.prog_load);
        // get this process ID
        if (event->attr.prog_load.insn_cnt > 0) {
            printf("BPF Instructions:\n");
            //print_bpf_instructions(event->attr.prog_load.insns, event->attr.prog_load.insn_cnt);
        }
        pid_t pid = getpid();
        if(pid != event->pid && event->attr.prog_load.prog_type != BPF_PROG_TYPE_XDP){
            if(check_capability(event->effective_cap, CAP_SYS_ADMIN) == 0){
                printf("Killing process %d, program type:%i\n", event->pid, event->attr.prog_load.prog_type);
                kill(event->pid, SIGKILL);
            }
            printf("Killing process %d, program type:%i\n", event->pid, event->attr.prog_load.prog_type);
            kill(event->pid, SIGKILL);
        }
    }
    
    return 0;
}


int main() {
    struct bpf_trace_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    //signal(SIGINT, sigint_handler);

    skel = bpf_trace_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = bpf_trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        bpf_trace_bpf__destroy(skel);
        return 1;
    }

    printf("BPF program attached. Monitoring bpf syscall...\n");

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Start polling ring buffer (Ctrl+C to exit)\n");
    while (true) {
        err = ring_buffer__poll(rb, -1);
        if (err == -EINTR) continue;
        if (err < 0) {
            fprintf(stderr, "Error polling buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_trace_bpf__destroy(skel);
    return 0;
}