#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_trace.h"
#include <linux/errno.h>
#include <linux/string.h>



// Define a map for storing events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} events SEC(".maps");


// Attach to the bpf syscall
SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf_syscall(struct trace_event_raw_sys_enter *ctx) {
    struct bpf_event event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u64 cmd = ctx->args[0];
    void *attr_addr = (void *)ctx->args[1];
    __u64 size = ctx->args[2];

    event.cmd = cmd;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.size = size;
    // get the uid of the process
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // get the cred struct of the process
    bpf_probe_read(&event.cred, sizeof(event.cred), &task->cred);
    // get the effective and permitted capabilities of the process
    bpf_probe_read(&event.effective_cap, sizeof(event.effective_cap), &event.cred->cap_effective);
    bpf_probe_read(&event.permitted_cap, sizeof(event.permitted_cap), &event.cred->cap_permitted);

    // Only handle BPF_PROG_LOAD for this example
    if (cmd == BPF_PROG_LOAD) {
        // Read the user-space memory into the local struct
        if (bpf_probe_read_user(&event.attr.prog_load, sizeof(event.attr.prog_load), attr_addr) != 0) {
            return 0; // Skip if reading fails
        }
        bpf_probe_read_kernel(&event.bpf_prog, sizeof(event.bpf_prog), (void *) event.attr.prog_load.insns);
        
    }

    // Write the event to the ring buffer
    struct bpf_event *ring_event = bpf_ringbuf_reserve(&events, sizeof(event), 0);
    if (ring_event) {
        bpf_probe_read(ring_event, sizeof(*ring_event), &event);
        bpf_ringbuf_submit(ring_event, 0);
    }

    return 0;
}

/*
SEC("lsm/bpf")
int lsm_bpf_filter(struct bpf_prog *prog, union bpf_attr *attr, unsigned int cmd) {
    // get the name of the program
    char prog_name[100];
    int read_size = bpf_probe_read_user_str(prog_name, sizeof(prog_name), attr->prog_name);
    bpf_printk("Program name: %s\n", prog_name);
    if (cmd == BPF_PROG_LOAD && attr->kern_version != 0 && strcmp(prog_name, "bpf_trace")) {  // Intercept BPF_PROG_LOAD commands
        //char prog_name[BPF_OBJ_NAME_LEN];
        bpf_printk("Blocking BPF_PROG_LOAD for program:\n");
        return -EPERM;  // Deny the syscall
    }
    return 0;  // Allow other commands
}
*/
char LICENSE[] SEC("license") = "GPL";