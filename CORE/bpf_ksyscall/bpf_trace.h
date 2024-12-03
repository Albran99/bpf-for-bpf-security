#ifndef _BPF_PROGRAM_H
#define _BPF_PROGRAM_H

// Define the structure for BPF_PROG_LOAD (based on man page)
struct bpf_prog_load_attr {
    __u32 prog_type;
    __u32 insn_cnt;
    __u64 insns;
    __u64 license;
    __u32 log_level;
    __u32 log_size;
    __u64 log_buf;
    __u32 kern_version;
    __u32 prog_flags;
    char prog_name[16];
    __u32 prog_ifindex;
    __u32 expected_attach_type;
    __u32 prog_btf_fd;
    __u32 func_info_rec_size;
    __u64 func_info;
    __u32 func_info_cnt;
    __u32 line_info_rec_size;
    __u64 line_info;
    __u32 line_info_cnt;
    __u32 attach_btf_id;
    __u32 attach_prog_fd;
};
#define MAX_BPF_INSNS 32
// Define the structure for passing event data
struct bpf_event {
    __u32 cmd;  // Command type
    __u32 pid;  // Process ID
    union {
        struct bpf_prog_load_attr prog_load;   // Structure for BPF_PROG_LOAD
    } attr;
    __u32 size; // Size of the data
    __u32 uid;  // User ID
    const struct cred *cred;   // Pointer to the cred struct
    __u64 effective_cap;    // Effective capabilities
    __u64 permitted_cap;    // Permitted capabilities
    const struct bpf_insn bpf_prog[MAX_BPF_INSNS];   // BPF program instructions
};




#endif // _BPF_PROGRAM_H