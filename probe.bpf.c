#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <string.h>
#include "probe.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

long ringbuffer_flags = 0;

/*
SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx, void * pic )

{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    id = bpf_get_current_uid_gid();
    __u32 uid = id >> 32;

    proc_info *process;
    // Reserve space on the ringbuffer for the sample
    process = bpf_ringbuf_reserve(&events, sizeof(proc_info), ringbuffer_flags);
    if (!process) {
        return 0;
    }

    process->pid = tgid;
    process->uid = uid; 
    strcpy(process->msg, "execve event!!!!!!");
    bpf_get_current_comm(&process->comm, 200);
    bpf_ringbuf_submit(process, ringbuffer_flags);
    return 0;
}
*/

SEC("kprobe/vfs_rename")
int kprobe__vfs_rename(struct pt_regs *ctx)
{
    char OPRN[10] = "WRITE";

    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    id = bpf_get_current_uid_gid();
    __u32 uid = id >> 32;

    proc_file_info *process;
    // Reserve space on the ringbuffer for output 
    process = bpf_ringbuf_reserve(&events, sizeof(proc_info), ringbuffer_flags);
    if (!process) {
        return 0;
    }

    process->pid = tgid;
    process->uid = uid; 
    strcpy(process->msg, "file rename event!!!!!!");
    bpf_get_current_comm(&process->comm, 200);
    bpf_ringbuf_submit(process, ringbuffer_flags);
    return 0;
}