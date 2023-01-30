//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h> 
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include "simple.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

long ringbuffer_flags = 0;

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx)

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
    bpf_get_current_comm(&process->comm, 100);
    bpf_ringbuf_submit(process, ringbuffer_flags);
    return 0;
}



SEC("kprobe/vfs_write")
int kprobe__vfs_write(struct pt_regs *ctx, struct file *file, char __user *buf, size_t count)
{
    char OPRN[10] = "WRITE";

    if (!(file->f_op->write_iter)) return 0;


    //return common(ctx, file->f_path.dentry, OPRN);

    struct dentry * de;
    de=file->f_path.dentry;
    if (de->d_name.len == 0) return 0;

    u32 inode = de->d_inode->i_ino;
    u32 *inode_ptr = inodemap.lookup(&inode);
    if (inode_ptr != 0) {
        goto RUN;
    }
    return 0;
    
    RUN:;
        struct data_t data = {};
        

        struct qstr d_name = de->d_name;
        if (d_name.len == 0)
            return 0;

        
        data.pid = bpf_get_current_pid_tgid();
        data.uid = bpf_get_current_uid_gid();

        bpf_trace_printk("a file is being written!")
        return 0;
}
