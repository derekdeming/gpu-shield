//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 10240
#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 256

// Event types
#define EVENT_DRIVER_IOCTL 1
#define EVENT_DMA_BUF_MAPPING 2
#define EVENT_PROCESS_START 3
#define EVENT_PROCESS_EXIT 4
#define EVENT_SYSCALL 5
#define EVENT_MODULE_LOAD 6

// GPU driver major numbers (NVIDIA)
#define NVIDIA_MAJOR 195
#define NVIDIA_CTL_MAJOR 195

// Common event structure
struct gpu_event {
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    char comm[MAX_COMM_LEN];
    __u64 data[8]; // Event-specific data
};

// IOCTL event data
struct ioctl_data {
    __u32 major;
    __u32 minor;
    __u32 cmd;
    __u64 arg;
    __s32 ret;
};

// DMA buffer mapping event
struct dma_mapping_data {
    __u64 dma_addr;
    __u64 size;
    __u32 direction;
    __u32 flags;
};

// Process event data
struct process_data {
    __u32 ppid;
    __u32 exit_code;
    char filename[MAX_PATH_LEN];
};

// Syscall event data
struct syscall_data {
    __u64 syscall_nr;
    __u64 args[6];
    __s64 ret;
};

// Module load event data
struct module_data {
    char name[64];
    __u64 base_addr;
    __u64 size;
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} process_start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct process_data);
} process_info SEC(".maps");

// get current task
static __always_inline struct task_struct *get_current_task(void) {
    return (struct task_struct *)bpf_get_current_task();
}

// fill common event fields
static __always_inline void fill_common_event(struct gpu_event *event, __u32 event_type) {
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tid = bpf_get_current_pid_tgid() & 0xffffffff;
    
    __u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = uid_gid & 0xffffffff;
    event->gid = uid_gid >> 32;
    
    event->event_type = event_type;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
}

// Probe for IOCTL calls to GPU drivers
SEC("kprobe/do_vfs_ioctl")
int probe_ioctl(struct pt_regs *ctx) {
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    unsigned int cmd = (unsigned int)PT_REGS_PARM2(ctx);
    unsigned long arg = (unsigned long)PT_REGS_PARM3(ctx);
    
    if (!file)
        return 0;
    
    struct inode *inode;
    if (bpf_core_read(&inode, sizeof(inode), &file->f_inode) < 0)
        return 0;
    
    unsigned int major, minor;
    dev_t rdev;
    if (bpf_core_read(&rdev, sizeof(rdev), &inode->i_rdev) < 0)
        return 0;
    
    major = MAJOR(rdev);
    minor = MINOR(rdev);
    
    // Filter for GPU device files
    if (major != NVIDIA_MAJOR && major != NVIDIA_CTL_MAJOR)
        return 0;
    
    struct gpu_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    fill_common_event(event, EVENT_DRIVER_IOCTL);
    
    struct ioctl_data *ioctl_info = (struct ioctl_data *)event->data;
    ioctl_info->major = major;
    ioctl_info->minor = minor;
    ioctl_info->cmd = cmd;
    ioctl_info->arg = arg;
    ioctl_info->ret = 0; // Will be filled in return probe
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Return probe for IOCTL to capture return value
SEC("kretprobe/do_vfs_ioctl")
int probe_ioctl_ret(struct pt_regs *ctx) {
    long ret = PT_REGS_RC(ctx);
    // just log the return value
    // TODO: we'd correlate with the entry probe
    return 0;
}

// Probe for DMA buffer mapping operations
SEC("kprobe/dma_map_single")
int probe_dma_map(struct pt_regs *ctx) {
    struct device *dev = (struct device *)PT_REGS_PARM1(ctx);
    void *ptr = (void *)PT_REGS_PARM2(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    enum dma_data_direction direction = (enum dma_data_direction)PT_REGS_PARM4(ctx);
    
    if (!dev || size == 0)
        return 0;
    
    // Check if this is a GPU device (simplified check)
    char dev_name[32];
    if (bpf_core_read_str(dev_name, sizeof(dev_name), dev->kobj.name) < 0)
        return 0;
    
    // Look for NVIDIA or AMD GPU devices
    if (!__builtin_memcmp(dev_name, "nvidia", 6) == 0 && 
        !__builtin_memcmp(dev_name, "amdgpu", 6) == 0)
        return 0;
    
    struct gpu_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    fill_common_event(event, EVENT_DMA_BUF_MAPPING);
    
    struct dma_mapping_data *dma_info = (struct dma_mapping_data *)event->data;
    dma_info->dma_addr = (u64)ptr;
    dma_info->size = size;
    dma_info->direction = direction;
    dma_info->flags = 0;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Probe for process creation
SEC("tracepoint/sched/sched_process_fork")
int trace_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 pid = ctx->child_pid;
    __u64 start_time = bpf_ktime_get_ns();
    
    // Store process start time
    bpf_map_update_elem(&process_start_time, &pid, &start_time, BPF_ANY);
    
    struct gpu_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    fill_common_event(event, EVENT_PROCESS_START);
    
    struct process_data *proc_info = (struct process_data *)event->data;
    proc_info->ppid = ctx->parent_pid;
    proc_info->exit_code = 0;
    
    // Try to get the executable path
    struct task_struct *task = get_current_task();
    if (task) {
        struct mm_struct *mm;
        if (bpf_core_read(&mm, sizeof(mm), &task->mm) == 0 && mm) {
            struct file *exe_file;
            if (bpf_core_read(&exe_file, sizeof(exe_file), &mm->exe_file) == 0 && exe_file) {
                struct path path;
                if (bpf_core_read(&path, sizeof(path), &exe_file->f_path) == 0) {
                    struct dentry *dentry;
                    if (bpf_core_read(&dentry, sizeof(dentry), &path.dentry) == 0) {
                        bpf_core_read_str(proc_info->filename, sizeof(proc_info->filename), 
                                        dentry->d_name.name);
                    }
                }
            }
        }
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Probe for process exit
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 pid = ctx->pid;
    
    struct gpu_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    fill_common_event(event, EVENT_PROCESS_EXIT);
    
    struct process_data *proc_info = (struct process_data *)event->data;
    proc_info->ppid = 0;
    
    // Get exit code from task struct
    struct task_struct *task = get_current_task();
    if (task) {
        int exit_code;
        if (bpf_core_read(&exit_code, sizeof(exit_code), &task->exit_code) == 0) {
            proc_info->exit_code = exit_code;
        }
    }
    
    // Clean up process start time
    bpf_map_delete_elem(&process_start_time, &pid);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Probe for suspicious system calls
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 syscall_nr = ctx->id;
    
    // Monitor specific syscalls that might be used for GPU attacks
    // mmap, mprotect, ptrace, etc.
    if (syscall_nr != __NR_mmap && 
        syscall_nr != __NR_mprotect && 
        syscall_nr != __NR_ptrace &&
        syscall_nr != __NR_ioctl)
        return 0;
    
    struct gpu_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    fill_common_event(event, EVENT_SYSCALL);
    
    struct syscall_data *syscall_info = (struct syscall_data *)event->data;
    syscall_info->syscall_nr = syscall_nr;
    
    // Copy syscall arguments
    for (int i = 0; i < 6; i++) {
        syscall_info->args[i] = ctx->args[i];
    }
    syscall_info->ret = 0; // Will be filled in exit probe
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Probe for kernel module loading
SEC("kprobe/do_init_module")
int probe_module_load(struct pt_regs *ctx) {
    struct module *mod = (struct module *)PT_REGS_PARM1(ctx);
    
    if (!mod)
        return 0;
    
    struct gpu_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    fill_common_event(event, EVENT_MODULE_LOAD);
    
    struct module_data *mod_info = (struct module_data *)event->data;
    
    // Read module name
    if (bpf_core_read_str(mod_info->name, sizeof(mod_info->name), mod->name) < 0) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    
    // Read module base address and size
    void *module_core;
    if (bpf_core_read(&module_core, sizeof(module_core), &mod->core_layout.base) == 0) {
        mod_info->base_addr = (u64)module_core;
    }
    
    unsigned int core_size;
    if (bpf_core_read(&core_size, sizeof(core_size), &mod->core_layout.size) == 0) {
        mod_info->size = core_size;
    }
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

// Probe for memory protection changes
SEC("kprobe/mprotect_fixup")
int probe_mprotect(struct pt_regs *ctx) {
    struct vm_area_struct *vma = (struct vm_area_struct *)PT_REGS_PARM1(ctx);
    unsigned long start = (unsigned long)PT_REGS_PARM2(ctx);
    unsigned long end = (unsigned long)PT_REGS_PARM3(ctx);
    unsigned long newflags = (unsigned long)PT_REGS_PARM4(ctx);
    
    if (!vma)
        return 0;
    
    // Check if this might be related to GPU memory
    // This is a simplified check - in practice, you'd want more sophisticated detection
    unsigned long size = end - start;
    if (size < 4096) // Ignore small mappings
        return 0;
    
    struct gpu_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    fill_common_event(event, EVENT_SYSCALL);
    
    struct syscall_data *syscall_info = (struct syscall_data *)event->data;
    syscall_info->syscall_nr = __NR_mprotect;
    syscall_info->args[0] = start;
    syscall_info->args[1] = size;
    syscall_info->args[2] = newflags;
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
