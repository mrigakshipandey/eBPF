// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "execsnoop.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls_sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    u64 id;
    pid_t pid;
    struct event event={0};
    struct task_struct *task;

    // we first obtain the process ID and user ID of the current process
    uid_t uid = (u32)bpf_get_current_uid_gid();
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;

    event.pid = pid;
    event.uid = uid;

    // the we use the helper function bpf_get_current_task() to get the task structure
    task = (struct task_struct*)bpf_get_current_task();
    event.ppid = BPF_CORE_READ(task, real_parent, pid);

    char *cmd_ptr = (char *) BPF_CORE_READ(ctx, args[0]);
        
    // bpf_probe_read_str() function to read the process name.
    bpf_probe_read_str(&event.comm, sizeof(event.comm), cmd_ptr);

    // Finally we sent the even info to the perf buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    /*
    Everytime this function is called we are string a structure's worth of data into the buffer.
    The loader will now loop indefinitely, polling the perf ring buffer. 
    If there is any data available, it would be printed on the terminal.
    */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";