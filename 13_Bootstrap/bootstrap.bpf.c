// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

/* ********************************************************************************************
Required Header Files
******************************************************************************************** */

// standard header files required for eBPF development
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// custom header files defining data structures and maps
#include "bootstrap.h"


/* ********************************************************************************************
License
******************************************************************************************** */
// This is required for many kernel features as they require eBPF programs to follow the GPL license.
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ********************************************************************************************
eBPF Maps
******************************************************************************************** */

// Hash type eBPF map used to store the timestamp when a process starts executing
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");

// Ring buffer type eBPF map used to store captured event data and send it to the user-space program
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* ********************************************************************************************
Constants and Global Variables
******************************************************************************************** */
const volatile unsigned long long min_duration_ns = 0;

/* ********************************************************************************************
Functions triggered at specified event
******************************************************************************************** */

// triggered when a process executes the exec() system call
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    unsigned fname_off;
    struct event *e;
    pid_t pid;
    u64 ts;

    // retrieve the PID from the current process
    pid = bpf_get_current_pid_tgid() >> 32;
    // record the timestamp when the process starts executing
    ts = bpf_ktime_get_ns();
    // and store it in the exec_start map
    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

    // don't emit exec events when minimum duration is specified 
    if (min_duration_ns)
        return 0;

    // reserve an event structure from the ring buffer map rb
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // get current task struct
    task = (struct task_struct *)bpf_get_current_task();

    // Fill information in the event structure
    e->exit_event = false;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    // submit it to user-space for post-processing
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// triggered when a process executes the exit() system call
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, tid;
    u64 id, ts, *start_ts, duration_ns = 0;

    // retrieve the PID from the current process
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    // If the PID and TID are not equal, it means that this is a thread exit, and we will ignore this event 
    if (pid != tid)
        return 0;

    // retrieve start time from hash map
    start_ts = bpf_map_lookup_elem(&exec_start, &pid);
    // calculate the process's lifetime duration
    if (start_ts)duration_ns = bpf_ktime_get_ns() - *start_ts;
    else if (min_duration_ns)
        return 0;
    // then remove the record
    bpf_map_delete_elem(&exec_start, &pid);

    /* if process didn't live long enough, return early */
    if (min_duration_ns && duration_ns < min_duration_ns)
        return 0;

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    /* fill out the sample with data */
    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = true;
    e->duration_ns = duration_ns;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}