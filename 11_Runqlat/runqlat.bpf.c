// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang

/* ********************************************************************************************
Required Header Files
******************************************************************************************** */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "runqlat.h"
#include "bits.bpf.h"
#include "maps.bpf.h"
#include "core_fixes.bpf.h"


/* ********************************************************************************************
Constants and Global Variables
******************************************************************************************** */

// The maximum number of map entries.
#define MAX_ENTRIES 10240
//The task status value.
#define TASK_RUNNING  0

/*
Boolean variables for filtering and target options. 
These options can be set by user-space programs to customize the behavior of the eBPF program.
*/
const volatile bool filter_cg = false;
const volatile bool targ_per_process = false;
const volatile bool targ_per_thread = false;
const volatile bool targ_per_pidns = false;
const volatile bool targ_ms = false;
const volatile pid_t targ_tgid = 0;


/* ********************************************************************************************
eBPF Maps
******************************************************************************************** */
struct {
 __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
 __type(key, u32);
 __type(value, u32);
 __uint(max_entries, 1);
} cgroup_map SEC(".maps");  // used for filtering cgroups.

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, u32);
 __type(value, u64);
} start SEC(".maps");       // used to store timestamps when processes are enqueued.

static struct hist zero;

/// @sample {"interval": 1000, "type" : "log2_hist"}
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, u32);
 __type(value, struct hist);
} hists SEC(".maps");       // used to store histogram data for recording process scheduling delays.


/* ********************************************************************************************
Helper Functions
******************************************************************************************** */

// This function is used to record the timestamp when a process is enqueued.
// It takes the tgid and pid values as parameters.
static int trace_enqueue(u32 tgid, u32 pid)
{
u64 ts;

// If the pid value is 0  
if (!pid)
  return 0;
// or the targ_tgid value is not 0 and not equal to tgid
if (targ_tgid && targ_tgid != tgid)
  return 0; //the function returns 0.

// it retrieves the current timestamp using bpf_ktime_get_ns 
// and updates the start map with the pid key and the timestamp value.
ts = bpf_ktime_get_ns();
bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
return 0;
}

// This function is used to get the PID namespace of a process.
// It takes a task_struct pointer as a parameter
static unsigned int pid_namespace(struct task_struct *task)
{
struct pid *pid;
unsigned int level;
struct upid upid;
unsigned int inum;

// The function retrieves the PID namespace by following pid->numbers[pid->level].ns
pid = BPF_CORE_READ(task, thread_pid);
level = BPF_CORE_READ(pid, level);
bpf_core_read(&upid, sizeof(upid), &pid->numbers[level]);
inum = BPF_CORE_READ(upid.ns, ns.inum);

// returns the PID namespace of the process
return inum;
}

// used to handle scheduling switch events, calculate process scheduling latency, and update histogram data
static int handle_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
struct hist *histp;
u64 *tsp, slot;
u32 pid, hkey;
s64 delta;

// If we are filtering cgroup and the task is not under the current cgroup
// return 0
if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

// If the previous process state is TASK_RUNNING
// the trace_enqueue() function is called to record the enqueue time of the process.
if (get_task_state(prev) == TASK_RUNNING)
  trace_enqueue(BPF_CORE_READ(prev, tgid), BPF_CORE_READ(prev, pid));

// read the pid of the next task
pid = BPF_CORE_READ(next, pid);

// look for the nect task entry in the start map
tsp = bpf_map_lookup_elem(&start, &pid);
if (!tsp)
  return 0; // return 0 if not found

// The scheduling latency (delta) is calculated,
delta = bpf_ktime_get_ns() - *tsp;

if (delta < 0)
  goto cleanup;

// the key for the histogram map (hkey) is determined based on different options 
if (targ_per_process)
  hkey = BPF_CORE_READ(next, tgid);
else if (targ_per_thread)
  hkey = pid;
else if (targ_per_pidns)
  hkey = pid_namespace(next);
else
  hkey = -1;

// the histogram map is looked up or initialized
histp = bpf_map_lookup_or_try_init(&hists, &hkey, &zero);
if (!histp)
  goto cleanup;

// the histogram data is updated with the command name
if (!histp->comm[0])
  bpf_probe_read_kernel_str(&histp->comm, sizeof(histp->comm),
     next->comm);

// the histogram data is updated with the slots to show delta delay
if (targ_ms)
  delta /= 1000000U;
else
  delta /= 1000U;
slot = log2l(delta);
if (slot >= MAX_SLOTS)
  slot = MAX_SLOTS - 1;
__sync_fetch_and_add(&histp->slots[slot], 1);

// the enqueue timestamp record of the process is deleted.
cleanup:
bpf_map_delete_elem(&start, &pid);
return 0;
}

/* ********************************************************************************************
Functions triggered at specified event
******************************************************************************************** */

// event triggered when a process is woken up from sleep state
SEC("raw_tp/sched_wakeup")
int BPF_PROG(handle_sched_wakeup, struct task_struct *p)
{
 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;
    
 // Record the time stamp when the process becomes runnable
 return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

// event triggered when a newly created process is woken up
SEC("raw_tp/sched_wakeup_new")
int BPF_PROG(handle_sched_wakeup_new, struct task_struct *p)
{
 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

 // Record the time stamp when the process becomes runnable
 return trace_enqueue(BPF_CORE_READ(p, tgid), BPF_CORE_READ(p, pid));
}

// event triggered when the scheduler selects a new process to run.
SEC("raw_tp/sched_switch")
int BPF_PROG(handle_sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
 return handle_switch(preempt, prev, next);
}

/* ********************************************************************************************
License
******************************************************************************************** */
// This is required for many kernel features as they require eBPF programs to follow the GPL license.
char LICENSE[] SEC("license") = "GPL";