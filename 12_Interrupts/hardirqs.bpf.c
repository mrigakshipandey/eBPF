// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Wenbo Zhang

/* ********************************************************************************************
Required Header Files
******************************************************************************************** */

// standard header files required for eBPF development
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// custom header files defining data structures and maps
#include "hardirqs.h"
#include "bits.bpf.h"
#include "maps.bpf.h"

/* ********************************************************************************************
Constants and Global Variables
******************************************************************************************** */
#define MAX_ENTRIES 256

const volatile bool filter_cg = false;  // controls whether to filter cgroups
const volatile bool targ_dist = false;  // controls whether to display the distribution of execution time
const volatile bool targ_ns = false;
const volatile bool do_count = false;

struct irq_key {
	char name[32];
};

/* ********************************************************************************************
eBPF Maps
******************************************************************************************** */
struct {
 __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
 __type(key, u32);
 __type(value, u32);
 __uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
 __uint(max_entries, 1);
 __type(key, u32);
 __type(value, u64);
} start SEC(".maps");

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct irq_key);
 __type(value, struct info);
} infos SEC(".maps");

static struct info zero;

/* ********************************************************************************************
Helper Functions
******************************************************************************************** */

// records the start timestamp or updates the interrupt count
static int handle_entry(int irq, struct irqaction *action)
{
 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

 if (do_count) {
  struct irq_key key = {};
  struct info *info;

  bpf_probe_read_kernel_str(&key.name, sizeof(key.name), BPF_CORE_READ(action, name));
  info = bpf_map_lookup_or_try_init(&infos, &key, &zero);
  if (!info)
   return 0;
  info->count += 1;
  return 0;
 } else {
  u64 ts = bpf_ktime_get_ns();
  u32 key = 0;

  if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
   return 0;

  bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
  return 0;
 }
}

// calculates the execution time of the interrupt handler 
// and stores the result in the corresponding information map.
static int handle_exit(int irq, struct irqaction *action)
{
 struct irq_key ikey = {};
 struct info *info;
 u32 key = 0;
 u64 delta;
 u64 *tsp;

 if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
  return 0;

 tsp = bpf_map_lookup_elem(&start, &key);
 if (!tsp)
  return 0;

 delta = bpf_ktime_get_ns() - *tsp;
 if (!targ_ns)
  delta /= 1000U;

 bpf_probe_read_kernel_str(&ikey.name, sizeof(ikey.name), BPF_CORE_READ(action, name));
 info = bpf_map_lookup_or_try_init(&infos, &ikey, &zero);
 if (!info)
  return 0;

 if (!targ_dist) {
  info->count += delta;
 } else {
  u64 slot;

  slot = log2(delta);
  if (slot >= MAX_SLOTS)
   slot = MAX_SLOTS - 1;
  info->slots[slot]++;
 }

 return 0;
}

/* ********************************************************************************************
Functions triggered at specified event
******************************************************************************************** */

/*
Here, four entry points of the eBPF program are defined, 
which are used to capture the entry and exit events of the interrupt handler. 

tp_btf and raw_tp represent capturing events using BPF Type Format (BTF) and raw tracepoints, respectively. 
This ensures that the program can be ported and run on different kernel versions.

corresponding softirq events would be:
- tp_btf/softirq_entry
- tp_btf/softirq_exit
- raw_tp/softirq_entry
- raw_tp/softirq_exit
*/

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(irq_handler_entry_btf, int irq, struct irqaction *action)
{
 return handle_entry(irq, action);
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(irq_handler_exit_btf, int irq, struct irqaction *action)
{
 return handle_exit(irq, action);
}

SEC("raw_tp/irq_handler_entry")
int BPF_PROG(irq_handler_entry, int irq, struct irqaction *action)
{
 return handle_entry(irq, action);
}

SEC("raw_tp/irq_handler_exit")
int BPF_PROG(irq_handler_exit, int irq, struct irqaction *action)
{
 return handle_exit(irq, action);
}

/* ********************************************************************************************
License
******************************************************************************************** */
// This is required for many kernel features as they require eBPF programs to follow the GPL license.
char LICENSE[] SEC("license") = "GPL";