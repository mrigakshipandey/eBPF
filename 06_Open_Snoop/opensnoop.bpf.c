#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/*
Define the global variable pid_target for filtering a specified process ID. 
Setting it to 0 captures sys_openat calls from all processes.
*/
const volatile int pid_target = 0;

/*
the parameter ctx contains information about the system call.
*/
SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (pid_target && pid_target != pid)
        return false;

    // Use bpf_printk to print the process information
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

// Setting the program license to "GPL", is a necessary condition for running eBPF programs.
char LICENSE[] SEC("license") = "GPL";