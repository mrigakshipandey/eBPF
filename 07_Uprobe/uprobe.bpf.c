#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

// we want to capture the readline function in the /bin/bash binary file.
SEC("uretprobe//bin/bash:readline")

// the BPF_PROBE function printret() will execute when readline returns
int BPF_KRETPROBE(printret, const void *ret)
{
 char str[MAX_LINE_SIZE];
 char comm[TASK_COMM_LEN];
 u32 pid;

 if (!ret)
  return 0;

// obtain the process name and process ID of the process calling readline
 bpf_get_current_comm(&comm, sizeof(comm)); 
 pid = bpf_get_current_pid_tgid() >> 32;

// read the user input command line string
 bpf_probe_read_user_str(str, sizeof(str), ret);

// print the process ID, process name, and input command line string
 bpf_printk("PID %d (%s) read: %s ", pid, comm, str);

 return 0;
};

char LICENSE[] SEC("license") = "GPL";