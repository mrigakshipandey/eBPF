## 3. Syscall - minimal eBPF program
This program defines a handle_tp function and we will attach it to the sys_enter_write tracepoint (it is executed when the write system call is entered). 

The function retrieves the process ID of the write system call invocation using the bpf_get_current_pid_tgid() helper function and bpf_printk() helper function prints it in the kernel log.

### What are Tracepoints?
They are instrumentation points placed in various parts of the Linux kernel code. They provide a way to hook into specific events or code paths within the kernel without modifying the kernel source code.
```
sudo ls /sys/kernel/debug/tracing/events
```

### Download and Install eunomia-bpf Development Tools
eunomia-bpf is an open-source eBPF dynamic loading runtime and development toolchain that combines with Wasm. 

Its goal is to simplify the development, build, distribution, and execution of eBPF programs. 

```
cd 3_Syscall

wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli
./ecli -h

wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
./ecc -h
```

### Compile the program using ecc
```
./ecc hello.bpf.c
```

### Run the compiled program using ecli
```
sudo ./ecli run package.json
```
We can see the output in a different terminal
```
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep "BPF triggered sys_enter_write"
```
Once we use Ctrl+C to stop the ecli process, the corresponding output would also stop 