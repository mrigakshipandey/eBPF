## 8. Capturing Signal Sending and Store State with Hash Maps
An eBPF program for capturing system calls that send signals to processes, including kill, tkill, and tgkill. 
It captures the enter and exit events of system calls by using tracepoints, and executes specified probe functions 
such as probe_entry and probe_exit when these events occur.

In the probe function, we use the bpf_map to store the captured event information.
When the system call exits, we retrieve the event information stored in the bpf_map and use bpf_printk to print the information.

## Compile the program using ecc
```
./ecc sigsnoop.bpf.c
```

### Run the compiled program using ecli
```
sudo ./ecli run package.json
```
We can see the output in a different terminal
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
Now we can kill a process in a new terminal and they'll be logged in the trace_pipe
```
kill -9 $$
```

Once we use Ctrl+C to stop the ecli process, the corresponding output would also stop 