## 9. Capturing Process Execution, Output with Perf Event Array
Here we capture process execution events in the Linux kernel and print output to the user command line via a Perf Event Array. 
This eliminates the need to view the output of eBPF programs by checking the /sys/kernel/debug/tracing/trace_pipe file. 
After sending information to user space via the Perf Event Array, complex data processing and analysis can be performed.

### Compile the program using ecc
```
./ecc execsnoop.bpf.c execsnoop.h
```

### Run the compiled program using ecli
```
sudo ./ecli run package.json
```