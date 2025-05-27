## 5. Fentry Probes
fentry (function entry) and fexit (function exit) are two types of probes in eBPF (Extended Berkeley Packet Filter) used for tracing at the entry and exit points of Linux kernel functions. 

Compared to kprobes, fentry and fexit programs have higher performance and availability. In this example, we can directly access the pointers to the functions' parameters, just like in regular C code, without needing various read helpers. The main difference between fexit and kretprobe programs is that fexit programs can access both the input parameters and return values of a function, while kretprobe programs can only access the return value.

### Compile the program using ecc
```
./ecc fentry.bpf.c
```

### Run the compiled program using ecli
```
sudo ./ecli run package.json
```
We can see the output in a different terminal
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
We can create and delete a file and see if the file name appreas in the trace.
Once we use Ctrl+C to stop the ecli process, the corresponding output would also stop 