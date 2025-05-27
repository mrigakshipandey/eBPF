## 4. Monitoring System Calls with kprobe
### Background of kprobes Technology
Using Kprobes we can define our own callback functions and dynamically insert probes into almost all functions in the kernel or modules (some functions cannot be probed, such as the kprobes' own implementation functions, which will be explained in detail later), doesnt require recompiling the kernel or modules, restarting the device. 

When the kernel execution flow reaches the specified probe function, it will invoke the callback function, allowing the user to collect the desired information. The kernel will then return to the normal execution flow. If the user has collected sufficient information and no longer needs to continue probing, the probes can be dynamically removed. Therefore, the kprobes technology has the advantages of minimal impact on the kernel execution flow and easy operation.

### Compile the program using ecc
```
./ecc kprobes.bpf.c
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