## 7. Capturing readline Function Calls with Uprobe
uprobe is an eBPF probe used to capture user-space function calls, 
allowing us to capture system functions called by user-space programs. 
It can probe function entry, specific offsets, and function returns.

bpftime is a user mode eBPF runtime based on LLVM JIT/AOT. 
It can run eBPF programs in user mode and is compatible with kernel mode eBPF, 
avoiding context switching between kernel mode and user mode, 
thereby improving the execution efficiency of eBPF programs by 10 times.

## Compile the program using ecc
```
./ecc uprobe.bpf.c
```

### Run the compiled program using ecli
```
sudo ./ecli run package.json
```
We can see the output in a different terminal
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
Now we can type commnads in a new terminal and they'll be logged in the trace_pipe

Once we use Ctrl+C to stop the ecli process, the corresponding output would also stop 
