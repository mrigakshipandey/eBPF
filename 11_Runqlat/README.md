## 11. Runqlat
Runqlat is an eBPF tool used for analyzing the scheduling performance of the Linux system. 
Specifically, runqlat is used to measure the time a task waits in the run queue before being scheduled to run on a CPU. 
This information is very useful for identifying performance bottlenecks and improving the overall efficiency of the Linux kernel scheduling algorithm.

Processes can have several possible states, such as:
- Runnable or running
- Interruptible sleep
- Uninterruptible sleep
- Stopped
- Zombie process

Processes waiting for resources or other function signals are in the interruptible or uninterruptible sleep state: the process is put to sleep until the resource it needs becomes available. Then, depending on the type of sleep, the process can transition to the runnable state or remain asleep.

When a process has all the resources it needs, it does not start running immediately, it transitions to the runnable state and is queued. The length of this runnable queue (known as the CPU run queue) can depend on the hardware confuguration of the system. 

A short run queue length indicates that the CPU is not being fully utilized. On the other hand, if the run queue is long, it may mean that the CPU is not powerful enough to handle all the processes or that the number of CPU cores is insufficient. In an ideal CPU utilization, the length of the run queue will be equal to the number of cores in the system.

Run queue latency, is the time it takes for a thread to go from becoming runnable to actually running on the CPU. And it can be reduced by careful tuning to improve the overall system performance.

# Compile the program using ecc
```
./ecc runqlat.bpf.c
```

### Run the compiled program using ecli
```
sudo ./ecli run package.json
```