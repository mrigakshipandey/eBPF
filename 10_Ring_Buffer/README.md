## 9. Ring Buffer
Whenever a BPF program needs to send collected data to user space for post-processing and logging, it typically uses the BPF perf buffer (perfbuf).

**Perf Array** is a collection of per-CPU circular buffers that allow efficient data exchange between the kernel and user space. 
It works well in practice, but it has two main drawbacks that have proven to be inconvenient: **inefficient memory usage and event reordering**.

To address these issues, starting from Linux 5.8, BPF introduces a new BPF data structure called BPF **Ring buffer**. It is a multiple producer, single consumer (MPSC) queue that can be **safely shared across multiple CPUs**.

# Compile the program using ecc
```
./ecc exitsnoop.bpf.c
```

### Run the compiled program using ecli
```
sudo ./ecli run package.json
```