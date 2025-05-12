## XDP Event
You can think of the XDP event being triggered the moment a network packet arrives inbound on a (physical or virtual) network interface.

This is an example of an eBPF program that attaches to the XDP Event.

### Compiling the Program
Our eBPF source code needs to be compiled into the machine instructions that the eBPF virtual machine can understand i.e. the eBPF bytecode.

Our Makefile contains the rule for compiling an eBPF Object File using the Clang compiler. 
To compile our program we can simply run make in our 'XDP Event' Directory.
```
make
```

We can get some info about the resuting object file using the 'file' utility.
```
file hello.bpf.o
```

To see the eBPF instructions we can also disassemble the resulting object file using the utility 'llvm-objdump'.
```
llvm-objdump -S hello.bpf.o
```
### Loading the Program into the Kernel
We need the utility 'bpftool' to load a program into the kernel. Note
that it likely need to be done as root (or use sudo) to get the BPF privileges that bpftool requires.
```
sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello
```
This loads the eBPF program from our compiled object file and “pins” it to the location /sys/fs/bpf/hello.

No output response to this command indicates success, but it
can be confirmed that the program is in place using ls
```
sudo ls /sys/fs/bpf
```

### Inspecting the Loaded Program
The 'bpftool' utility can list all the programs that are loaded into the kernel.
```
sudo bpftool prog list
```
The output will give a list of key-value pairs. Further, we can use the key from this list to see the information in a more readble format.
```
sudo bpftool prog show id <id> --pretty
```
The bpftool utility accepts references to a BPF program by ID, name, tag, or pinned path.

We can see the eBPF instrctions of the loaded program.
```
sudo bpftool prog dump xlated name <name>
```
eBPF uses a JIT compiler to convert eBPF bytecode to machine code that runs natively on the target CPU. The bpftool utility can generate a dump of this JITed code in assembly language.
```
sudo bpftool prog dump jited name <name>
```
### Attaching to an Event
The program type has to match the type of event it’s being attached to. In this case it’s an XDP program, we can use 'bpftool' to attach the eBPF program to the XDP event on a network interface
```
sudo bpftool net attach xdp id <id> dev <network interface>
```
Suitable network interface can be found using the following command.
```
ip -br a
```
We have used the programs id to attach the program to the network interface.

We can view all the network-attached eBPF programs using 'bpftool'.
```
sudo bpftool net list
```
### Inspecting the output
At this point, the hello eBPF program should be producing trace output every time a network packet is received. We can check this out in the trace
```
sudo bpftool prog tracelog
```
We know that the helper function bpf_printk() always writes to a the same location so we can see the trace using the 'cat' utility.
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
### How are Global Variables Implemented?
A BPF map is a data structure that can be accessed from an eBPF program or from user space. 

Since the same map can be accessed repeatedly by different runs of the same program, it can be used to hold state from one execution to the next. Multiple programs can also access the same map. Because of these characteristics, map semantics can be repurposed for use as global variables.

The bpftool utility can show the maps loaded into the kernel.
```
sudo bpftool map list
```
We can also see more information on the maps created by this programs using the following command, if we had compiled the program with -g flag.
```
sudo bpftool map dump name <name>
```
Our programs creates two maps. One for the counter and one read only map used to store the string used by the eBPF program for tracing.

### Detaching the Program
We can detach the program from the network interface like this.
```
sudo bpftool net detach xdp dev <network interface>
```
We can confirm that the program is no longer attached by the lack of XDP entries in the output from bpftool net list.
```
sudo bpftool net list
```
However, the program is still loaded into the kernel.
```
sudo bpftool prog show name <name>
```
### Unloading the Program
There’s no inverse of bpftool prog load (at least not at the time of this writing), but we can remove the program from the kernel by deleting the pinned pseudofile
```
sudo rm /sys/fs/bpf/<name>
sudo bpftool prog show name <name>
```