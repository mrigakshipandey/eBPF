## 2. Making Function calls in BPF Programs
In BPF we have the ability to call a function from within a BPf program

### Compiling the Program
Compile the BPF program
```
cd 2_BPF_Func_Call
make
```
### Loading the Program into the Kernel
We need the utility 'bpftool' to load a program into the kernel. 
```
sudo bpftool prog load hello_func.bpf.o /sys/fs/bpf/hello
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
We can see the eBPF instrctions of the loaded program.
```
sudo bpftool prog dump xlated name hello
```
We can see the program making a function call at instruction 0.

The function call instruction necessitates putting the current state on the eBPF virtual machine’s stack so that when the called function exits, execution can continue in the calling function. 

Since the stack size is limited to 512 bytes, BPF to BPF calls can’t be very deeply nested.

### Unloading the Program
Remove the program from the kernel by deleting the pinned pseudofile
```
sudo rm /sys/fs/bpf/hello
sudo bpftool prog show name hello
```

