## 13. Bootstrap
Bootstrap consists of two parts: 
- kernel space: eBPF program that traces the exec() and exit() system calls [bootstrap.bpf.c]
- user space: C language program that uses the libbpf library to load, run and process the data from the kernel space program [bootstrap.c]

### The libbpf Library and Why We Need to Use It
libbpf is a C language library that is distributed with the kernel version to assist in loading and running eBPF programs. It provides a set of C APIs for interacting with the eBPF system, allowing developers to write user-space programs more easily to load and manage eBPF programs. 

BTF is a metadata format used to describe type information in eBPF programs. 
The primary purpose of BTF is to provide a structured way to describe data structures in the kernel so that eBPF programs can access and manipulate them more easily.
By using BPF CO-RE, eBPF programs can leverage BTF to parse the type information of kernel data structures during compilation, thereby generating eBPF programs that can run on different kernel versions.

### Install Dependencies
Building the example requires clang, libelf, and zlib.
```
sudo apt install clang libelf1 libelf-dev zlib1g-dev
```

### Compile and Run
Run the following to commands
```
cd 13_Bootstrap
sudo make
sudo ./bootstrap 
```