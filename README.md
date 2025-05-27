# eBPF Setup and Examples
eBPF is a revolutionary kernel technology that allows developers to write custom code that can be loaded into the kernel dynamically, changing the way the kernel behaves.

This Repository Documents me learning eBPF.
### References
|Resouce|Link|
|---|---:|
| Book:   | [Learning-eBPF](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf)  |
| bpftool: | [github.com/lizrice/learning-ebpf](https://github.com/lizrice/learning-ebpf)  | 
| ecc and ecli: | [github.com/eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial)  | 
| bootstrap: | [github.com/libbpf/libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)  | 

### Setup

>**OS Distribution:** Ubuntu 22.04.1 LTS
>**Kernel:** 5.15.0-48-generic

This information can be found using the following commands:
```
lsb_release -a
uname -r
```

#### Step 1: Install Required Dependencies
To build eBPF programs and tools like bpftool, ensure the following packages are installed:
```
sudo apt update
sudo apt install -y \
  git build-essential clang llvm libelf-dev libzstd-dev \
  libcap-dev libssl-dev libbfd-dev libncurses-dev \
  linux-headers-$(uname -r)
```
#### Step 2: Build and Install libbpf
This installs libbpf to /usr/local/lib and headers to /usr/local/include
```
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
make
sudo make install
cd ../..
```
#### Step 3: Build and Install bpftool
This installs bpftool to /usr/local/bin
```
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make
sudo make install
cd ../..
```
### Examples
**Simple Examples bpftool:**
- [Simple Program attached to an XDP Event](https://github.com/mrigakshipandey/eBPF/blob/master/01_XDP_Event/README.md)
- [Making Function calls in BPF Programs](https://github.com/mrigakshipandey/eBPF/blob/master/02_BPF_Func_Call/README.md)

**Simple Examples ecc and ecli:**
- [Attaching Probes to syscalls](https://github.com/mrigakshipandey/eBPF/blob/master/03_Syscall/README.md)
- [Using Kprobes and Kretprobes](https://github.com/mrigakshipandey/eBPF/blob/master/04_Kprobes/README.md)
- [Using Fentry and Fexit](https://github.com/mrigakshipandey/eBPF/blob/master/05_Fentry/README.md)
- [Capturing File Open and Filter with Global Variables](https://github.com/mrigakshipandey/eBPF/blob/master/06_Open_Snoop/README.md)
- [Capturing readline Function Calls with Uprobe](https://github.com/mrigakshipandey/eBPF/blob/master/07_Uprobe/README.md)
- [eBPF Hash Maps](https://github.com/mrigakshipandey/eBPF/blob/master/08_Hash_Maps/README.md)
- [eBPF Perf Array](https://github.com/mrigakshipandey/eBPF/blob/master/09_Pref_Array/README.md)
- [eBPF Ring Buffer](https://github.com/mrigakshipandey/eBPF/blob/master/10_Ring_Buffer/README.md)
- [Run Queue Latency](https://github.com/mrigakshipandey/eBPF/blob/master/11_Runqlat/README.md)
- [Hardware Interrupts](https://github.com/mrigakshipandey/eBPF/blob/master/12_Interrupts/README.md)