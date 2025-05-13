# eBPF Setup and Examples
eBPF is a revolutionary kernel technology that allows developers to write custom code that can be loaded into the kernel dynamically, changing the way the kernel behaves.

This Repository Documents me learning eBPF.
### References
|Resouce|Link|
|---|---:|
| Book:   | [Learning-eBPF](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf)  |
| Github: | [github.com/lizrice/learning-ebpf](https://github.com/lizrice/learning-ebpf)  | 

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
Continue to go through the Example eBPF Programs
- [Simple Program attached to an XDP Event](https://github.com/mrigakshipandey/eBPF/blob/master/1_XDP_Event/README.md)
- [Making Function calls in BPF Programs](https://github.com/mrigakshipandey/eBPF/blob/master/2_BPF_Func_Call/README.md)

