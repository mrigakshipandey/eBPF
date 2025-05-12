// Header files required to compile an eBPF program
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
A Gobal variable that can be accessed across 
the several invocations of the hello() function at XDP Events
*/ 
int counter = 0;

// Macro that makes it an XDP Program
SEC("xdp")

// The function that will be attched to XDP events
int hello(struct xdp_md *ctx) {
  
    /* 
    bpf_printk() is a helper function i.e. it is one of the functions
    made available to BPF programs by the linux kernel
    */
    // We will print the current value of the counter and increment it
    bpf_printk("Number of XDP Packets encountered: %d", ++counter); 

    // Then let the network paqcket continue as usual
    return XDP_PASS;
}

/* 
We need to add the GPL license because some of the BPF 
helper functions in the kernel are defined as “GPL only.”
*/ 
char LICENSE[] SEC("license") = "Dual BSD/GPL";