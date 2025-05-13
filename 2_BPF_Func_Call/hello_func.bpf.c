// Header files required to compile an eBPF program
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
Given the choice, the compiler would probably inline this 
very simple function. So, we have inlined it to force the compiler’s 
hand.

Normally, omit this and allow the compiler to optimize as it sees fit.
*/
static __attribute((noinline)) int get_opcode(
    struct bpf_raw_tracepoint_args *ctx) {
    return ctx->args[1];
}

SEC("raw_tp/")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = get_opcode(ctx);
    bpf_printk("Syscall: %d", opcode);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";