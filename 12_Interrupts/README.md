## 12. Capturing Interrupts with hardirqs or softirqs
**hardirqs** are hardware interrupt handlers. When a hardware device generates an interrupt request, the kernel maps it to a specific interrupt vector and executes the associated hardware interrupt handler. Hardware interrupt handlers are commonly used to handle events in device drivers, such as completion of device data transfer or device errors.

**softirqs** are software interrupt handlers. They are a low-level asynchronous event handling mechanism in the kernel, used for handling high-priority tasks in the kernel. softirqs are commonly used to handle events in the network protocol stack, disk subsystem, and other kernel components. Compared to hardware interrupt handlers, software interrupt handlers have more flexibility and configurability.

To capture hardirqs and softirqs, eBPF programs need to be placed on relevant kernel functions. These functions include:

- For hardirqs: irq_handler_entry and irq_handler_exit.
- For softirqs: softirq_entry and softirq_exit.

To capture hardirqs and softirqs:

1. Define data structures and maps in eBPF programs for storing interrupt information.
2. Write eBPF programs and attach them to the corresponding kernel functions to capture hardirqs or softirqs.
3. In eBPF programs, collect relevant information about interrupt handlers and store this information in the maps.
4. In user space applications, read the data from the maps to analyze and display the interrupt handling information.

# Compile the program using ecc
```
./ecc hardirqs.bpf.c
```

### Run the compiled program using ecli
```
sudo ./ecli run package.json
```