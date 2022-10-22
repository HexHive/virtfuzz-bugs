# None

# Division by zero in uart_parameters_setup


## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, None, None, None

### VM architecture, device, device type
aarch64, cadence_uart, char

### Bug Type: Devision by Zero

### Stack traces, crash details

```
root@e1fc40420e44:~/evaluation/bug-reports# /tmp/tmp.OljH5NPSeN/picire_reproduce.sh /tmp/tmp.OljH5NPSeN/picire_inputs.20211003_145546/picire_inputs
INFO: found LLVMFuzzerCustomMutator (0x563846a83230). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 657066260
INFO: Loaded 1 modules   (1042817 inline 8-bit counters): 1042817 [0x56384a7ab000, 0x56384a8a9981),
INFO: Loaded 1 PC tables (1042817 PCs): 1042817 [0x5638497c1790,0x56384a7aafa0),
/root/qemu/build-san-5/qemu-fuzz-aarch64-target-stateful-fuzz-cadence-uart: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
Matching objects by name , *uart*
This process will fuzz the following MemoryRegions:
  * uart[0] (size 1000)
  * uart[0] (size 1000)
This process will fuzz through the following interfaces:
  * uart, EVENT_TYPE_MMIO_READ, 0xff000000 +0x1000, 1,4
  * uart, EVENT_TYPE_MMIO_WRITE, 0xff000000 +0x1000, 1,4
  * uart, EVENT_TYPE_MMIO_READ, 0xff010000 +0x1000, 1,4
  * uart, EVENT_TYPE_MMIO_WRITE, 0xff010000 +0x1000, 1,4
  * uart, EVENT_TYPE_MMIO_READ, 0xff000000 +0x1000, 1,4
  * uart, EVENT_TYPE_MMIO_WRITE, 0xff000000 +0x1000, 1,4
  * uart, EVENT_TYPE_MMIO_READ, 0xff010000 +0x1000, 1,4
  * uart, EVENT_TYPE_MMIO_WRITE, 0xff010000 +0x1000, 1,4
INFO: seed corpus: files: 1 min: 1971b max: 1971b total: 1971b rss: 487Mb
#3	INITED cov: 1810 ft: 1809 corp: 1/1971b exec/s: 0 rss: 488Mb
Running: /root/evaluation/bug-reports/crash-1c170bd042242a1be8d01ba2375413df135f0540
/root/qemu/hw/char/cadence_uart.c:180:15: runtime error: division by zero
    #0 0x563843fee654 in uart_parameters_setup cadence_uart.c
    #1 0x563843fe8101 in uart_write cadence_uart.c
    #2 0x563843043fd1 in memory_region_write_accessor memory.c
    #3 0x5638430435a6 in access_with_adjusted_size memory.c
    #4 0x5638430414f1 in memory_region_dispatch_write (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x480e4f1)
    #5 0x5638422c9749 in flatview_write_continue exec.c
    #6 0x5638422b38d2 in flatview_write exec.c
    #7 0x5638422b3421 in address_space_write (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x3a80421)
    #8 0x563846a6ef29 in __wrap_qtest_writel (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x823bf29)
    #9 0x563846b13650 in dispatch_mmio_write stateful_fuzz.c
    #10 0x563846a8d655 in dispatch_event stateful_fuzz.c
    #11 0x563846b1593a in stateful_fuzz stateful_fuzz.c
    #12 0x563846a651ee in LLVMFuzzerTestOneInput (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x82321ee)
    #13 0x563842166803 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:607
    #14 0x563842149b2a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #15 0x5638421547e4 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:883
    #16 0x56384212a3d2 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #17 0x7f60b04d6bf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
    #18 0x56384213ff59 in _start (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x390cf59)

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /root/qemu/hw/char/cadence_uart.c:180:15 in
MS: 0 ; base unit: 0000000000000000000000000000000000000000```

### Reproducer steps

bash 29.sh
## Contact

Let us know if I need to provide more information.
