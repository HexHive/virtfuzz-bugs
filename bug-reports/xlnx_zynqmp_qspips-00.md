# Index out of bounds for type uint32_t[64] in xilinx_spips_write()

# Index out of bounds for type uint32_t [64] in xilinx_spips_write
## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type
i386, xlnx_zynqmp_qspips, storage

### Bug Type: Out-of-bound Read/Write

### Stack traces, crash details

```
root@fff5a5933072:~/qemu/build-san-5# ./qemu-fuzz-aarch64 --fuzz-target=stateful-fuzz-xlnx-zynqmp-qspips crash-69ad8465205e9ac08b9fc1f0d469674e81a73019 
INFO: found LLVMFuzzerCustomMutator (0x558d919138d0). Disabling -len_control by default.
INFO: libFuzzer ignores flags that start with '--'
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1456315993
INFO: Loaded 1 modules   (1042849 inline 8-bit counters): 1042849 [0x558d9563c000, 0x558d9573a9a1), 
INFO: Loaded 1 PC tables (1042849 PCs): 1042849 [0x558d94651830,0x558d9563b240), 
./qemu-fuzz-aarch64: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
Matching objects by name , *spi*, *lqspi*
This process will fuzz the following MemoryRegions:
  * spi[0] (size 830)
  * spi[0] (size 830)
  * lqspi[0] (size 2000000)
  * spi[0] (size 830)
This process will fuzz through the following interfaces:
  * spi, EVENT_TYPE_MMIO_READ, 0xff040000 +0x830, 1,4
  * spi, EVENT_TYPE_MMIO_WRITE, 0xff040000 +0x830, 1,4
  * lqspi, EVENT_TYPE_MMIO_READ, 0xc0000000 +0x2000000, 4,4
  * lqspi, EVENT_TYPE_MMIO_WRITE, 0xc0000000 +0x2000000, 4,4
  * spi, EVENT_TYPE_MMIO_READ, 0xff0f0000 +0x830, 1,4
  * spi, EVENT_TYPE_MMIO_WRITE, 0xff0f0000 +0x830, 1,4
  * spi, EVENT_TYPE_MMIO_READ, 0xff050000 +0x830, 1,4
  * spi, EVENT_TYPE_MMIO_WRITE, 0xff050000 +0x830, 1,4
  * lqspi, EVENT_TYPE_MMIO_READ, 0xc0000000 +0x2000000, 4,4
  * lqspi, EVENT_TYPE_MMIO_WRITE, 0xc0000000 +0x2000000, 4,4
  * spi, EVENT_TYPE_MMIO_READ, 0xff040000 +0x830, 1,4
  * spi, EVENT_TYPE_MMIO_WRITE, 0xff040000 +0x830, 1,4
  * lqspi, EVENT_TYPE_MMIO_READ, 0xc0000000 +0x2000000, 4,4
  * lqspi, EVENT_TYPE_MMIO_WRITE, 0xc0000000 +0x2000000, 4,4
  * spi, EVENT_TYPE_MMIO_READ, 0xff0f0000 +0x830, 1,4
  * spi, EVENT_TYPE_MMIO_WRITE, 0xff0f0000 +0x830, 1,4
  * spi, EVENT_TYPE_MMIO_READ, 0xff050000 +0x830, 1,4
  * spi, EVENT_TYPE_MMIO_WRITE, 0xff050000 +0x830, 1,4
  * lqspi, EVENT_TYPE_MMIO_READ, 0xc0000000 +0x2000000, 4,4
  * lqspi, EVENT_TYPE_MMIO_WRITE, 0xc0000000 +0x2000000, 4,4
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 11 ft: 12 corp: 1/1b exec/s: 0 rss: 487Mb
Running: crash-69ad8465205e9ac08b9fc1f0d469674e81a73019
/root/qemu/hw/ssi/xilinx_spips.c:1035:22: runtime error: index 501 out of bounds for type 'uint32_t [64]'
    #0 0x558d90350923 in xilinx_spips_write xilinx_spips.c
    #1 0x558d8ded3fd1 in memory_region_write_accessor memory.c
    #2 0x558d8ded35a6 in access_with_adjusted_size memory.c
    #3 0x558d8ded14f1 in memory_region_dispatch_write (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x480e4f1)
    #4 0x558d8d159749 in flatview_write_continue exec.c
    #5 0x558d8d1438d2 in flatview_write exec.c
    #6 0x558d8d143421 in address_space_write (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x3a80421)
    #7 0x558d918ff5c9 in __wrap_qtest_writel (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x823c5c9)
    #8 0x558d919a3cf0 in dispatch_mmio_write stateful_fuzz.c
    #9 0x558d9191dcf5 in dispatch_event stateful_fuzz.c
    #10 0x558d919a5fda in stateful_fuzz stateful_fuzz.c
    #11 0x558d918f588e in LLVMFuzzerTestOneInput (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x823288e)
    #12 0x558d8cff6803 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:607
    #13 0x558d8cfd9b2a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #14 0x558d8cfe47e4 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:883
    #15 0x558d8cfba3d2 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #16 0x7f4379acabf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
    #17 0x558d8cfcff59 in _start (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x390cf59)

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /root/qemu/hw/ssi/xilinx_spips.c:1035:22 in 
MS: 0 ; base unit: 0000000000000000000000000000000000000000
```

### Reproducer steps

root@fff5a5933072:~/qemu/build-san-5# ./qemu-fuzz-aarch64 --fuzz-target=stateful-fuzz-xlnx-zynqmp-qspips crash-69ad8465205e9ac08b9fc1f0d469674e81a73019 
## Contact

Let us know if I need to provide more information.
