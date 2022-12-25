# Shift exponent is too large in xilinx_spips_read()

# Shift exponent is too large in xilinx_spips_read
## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type

aarch64, xlnx_zynqmp_qspips, storage

### Bug Type: Large Shift

### Stack traces, crash details

```
root@fff5a5933072:~/qemu/build-san-5# ./qemu-fuzz-aarch64 --fuzz-target=stateful-fuzz-xlnx-zynqmp-qspips crash-c1ae8ecd443456fab947fee4e1e967c074fd9763 
INFO: found LLVMFuzzerCustomMutator (0x55bbd35d3980). Disabling -len_control by default.
INFO: libFuzzer ignores flags that start with '--'
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 728348722
INFO: Loaded 1 modules   (1042851 inline 8-bit counters): 1042851 [0x55bbd72fc000, 0x55bbd73fa9a3), 
INFO: Loaded 1 PC tables (1042851 PCs): 1042851 [0x55bbd6311830,0x55bbd72fb260), 
./qemu-fuzz-aarch64: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
Matching objects by name , *spi*, *lqspi*
This process will fuzz the following MemoryRegions:
  * spi[0] (size 830)
  * spi[0] (size 830)
  * spi[0] (size 830)
  * lqspi[0] (size 2000000)
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
Running: crash-c1ae8ecd443456fab947fee4e1e967c074fd9763
/root/qemu/hw/ssi/xilinx_spips.c:921:17: runtime error: shift exponent 32 is too large for 32-bit type 'uint32_t' (aka 'unsigned int')
    #0 0x55bbd200ec0f in xilinx_spips_read xilinx_spips.c
    #1 0x55bbd2024a8e in xlnx_zynqmp_qspips_read xilinx_spips.c
    #2 0x55bbcfc01c41 in memory_region_read_accessor memory.c
    #3 0x55bbcfb935a6 in access_with_adjusted_size memory.c
    #4 0x55bbcfb8f75b in memory_region_dispatch_read1 memory.c
    #5 0x55bbcfb8e98d in memory_region_dispatch_read (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x480b98d)
    #6 0x55bbcee00788 in flatview_read_continue (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x3a7d788)
    #7 0x55bbcee0306b in flatview_read exec.c
    #8 0x55bbcee02bc1 in address_space_read_full (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x3a7fbc1)
    #9 0x55bbd35bc898 in __wrap_qtest_readw (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x8239898)
    #10 0x55bbd3663bca in dispatch_mmio_read stateful_fuzz.c
    #11 0x55bbd35ddba7 in dispatch_event stateful_fuzz.c
    #12 0x55bbd366608a in stateful_fuzz stateful_fuzz.c
    #13 0x55bbd35b593e in LLVMFuzzerTestOneInput (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x823293e)
    #14 0x55bbcecb6803 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:607
    #15 0x55bbcec99b2a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #16 0x55bbceca47e4 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:883
    #17 0x55bbcec7a3d2 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #18 0x7fa387815bf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
    #19 0x55bbcec8ff59 in _start (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x390cf59)

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /root/qemu/hw/ssi/xilinx_spips.c:921:17 in 
MS: 0 ; base unit: 0000000000000000000000000000000000000000```

### Reproducer steps

root@fff5a5933072:~/qemu/build-san-5# ./qemu-fuzz-aarch64 --fuzz-target=stateful-fuzz-xlnx-zynqmp-qspips crash-c1ae8ecd443456fab947fee4e1e967c074fd9763 
## Contact

Let us know if I need to provide more information.
