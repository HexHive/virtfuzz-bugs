# Index 119 out of bounds for type uint32_t[119] in xlnx_dp_vblend_read

# Index 119 out of bounds for type 'uint32_t [119] in xlnx_dp_vblend_read
## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type
aarch64, xlnx_dp, display

### Bug Type: Out-of-bounds Read/Write

### Stack traces, crash details

```
root@fff5a5933072:~/qemu/build-san-6# ./qemu-fuzz-aarch64 --fuzz-target=stateful-fuzz-xlnx-dp crash-3fad1ba43f006ce831ec281e5b52fa42c27b0bf8 
==44736==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x5651017131d0). Disabling -len_control by default.
INFO: libFuzzer ignores flags that start with '--'
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1509753334
INFO: Loaded 1 modules   (1103891 inline 8-bit counters): 1103891 [0x56510a761000, 0x56510a86e813), 
INFO: Loaded 1 PC tables (1103891 PCs): 1103891 [0x5651096886a0,0x56510a7607d0), 
./qemu-fuzz-aarch64: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
Matching objects by name , *.core*, *.v_blend*, *.av_buffer_manager*, *.audio*
This process will fuzz the following MemoryRegions:
  * xlnx.v-dp.audio[0] (size 50)
  * xlnx.v-dp.v_blend[0] (size 1df)
  * xlnx.v-dp.av_buffer_manager[0] (size 238)
  * xlnx.v-dp.core[0] (size 3af)
This process will fuzz through the following interfaces:
  * xlnx.v-dp.core, EVENT_TYPE_MMIO_READ, 0xfd4a0000 +0x3af, 4,4
  * xlnx.v-dp.core, EVENT_TYPE_MMIO_WRITE, 0xfd4a0000 +0x3af, 4,4
  * xlnx.v-dp.v_blend, EVENT_TYPE_MMIO_READ, 0xfd4aa000 +0x1df, 4,4
  * xlnx.v-dp.v_blend, EVENT_TYPE_MMIO_WRITE, 0xfd4aa000 +0x1df, 4,4
  * xlnx.v-dp.av_buffer_manager, EVENT_TYPE_MMIO_READ, 0xfd4ab000 +0x238, 4,4
  * xlnx.v-dp.av_buffer_manager, EVENT_TYPE_MMIO_WRITE, 0xfd4ab000 +0x238, 4,4
  * xlnx.v-dp.audio, EVENT_TYPE_MMIO_READ, 0xfd4ac000 +0x50, 1,4
  * xlnx.v-dp.audio, EVENT_TYPE_MMIO_WRITE, 0xfd4ac000 +0x50, 1,4
  * xlnx.v-dp.core, EVENT_TYPE_MMIO_READ, 0xfd4a0000 +0x3af, 4,4
  * xlnx.v-dp.core, EVENT_TYPE_MMIO_WRITE, 0xfd4a0000 +0x3af, 4,4
  * xlnx.v-dp.v_blend, EVENT_TYPE_MMIO_READ, 0xfd4aa000 +0x1df, 4,4
  * xlnx.v-dp.v_blend, EVENT_TYPE_MMIO_WRITE, 0xfd4aa000 +0x1df, 4,4
  * xlnx.v-dp.av_buffer_manager, EVENT_TYPE_MMIO_READ, 0xfd4ab000 +0x238, 4,4
  * xlnx.v-dp.av_buffer_manager, EVENT_TYPE_MMIO_WRITE, 0xfd4ab000 +0x238, 4,4
  * xlnx.v-dp.audio, EVENT_TYPE_MMIO_READ, 0xfd4ac000 +0x50, 1,4
  * xlnx.v-dp.audio, EVENT_TYPE_MMIO_WRITE, 0xfd4ac000 +0x50, 1,4
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 11 ft: 12 corp: 1/1b exec/s: 0 rss: 499Mb
Running: crash-3fad1ba43f006ce831ec281e5b52fa42c27b0bf8
../hw/display/xlnx_dp.c:1001:12: runtime error: index 119 out of bounds for type 'uint32_t [119]'
    #0 0x565103859b5b in xlnx_dp_vblend_read /root/qemu/build-san-6/../hw/display/xlnx_dp.c:1001:12
    #1 0x56510510a7a1 in memory_region_read_accessor /root/qemu/build-san-6/../softmmu/memory.c:442:11
    #2 0x565105099f96 in access_with_adjusted_size /root/qemu/build-san-6/../softmmu/memory.c:552:18
    #3 0x56510509614b in memory_region_dispatch_read1 /root/qemu/build-san-6/../softmmu/memory.c:1422:16
    #4 0x56510509537d in memory_region_dispatch_read /root/qemu/build-san-6/../softmmu/memory.c:1450:9
    #5 0x5651051f13b8 in flatview_read_continue /root/qemu/build-san-6/../softmmu/physmem.c:2810:23
    #6 0x5651051f397b in flatview_read /root/qemu/build-san-6/../softmmu/physmem.c:2849:12
    #7 0x5651051f34d1 in address_space_read_full /root/qemu/build-san-6/../softmmu/physmem.c:2862:18
    #8 0x5651016fd268 in address_space_read /root/qemu/include/exec/memory.h:2523:18
    #9 0x5651016fd268 in __wrap_qtest_readl /root/qemu/build-san-6/../tests/qtest/fuzz/qtest_wrappers.c:134:9
    #10 0x5651017a343a in dispatch_mmio_read /root/qemu/build-san-6/../tests/qtest/fuzz/stateful_fuzz_dispatch.h:29:13
    #11 0x56510171d3f7 in dispatch_event /root/qemu/build-san-6/../tests/qtest/fuzz/stateful_fuzz_dispatch.h:172:13
    #12 0x5651017a58da in stateful_fuzz /root/qemu/build-san-6/../tests/qtest/fuzz/stateful_fuzz.c:133:13
    #13 0x5651017b1c7e in LLVMFuzzerTestOneInput /root/qemu/build-san-6/../tests/qtest/fuzz/fuzz.c:151:5
    #14 0x5651015f5413 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:607
    #15 0x5651015d873a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #16 0x5651015e33f4 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:883
    #17 0x5651015c56b2 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #18 0x7f4f1753dbf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
    #19 0x5651015ceb69 in _start (/root/qemu/build-san-6/qemu-fuzz-aarch64+0x3c91b69)

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../hw/display/xlnx_dp.c:1001:12 in 
MS: 0 ; base unit: 0000000000000000000000000000000000000000```

### Reproducer steps

root@fff5a5933072:~/qemu/build-san-6# ./qemu-fuzz-aarch64 --fuzz-target=stateful-fuzz-xlnx-dp crash-3fad1ba43f006ce831ec281e5b52fa42c27b0bf8 
## Contact

Let us know if I need to provide more information.
