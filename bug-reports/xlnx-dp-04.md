tag: arch: aarch64
tag: type: OOM

# Out-of-memory in xlnx_dp_recreate_surface
## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Stack traces, crash details

```
root@e1fc40420e44:~/evaluation/bug-reports# /tmp/tmp.zsF1J7FK8Q/picire_reproduce.sh /tmp/tmp.zsF1J7FK8Q/picire_inputs.20211003_191503/picire_inputs
INFO: found LLVMFuzzerCustomMutator (0x55de89ef0b20). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3516093713
INFO: Loaded 1 modules   (1042861 inline 8-bit counters): 1042861 [0x55de8dc19000, 0x55de8dd179ad), 
INFO: Loaded 1 PC tables (1042861 PCs): 1042861 [0x55de8cc2e850,0x55de8dc18320), 
/root/qemu/build-san-5/qemu-fuzz-aarch64-target-stateful-fuzz-xlnx-dp: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
Matching objects by name , *.core*, *.v_blend*, *.av_buffer_manager*, *.audio*
This process will fuzz the following MemoryRegions:
  * xlnx.v-dp.core[0] (size 3af)
  * xlnx.v-dp.audio[0] (size 50)
  * xlnx.v-dp.v_blend[0] (size 1df)
  * xlnx.v-dp.av_buffer_manager[0] (size 238)
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
INFO: seed corpus: files: 1 min: 1894b max: 1894b total: 1894b rss: 487Mb
#3	INITED cov: 1741 ft: 1738 corp: 1/1894b exec/s: 0 rss: 488Mb
Running: /root/evaluation/bug-reports/oom-d267660be9d6f07e08171675a6a2921b65f19390
==21347== ERROR: libFuzzer: out-of-memory (malloc(2829539160))
   To change the out-of-memory limit use -rss_limit_mb=<N>

    #0 0x55de8569f518 in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86
    #1 0x55de855f9ed2 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210
    #2 0x55de855970a8 in fuzzer::Fuzzer::HandleMalloc(unsigned long) (.part.288) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:133
    #3 0x55de855d29f0 in fuzzer::Fuzzer::HandleMalloc(unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:88
    #4 0x55de855d29f0 in fuzzer::MallocHook(void const volatile*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:102
    #5 0x55de856aaa3e in __sanitizer::RunMallocHooks(void const*, unsigned long) /root/llvm-project/compiler-rt/lib/sanitizer_common/sanitizer_common.cpp:309
    #6 0x55de856072ab in __asan::Allocator::Allocate(unsigned long, unsigned long, __sanitizer::BufferedStackTrace*, __asan::AllocType, bool) /root/llvm-project/compiler-rt/lib/asan/asan_allocator.cpp:611
    #7 0x55de8560127c in __asan::Allocator::Calloc(unsigned long, unsigned long, __sanitizer::BufferedStackTrace*) /root/llvm-project/compiler-rt/lib/asan/asan_allocator.cpp:748
    #8 0x55de8560127c in __asan::asan_calloc(unsigned long, unsigned long, __sanitizer::BufferedStackTrace*) /root/llvm-project/compiler-rt/lib/asan/asan_allocator.cpp:984
    #9 0x55de8568f4d6 in __interceptor_calloc /root/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:155
    #10 0x7f9d6db811f9  (/usr/lib/x86_64-linux-gnu/libpixman-1.so.0+0x191f9)
    #11 0x7f9d6db812ac  (/usr/lib/x86_64-linux-gnu/libpixman-1.so.0+0x192ac)
    #12 0x55de891e827f in qemu_create_displaysurface_from (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x754827f)
    #13 0x55de87aaede3 in xlnx_dp_recreate_surface xlnx_dp.c
    #14 0x55de87aaa2e5 in xlnx_dp_write xlnx_dp.c
    #15 0x55de864b0fd1 in memory_region_write_accessor memory.c
    #16 0x55de864b05a6 in access_with_adjusted_size memory.c
    #17 0x55de864ae4f1 in memory_region_dispatch_write (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x480e4f1)
    #18 0x55de85736749 in flatview_write_continue exec.c
    #19 0x55de857208d2 in flatview_write exec.c
    #20 0x55de85720421 in address_space_write (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x3a80421)
    #21 0x55de89edc819 in __wrap_qtest_writel (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x823c819)
    #22 0x55de89f80f40 in dispatch_mmio_write stateful_fuzz.c
    #23 0x55de89efaf45 in dispatch_event stateful_fuzz.c
    #24 0x55de89f8322a in stateful_fuzz stateful_fuzz.c
    #25 0x55de89ed2ade in LLVMFuzzerTestOneInput (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x8232ade)
    #26 0x55de855d3803 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:607
    #27 0x55de855b6b2a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #28 0x55de855c17e4 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:883
    #29 0x55de855973d2 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #30 0x7f9d6bb61bf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
    #31 0x55de855acf59 in _start (/root/qemu/build-san-5/qemu-fuzz-aarch64+0x390cf59)

MS: 0 ; base unit: 0000000000000000000000000000000000000000
SUMMARY: libFuzzer: out-of-memory```

### Reproducer steps

bash 24.sh
## Contact

Let me know if I need to provide more information.
