# Assertion failure in fifo8_pop()

# Assertion failure in fifo8_pop through xlnx-zynqmp-can
## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type
aarch64, xlnx_zynqmp_can, net

### Bug Type: Out-of-Memory

### Stack traces, crash details

```
root@e1fc40420e44:~/evaluation/bug-reports#  /tmp/tmp.LaCEhRp4kg/picire_reproduce.sh /tmp/tmp.LaCEhRp4kg/picire_inputs.20211003_165230/picire_inputs 
==20287==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x556d5da3e1d0). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1255858598
INFO: Loaded 1 modules   (1103894 inline 8-bit counters): 1103894 [0x556d66a8c000, 0x556d66b99816), 
INFO: Loaded 1 PC tables (1103894 PCs): 1103894 [0x556d659b36c0,0x556d66a8b820), 
/root/qemu/build-san-6/qemu-fuzz-aarch64-target-stateful-fuzz-xlnx-zynqmp-can: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
Matching objects by name , *xlnx.zynqmp-can*
This process will fuzz the following MemoryRegions:
  * xlnx.zynqmp-can[0] (size 84)
  * xlnx.zynqmp-can[0] (size 84)
  * xlnx.zynqmp-can[1] (size 84)
  * xlnx.zynqmp-can[1] (size 84)
This process will fuzz through the following interfaces:
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_READ, 0xff060000 +0x84, 1,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_WRITE, 0xff060000 +0x84, 1,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_READ, 0xff060000 +0x84, 4,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_WRITE, 0xff060000 +0x84, 4,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_READ, 0xff070000 +0x84, 1,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_WRITE, 0xff070000 +0x84, 1,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_READ, 0xff070000 +0x84, 4,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_WRITE, 0xff070000 +0x84, 4,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_READ, 0xff060000 +0x84, 1,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_WRITE, 0xff060000 +0x84, 1,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_READ, 0xff060000 +0x84, 4,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_WRITE, 0xff060000 +0x84, 4,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_READ, 0xff070000 +0x84, 1,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_WRITE, 0xff070000 +0x84, 1,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_READ, 0xff070000 +0x84, 4,4
  * xlnx.zynqmp-can, EVENT_TYPE_MMIO_WRITE, 0xff070000 +0x84, 4,4
INFO: seed corpus: files: 1 min: 2545b max: 2545b total: 2545b rss: 499Mb
#3	INITED cov: 2103 ft: 2104 corp: 1/2545b exec/s: 0 rss: 500Mb
Running: /root/evaluation/bug-reports/crash-5069a575d11501dee60e46bf497c2fc9bba08770
qemu-fuzz-aarch64-target-stateful-fuzz-xlnx-zynqmp-can: ../util/fifo8.c:62: uint8_t fifo8_pop(Fifo8 *): Assertion `fifo->num > 0' failed.
==20287== ERROR: libFuzzer: deadly signal
    #0 0x556d5d9ec128 in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86
    #1 0x556d5d946ae2 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210
    #2 0x556d5d8f03e0 in fuzzer::Fuzzer::CrashCallback() (.part.290) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:235
    #3 0x556d5d91faac in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207
    #4 0x556d5d91faac in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:206
    #5 0x7fa52614f97f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1297f)
    #6 0x7fa525766fb6 in __libc_signal_restore_set /build/glibc-S9d2JN/glibc-2.27/signal/../sysdeps/unix/sysv/linux/nptl-signals.h:80
    #7 0x7fa525766fb6 in raise /build/glibc-S9d2JN/glibc-2.27/signal/../sysdeps/unix/sysv/linux/raise.c:48
    #8 0x7fa525768920 in abort /build/glibc-S9d2JN/glibc-2.27/stdlib/abort.c:79
    #9 0x7fa525758489 in __assert_fail_base /build/glibc-S9d2JN/glibc-2.27/assert/assert.c:92
    #10 0x7fa525758501 in __assert_fail /build/glibc-S9d2JN/glibc-2.27/assert/assert.c:101
    #11 0x556d6307b7b2 in fifo8_pop /root/qemu/build-san-6/../util/fifo8.c:62:5
    #12 0x556d5ef8fa23 in fifo32_pop /root/qemu/include/qemu/fifo32.h:137:17
    #13 0x556d5ef852d5 in transfer_fifo /root/qemu/build-san-6/../hw/net/can/xlnx-zynqmp-can.c:456:23
    #14 0x556d5ef7a17d in can_srr_pre_write /root/qemu/build-san-6/../hw/net/can/xlnx-zynqmp-can.c:529:9
    #15 0x556d5ee3787a in register_write /root/qemu/build-san-6/../hw/core/register.c:111:19
    #16 0x556d5ee3bd48 in register_write_memory /root/qemu/build-san-6/../hw/core/register.c:203:5
    #17 0x556d613c5a81 in memory_region_write_accessor /root/qemu/build-san-6/../softmmu/memory.c:491:5
    #18 0x556d613c5056 in access_with_adjusted_size /root/qemu/build-san-6/../softmmu/memory.c:552:18
    #19 0x556d613c2fa1 in memory_region_dispatch_write /root/qemu/build-san-6/../softmmu/memory.c:1502:16
    #20 0x556d61536169 in flatview_write_continue /root/qemu/build-san-6/../softmmu/physmem.c:2746:23
    #21 0x556d6151f2a2 in flatview_write /root/qemu/build-san-6/../softmmu/physmem.c:2786:14
    #22 0x556d6151edf1 in address_space_write /root/qemu/build-san-6/../softmmu/physmem.c:2878:18
    #23 0x556d5da2a619 in __wrap_qtest_writel /root/qemu/build-san-6/../tests/qtest/fuzz/qtest_wrappers.c:177:9
    #24 0x556d5dace5f0 in dispatch_mmio_write /root/qemu/build-san-6/../tests/qtest/fuzz/stateful_fuzz_dispatch.h:79:13
    #25 0x556d5da485f5 in dispatch_event /root/qemu/build-san-6/../tests/qtest/fuzz/stateful_fuzz_dispatch.h:175:13
    #26 0x556d5dad08da in stateful_fuzz /root/qemu/build-san-6/../tests/qtest/fuzz/stateful_fuzz.c:133:13
    #27 0x556d5dadcc7e in LLVMFuzzerTestOneInput /root/qemu/build-san-6/../tests/qtest/fuzz/fuzz.c:151:5
    #28 0x556d5d920413 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:607
    #29 0x556d5d90373a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #30 0x556d5d90e3f4 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:883
    #31 0x556d5d8f06b2 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #32 0x7fa525749bf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
    #33 0x556d5d8f9b69 in _start (/root/qemu/build-san-6/qemu-fuzz-aarch64+0x3c91b69)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000```

### Reproducer steps

bash 21.sh
## Contact

Let us know if I need to provide more information.
