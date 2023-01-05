# Overflow in xlnx_dp_aux_push_rx_fifo()

Pushing stuff into s->rx_fifo many times make s->rx_fifo overflow.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 7.2.50, 222059a0fccf4af3be776fe35a5ea2d6a68f9a0b, Ubuntu 20.04

### VM architecture, device, device type

aarch64, xlnx_dp, display

### Bug Type: Assertion Failure

### Stack traces, crash details

```
root@3728b1f90dbd:~/bugs/metadata/xlnx_dp-03# bash -x xlnx_dp-03.videzzo 
+ DEFAULT_INPUT_MAXSIZE=10000000
+ ./qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp -max_len=10000000 -detect_leaks=0 poc-qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp-crash-a6a2bd23ff0408dd50652670fdcdf9f5ceaab95d.minimized
==767==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x55d36d8b3870). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1781001818
INFO: Loaded 1 modules   (618604 inline 8-bit counters): 618604 [0x55d370a12000, 0x55d370aa906c), 
INFO: Loaded 1 PC tables (618604 PCs): 618604 [0x55d3700a0ce0,0x55d370a113a0), 
./qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
Matching objects by name , *.core*, *.v_blend*, *.av_buffer_manager*, *.audio*
This process will fuzz the following MemoryRegions:
  * xlnx.v-dp.core[0] (size 3b0)
  * xlnx.v-dp.v_blend[0] (size 1e0)
  * xlnx.v-dp.audio[0] (size 50)
  * xlnx.v-dp.av_buffer_manager[0] (size 238)
This process will fuzz through the following interfaces:
  * clock_step, EVENT_TYPE_CLOCK_STEP, 0xffffffff +0xffffffff, 255,255
  * xlnx.v-dp.core, EVENT_TYPE_MMIO_READ, 0xfd4a0000 +0x3b0, 4,4
  * xlnx.v-dp.core, EVENT_TYPE_MMIO_WRITE, 0xfd4a0000 +0x3b0, 4,4
  * xlnx.v-dp.v_blend, EVENT_TYPE_MMIO_READ, 0xfd4aa000 +0x1e0, 4,4
  * xlnx.v-dp.v_blend, EVENT_TYPE_MMIO_WRITE, 0xfd4aa000 +0x1e0, 4,4
  * xlnx.v-dp.av_buffer_manager, EVENT_TYPE_MMIO_READ, 0xfd4ab000 +0x238, 4,4
  * xlnx.v-dp.av_buffer_manager, EVENT_TYPE_MMIO_WRITE, 0xfd4ab000 +0x238, 4,4
  * xlnx.v-dp.audio, EVENT_TYPE_MMIO_READ, 0xfd4ac000 +0x50, 1,4
  * xlnx.v-dp.audio, EVENT_TYPE_MMIO_WRITE, 0xfd4ac000 +0x50, 1,4
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 492Mb
Running: poc-qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp-crash-a6a2bd23ff0408dd50652670fdcdf9f5ceaab95d.minimized
qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp: ../util/fifo8.c:43: void fifo8_push_all(Fifo8 *, const uint8_t *, uint32_t): Assertion `fifo->num + num <= fifo->capacity' failed.
==767== ERROR: libFuzzer: deadly signal
    #0 0x55d368c8c10e in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86:3
    #1 0x55d368bdad81 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:38
    #2 0x55d368bb3cb6 in fuzzer::Fuzzer::CrashCallback() (.part.0) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:236:18
    #3 0x55d368bb3d82 in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:208:1
    #4 0x55d368bb3d82 in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207:19
    #5 0x7f9897d8741f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f)
    #6 0x7f9897b9900a in __libc_signal_restore_set /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/internal-signals.h:86:3
    #7 0x7f9897b9900a in raise /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/raise.c:48:3
    #8 0x7f9897b78858 in abort /build/glibc-SzIz7B/glibc-2.31/stdlib/abort.c:79:7
    #9 0x7f9897b78728 in __assert_fail_base /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:92:3
    #10 0x7f9897b89fd5 in __assert_fail /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:101:3
    #11 0x55d36d56bff3 in fifo8_push_all /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/fifo8.c:43:5
    #12 0x55d3695e64d3 in xlnx_dp_aux_push_rx_fifo /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/display/xlnx_dp.c:436:5
    #13 0x55d3695e1e9a in xlnx_dp_aux_set_command /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/display/xlnx_dp.c:513:13
    #14 0x55d3695dea92 in xlnx_dp_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/display/xlnx_dp.c:805:9
    #15 0x55d36c866ef3 in memory_region_write_accessor /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:492:5
    #16 0x55d36c866831 in access_with_adjusted_size /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:554:18
    #17 0x55d36c865156 in memory_region_dispatch_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:1514:16
    #18 0x55d36c8f330e in flatview_write_continue /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2825:23
    #19 0x55d36c8e144b in flatview_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2867:12
    #20 0x55d36c8e0f08 in address_space_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2963:18
    #21 0x55d368ccc0cb in qemu_writel /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1088:5
    #22 0x55d368cca544 in dispatch_mmio_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1229:28
    #23 0x55d36d8af22f in videzzo_dispatch_event /root/videzzo/videzzo.c:1122:5
    #24 0x55d36d8a65ab in __videzzo_execute_one_input /root/videzzo/videzzo.c:272:9
    #25 0x55d36d8a6480 in videzzo_execute_one_input /root/videzzo/videzzo.c:313:9
    #26 0x55d368cd310c in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1504:12
    #27 0x55d36d8b3b12 in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1891:18
    #28 0x55d368bb4826 in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:594:17
    #29 0x55d368b97454 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #30 0x55d368ba23fe in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:885:19
    #31 0x55d368b8e9e6 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #32 0x7f9897b7a082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #33 0x55d368b8ea3d in _start (/root/bugs/metadata/xlnx_dp-03/qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp+0x3291a3d)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000
0x1,0x9,0x0,0x1,0x4a,0xfd,0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x0,0xe6,0x41,0xb1,0x7f,0x0,0x0,0x0,0x0,0x1,0x9,0x0,0x1,0x4a,0xfd,0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x0,0xe6,0x41,0xb1,0x7f,0x0,0x0,0x0,0x0,0x1,0x9,0x0,0x1,0x4a,0xfd,0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x0,0xe6,0x41,0xb1,0x7f,0x0,0x0,0x0,0x0,
\x01\x09\x00\x01J\xfd\x00\x00\x00\x00\x04\x00\x00\x00\xe6A\xb1\x7f\x00\x00\x00\x00\x01\x09\x00\x01J\xfd\x00\x00\x00\x00\x04\x00\x00\x00\xe6A\xb1\x7f\x00\x00\x00\x00\x01\x09\x00\x01J\xfd\x00\x00\x00\x00\x04\x00\x00\x00\xe6A\xb1\x7f\x00\x00\x00\x00
```

### Reproducer steps

```
export QEMU=/path/to/qemu-system-aarch64

cat << EOF | $QEMU \
-machine xlnx-zcu102 -monitor none -serial none \
-display none -nodefaults -qtest stdio
writel 0xfd4a0100 0x7fb141e6
writel 0xfd4a0100 0x7fb141e6
writel 0xfd4a0100 0x7fb141e6
EOF
```

## Contact

Let us know if I need to provide more information.
