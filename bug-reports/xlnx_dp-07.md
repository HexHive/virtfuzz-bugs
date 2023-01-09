# Overflow in xlnx_dp_aux_push_tx_fifo()

Invoking xlnx_dp_aux_push_tx_fifo() 17 times overflow the s->tx_fifo.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 7.2.50, 222059a0fccf4af3be776fe35a5ea2d6a68f9a0b, Ubuntu 20.04

### VM architecture, device, device type

aarch64, xlnx_dp, display

### Bug Type: Assertion Failure

### Stack traces, crash details

```
root@621cbd136b6f:~/bugs/metadata/xlnx_dp-07# bash -x xlnx_dp-07.videzzo 
+ DEFAULT_INPUT_MAXSIZE=10000000
+ ./qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp -max_len=10000000 -detect_leaks=0 ./poc-qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp-crash-8070de484ac8d4d9bfff9b439311058e05b8b40f.minimized
==47609==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x564c9e37c2b0). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2128347645
INFO: Loaded 1 modules   (600768 inline 8-bit counters): 600768 [0x564ca198f000, 0x564ca1a21ac0), 
INFO: Loaded 1 PC tables (600768 PCs): 600768 [0x564ca1063b10,0x564ca198e710), 
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
#2      INITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 510Mb
Running: ./poc-qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp-crash-8070de484ac8d4d9bfff9b439311058e05b8b40f.minimized
qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp: ../util/fifo8.c:43: void fifo8_push_all(Fifo8 *, const uint8_t *, uint32_t): Assertion `fifo->num + num <= fifo->capacity' failed.
==47609== ERROR: libFuzzer: deadly signal
    #0 0x564c998420fe in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86:3
    #1 0x564c99790d71 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:38
    #2 0x564c99769ca6 in fuzzer::Fuzzer::CrashCallback() (.part.0) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:236:18
    #3 0x564c99769d72 in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:208:1
    #4 0x564c99769d72 in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207:19
    #5 0x7f8ef929941f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f)
    #6 0x7f8ef90ab00a in __libc_signal_restore_set /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/internal-signals.h:86:3
    #7 0x7f8ef90ab00a in raise /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/raise.c:48:3
    #8 0x7f8ef908a858 in abort /build/glibc-SzIz7B/glibc-2.31/stdlib/abort.c:79:7
    #9 0x7f8ef908a728 in __assert_fail_base /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:92:3
    #10 0x7f8ef909bfd5 in __assert_fail /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:101:3
    #11 0x564c9e1cdbb3 in fifo8_push_all /root/videzzo/videzzo_qemu/qemu/out-san/../util/fifo8.c:43:5
    #12 0x564c9a189c13 in xlnx_dp_aux_push_tx_fifo /root/videzzo/videzzo_qemu/qemu/out-san/../hw/display/xlnx_dp.c:467:5
    #13 0x564c9a1842f2 in xlnx_dp_write /root/videzzo/videzzo_qemu/qemu/out-san/../hw/display/xlnx_dp.c:857:9
    #14 0x564c9d491e93 in memory_region_write_accessor /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/memory.c:493:5
    #15 0x564c9d4917d1 in access_with_adjusted_size /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/memory.c:555:18
    #16 0x564c9d4900f6 in memory_region_dispatch_write /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/memory.c:1515:16
    #17 0x564c9d5209ce in flatview_write_continue /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/physmem.c:2825:23
    #18 0x564c9d50e77b in flatview_write /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/physmem.c:2867:12
    #19 0x564c9d50e238 in address_space_write /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/physmem.c:2963:18
    #20 0x564c99882d48 in qemu_writel /root/videzzo/videzzo_qemu/qemu/out-san/../tests/qtest/videzzo/videzzo_qemu.c:1096:5
    #21 0x564c998810b3 in dispatch_mmio_write /root/videzzo/videzzo_qemu/qemu/out-san/../tests/qtest/videzzo/videzzo_qemu.c:1245:28
    #22 0x564c9e37772f in videzzo_dispatch_event /root/videzzo/videzzo.c:1140:5
    #23 0x564c9e36eaad in __videzzo_execute_one_input /root/videzzo/videzzo.c:288:9
    #24 0x564c9e36e854 in videzzo_execute_one_input /root/videzzo/videzzo.c:329:9
    #25 0x564c9988a08c in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/out-san/../tests/qtest/videzzo/videzzo_qemu.c:1520:12
    #26 0x564c9e37c57b in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1910:18
    #27 0x564c9976a816 in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:594:17
    #28 0x564c9974d444 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #29 0x564c997583ee in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:885:19
    #30 0x564c997449d6 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #31 0x7f8ef908c082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #32 0x564c99744a2d in _start (/root/bugs/metadata/xlnx_dp-07/qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp+0x3453a2d)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000
```

### Reproducer steps

```
export QEMU=/path/to/qemu-system-aarch64

cat << EOF | $QEMU \
-machine xlnx-zcu102 -monitor none -serial none \
-display none -nodefaults -qtest stdio
writel 0xfd4a0104 0x6fed53ba
writel 0xfd4a0104 0x66554466
writel 0xfd4a0104 0x6fed53ba
writel 0xfd4a0104 0x6fed53ba
writel 0xfd4a0104 0x666e0fa2
writel 0xfd4a0104 0x666e0fa2
writel 0xfd4a0104 0x666e0fa2
writel 0xfd4a0104 0x6fed53ba
writel 0xfd4a0104 0x6fed53ba
writel 0xfd4a0104 0x66554466
writel 0xfd4a0104 0x66554466
writel 0xfd4a0104 0x66554466
writel 0xfd4a0104 0x66554466
writel 0xfd4a0104 0x66554466
writel 0xfd4a0104 0x6fed53ba
writel 0xfd4a0104 0x6fed53ba
writel 0xfd4a0104 0x6fed53ba
EOF
```

## Contact

Let us know if I need to provide more information.
