# Assertion failure in fimd_update_memory_section()

It seems the frame buffer is not properly initialized before usage.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 7.2.50, 222059a0fccf4af3be776fe35a5ea2d6a68f9a0b, Ubuntu 20.04

### VM architecture, device, device type

arm, exynos421_fimd, display

### Bug Type: Assertion Failure

### Stack traces, crash details

```
root@621cbd136b6f:~/videzzo/videzzo_qemu/out-san# DEFAULT_INPUT_MAXSIZE=10000000 /root/videzzo/videzzo_qemu/out-san/qemu-videzzo-arm-target-videzzo-fuzz-exynos4210-fimd  -max_len=10000000 -detect_leaks=0 poc-qemu-videzzo-arm-target-videzzo-fuzz-exynos4210-fimd-crash-eda3de9b6941dd8c14e22959b56dbe5d8d07dae3
==13250==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x5590b12d2240). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3376651198
INFO: Loaded 1 modules   (583356 inline 8-bit counters): 583356 [0x5590b4672000, 0x5590b47006bc), 
INFO: Loaded 1 PC tables (583356 PCs): 583356 [0x5590b3d8b3b0,0x5590b4671f70), 
/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-arm-target-videzzo-fuzz-exynos4210-fimd: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
Matching objects by name , *exynos4210.fimd*
This process will fuzz the following MemoryRegions:
  * exynos4210.fimd[0] (size 4114)
This process will fuzz through the following interfaces:
  * clock_step, EVENT_TYPE_CLOCK_STEP, 0xffffffff +0xffffffff, 255,255
  * exynos4210.fimd, EVENT_TYPE_MMIO_READ, 0x11c00000 +0x4114, 4,4
  * exynos4210.fimd, EVENT_TYPE_MMIO_WRITE, 0x11c00000 +0x4114, 4,4
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 227Mb
Running: poc-qemu-videzzo-arm-target-videzzo-fuzz-exynos4210-fimd-crash-eda3de9b6941dd8c14e22959b56dbe5d8d07dae3
qemu-videzzo-arm-target-videzzo-fuzz-exynos4210-fimd: ../hw/display/exynos4210_fimd.c:1152: void fimd_update_memory_section(Exynos4210fimdState *, unsigned int): Assertion `w->mem_section.mr' failed.
==13250== ERROR: libFuzzer: deadly signal
    #0 0x5590acce30ee in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86:3
    #1 0x5590acc31d61 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:38
    #2 0x5590acc0ac96 in fuzzer::Fuzzer::CrashCallback() (.part.0) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:236:18
    #3 0x5590acc0ad62 in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:208:1
    #4 0x5590acc0ad62 in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207:19
    #5 0x7f9ed33c741f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f)
    #6 0x7f9ed31d900a in __libc_signal_restore_set /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/internal-signals.h:86:3
    #7 0x7f9ed31d900a in raise /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/raise.c:48:3
    #8 0x7f9ed31b8858 in abort /build/glibc-SzIz7B/glibc-2.31/stdlib/abort.c:79:7
    #9 0x7f9ed31b8728 in __assert_fail_base /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:92:3
    #10 0x7f9ed31c9fd5 in __assert_fail /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:101:3
    #11 0x5590ad56dce3 in fimd_update_memory_section /root/videzzo/videzzo_qemu/qemu/out-san/../hw/display/exynos4210_fimd.c:1152:5
    #12 0x5590ad565fb7 in exynos4210_fimd_enable /root/videzzo/videzzo_qemu/qemu/out-san/../hw/display/exynos4210_fimd.c:1198:13
    #13 0x5590ad5590a3 in exynos4210_fimd_write /root/videzzo/videzzo_qemu/qemu/out-san/../hw/display/exynos4210_fimd.c:1387:13
    #14 0x5590b03e7bc3 in memory_region_write_accessor /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/memory.c:493:5
    #15 0x5590b03e7501 in access_with_adjusted_size /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/memory.c:555:18
    #16 0x5590b03e5e26 in memory_region_dispatch_write /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/memory.c:1515:16
    #17 0x5590b047669e in flatview_write_continue /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/physmem.c:2825:23
    #18 0x5590b046444b in flatview_write /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/physmem.c:2867:12
    #19 0x5590b0463f08 in address_space_write /root/videzzo/videzzo_qemu/qemu/out-san/../softmmu/physmem.c:2963:18
    #20 0x5590acd23d38 in qemu_writel /root/videzzo/videzzo_qemu/qemu/out-san/../tests/qtest/videzzo/videzzo_qemu.c:1096:5
    #21 0x5590acd220a3 in dispatch_mmio_write /root/videzzo/videzzo_qemu/qemu/out-san/../tests/qtest/videzzo/videzzo_qemu.c:1245:28
    #22 0x5590b12cd6bf in videzzo_dispatch_event /root/videzzo/videzzo.c:1140:5
    #23 0x5590b12c4a3d in __videzzo_execute_one_input /root/videzzo/videzzo.c:288:9
    #24 0x5590b12c47e4 in videzzo_execute_one_input /root/videzzo/videzzo.c:329:9
    #25 0x5590acd2b07c in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/out-san/../tests/qtest/videzzo/videzzo_qemu.c:1520:12
    #26 0x5590b12d250b in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1910:18
    #27 0x5590acc0b806 in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:594:17
    #28 0x5590acbee434 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #29 0x5590acbf93de in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:885:19
    #30 0x5590acbe59c6 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #31 0x7f9ed31ba082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #32 0x5590acbe5a1d in _start (/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-arm-target-videzzo-fuzz-exynos4210-fimd+0x31cea1d)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000
```

### Reproducer steps

```
export QEMU=/path/to/qemu-system-arm

cat << EOF | $QEMU \
-machine smdkc210 -monitor none -serial none \
-display none -nodefaults -qtest stdio
writel 0x11c00020 0x3454d403
writel 0x11c00000 0x61988eaf
EOF
```

## Contact

Let us know if I need to provide more information.
