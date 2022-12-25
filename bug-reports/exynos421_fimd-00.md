# Assertion failure in fimd_update_memory_section()

# Assertion failure in fimd_update_memory_section

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type

arm, exynos421_fimd, display

### Bug Type: Assertion Failure

### Stack traces, crash details

```
qemu-fuzz-arm-target-stateful-fuzz-exynos4210-fimd: /root/qemu/hw/display/exynos4210_fimd.c:1152: void fimd_update_memory_section(Exynos4210fimdState *, unsigned int): Assertion `w->mem_section.mr' failed.
==2617== ERROR: libFuzzer: deadly signal
    #0 0x559f6b00e508 in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86
    #1 0x559f6af68ec2 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210
    #2 0x559f6af060f0 in fuzzer::Fuzzer::CrashCallback() (.part.290) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:235
    #3 0x559f6af41e8c in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207
    #4 0x559f6af41e8c in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:206
    #5 0x7fc58982097f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1297f)
    #6 0x7fc58903ffb6 in __libc_signal_restore_set /build/glibc-S9d2JN/glibc-2.27/signal/../sysdeps/unix/sysv/linux/nptl-signals.h:80
    #7 0x7fc58903ffb6 in raise /build/glibc-S9d2JN/glibc-2.27/signal/../sysdeps/unix/sysv/linux/raise.c:48
    #8 0x7fc589041920 in abort /build/glibc-S9d2JN/glibc-2.27/stdlib/abort.c:79
    #9 0x7fc589031489 in __assert_fail_base /build/glibc-S9d2JN/glibc-2.27/assert/assert.c:92
    #10 0x7fc589031501 in __assert_fail /build/glibc-S9d2JN/glibc-2.27/assert/assert.c:101
    #11 0x559f6ce6ad9d in fimd_update_memory_section exynos4210_fimd.c
    #12 0x559f6ce63057 in exynos4210_fimd_enable exynos4210_fimd.c
    #13 0x559f6ce56143 in exynos4210_fimd_write exynos4210_fimd.c
    #14 0x559f6bde4d21 in memory_region_write_accessor memory.c
    #15 0x559f6bde42f6 in access_with_adjusted_size memory.c
    #16 0x559f6bde2241 in memory_region_dispatch_write (/root/qemu/build-san-5/qemu-fuzz-arm-target-stateful-fuzz-exynos4210-fimd+0x458b241)
    #17 0x559f6b0a5b89 in flatview_write_continue exec.c
    #18 0x559f6b08fcb2 in flatview_write exec.c
    #19 0x559f6b08f801 in address_space_write (/root/qemu/build-san-5/qemu-fuzz-arm-target-stateful-fuzz-exynos4210-fimd+0x3838801)
    #20 0x559f6f3983f9 in __wrap_qtest_writel (/root/qemu/build-san-5/qemu-fuzz-arm-target-stateful-fuzz-exynos4210-fimd+0x7b413f9)
    #21 0x559f6f43cb20 in dispatch_mmio_write stateful_fuzz.c
    #22 0x559f6f3b6b25 in dispatch_event stateful_fuzz.c
    #23 0x559f6f43ee0a in stateful_fuzz stateful_fuzz.c
    #24 0x559f6f38e6be in LLVMFuzzerTestOneInput (/root/qemu/build-san-5/qemu-fuzz-arm-target-stateful-fuzz-exynos4210-fimd+0x7b376be)
    #25 0x559f6af427f3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:607
    #26 0x559f6af25b1a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #27 0x559f6af307d4 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:883
    #28 0x559f6af063c2 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #29 0x7fc589022bf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
    #30 0x559f6af1bf49 in _start (/root/qemu/build-san-5/qemu-fuzz-arm-target-stateful-fuzz-exynos4210-fimd+0x36c4f49)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000```

### Reproducer steps

bash 12.sh
## Contact

Let us know if I need to provide more information.
