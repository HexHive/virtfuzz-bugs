# Assertion failed due to bad token

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 7.2.50, 13356edb87506c148b163b8c7eb0695647d00c2a, Ubuntu 20.04

### VM architecture, device, device type

i386, ehci, usb

### Bug Type: Assertion Failure

### Stack traces, crash details

```
==6809==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x55e0dba278f0). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3864254433
INFO: Loaded 1 modules   (417919 inline 8-bit counters): 417919 [0x55e0de64b000, 0x55e0de6b107f),
INFO: Loaded 1 PC tables (417919 PCs): 417919 [0x55e0ddfe9f70,0x55e0de64a760),
./qemu-videzzo-i386-target-videzzo-fuzz-ehci: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
Matching objects by name , *capabilities*, *operational*, *ports*
This process will fuzz the following MemoryRegions:
  * operational[0] (size 44)
  * ports[0] (size 18)
  * capabilities[0] (size 10)
This process will fuzz through the following interfaces:
  * clock_step, EVENT_TYPE_CLOCK_STEP, 0xffffffff +0xffffffff, 255,255
  * capabilities, EVENT_TYPE_MMIO_READ, 0xe0000000 +0x10, 1,4
  * capabilities, EVENT_TYPE_MMIO_WRITE, 0xe0000000 +0x10, 1,4
  * operational, EVENT_TYPE_MMIO_READ, 0xe0000020 +0x44, 4,4
  * operational, EVENT_TYPE_MMIO_WRITE, 0xe0000020 +0x44, 4,4
  * ports, EVENT_TYPE_MMIO_READ, 0xe0000064 +0x18, 4,4
  * ports, EVENT_TYPE_MMIO_WRITE, 0xe0000064 +0x18, 4,4
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 201Mb
Running: ./poc-qemu-videzzo-i386-target-videzzo-fuzz-ehci-crash-c92914f16aa438359c4d57eca1abcff9a28cf593.minimized.minimized
attempt to set frame list size -- value 4
ehci: ASYNC list address register set while async schedule
      is enabled and HC is enabled
bad token
bad token
qemu-videzzo-i386-target-videzzo-fuzz-ehci: ../hw/usb/core.c:744: struct USBEndpoint *usb_ep_get(USBDevice *, int, int): Assertion `pid == USB_TOKEN_IN || pid == USB_TOKEN_OUT' failed.
==6809== ERROR: libFuzzer: deadly signal
    #0 0x55e0d816079e in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86:3
    #1 0x55e0d80af451 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:38
    #2 0x55e0d8089be6 in fuzzer::Fuzzer::CrashCallback() (.part.0) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:235:18
    #3 0x55e0d8089cad in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207:1
    #4 0x55e0d8089cad in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:206:19
    #5 0x7f43dc0f141f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f)
    #6 0x7f43dbf0100a in __libc_signal_restore_set /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/internal-signals.h:86:3
    #7 0x7f43dbf0100a in raise /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/raise.c:48:3
    #8 0x7f43dbee0858 in abort /build/glibc-SzIz7B/glibc-2.31/stdlib/abort.c:79:7
    #9 0x7f43dbee0728 in __assert_fail_base /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:92:3
    #10 0x7f43dbef1fd5 in __assert_fail /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:101:3
    #11 0x55e0d95cfccd in usb_ep_get /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../hw/usb/core.c:744:5
    #12 0x55e0d96e7b95 in ehci_execute /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../hw/usb/hcd-ehci.c:1367:10
    #13 0x55e0d96d30aa in ehci_state_execute /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../hw/usb/hcd-ehci.c:1951:13
    #14 0x55e0d96c893d in ehci_advance_state /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../hw/usb/hcd-ehci.c:2095:21
    #15 0x55e0d96c7659 in ehci_advance_async_state /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../hw/usb/hcd-ehci.c:2164:9
    #16 0x55e0d96981c3 in ehci_work_bh /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../hw/usb/hcd-ehci.c:2332:9
    #17 0x55e0db8d9ec7 in aio_bh_call /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../util/async.c:151:5
    #18 0x55e0db8dac7c in aio_bh_poll /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../util/async.c:179:13
    #19 0x55e0db84f528 in aio_dispatch /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../util/aio-posix.c:421:5
    #20 0x55e0db8e0f9e in aio_ctx_dispatch /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../util/async.c:321:5
    #21 0x7f43dd1a417c in g_main_context_dispatch (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x5217c)
    #22 0x55e0db8e48d9 in glib_pollfds_poll /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../util/main-loop.c:295:9
    #23 0x55e0db8e3193 in os_host_main_loop_wait /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../util/main-loop.c:318:5
    #24 0x55e0db8e2d5c in main_loop_wait /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../util/main-loop.c:604:11
    #25 0x55e0d81b1f5f in flush_events /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../tests/qtest/videzzo/videzzo_qemu.c:1516:9
    #26 0x55e0dba22d9b in videzzo_dispatch_event /home/liuqiang/project-videzzo/videzzo/videzzo.c:1143:9
    #27 0x55e0dba1a0ed in __videzzo_execute_one_input /home/liuqiang/project-videzzo/videzzo/videzzo.c:288:9
    #28 0x55e0dba19e94 in videzzo_execute_one_input /home/liuqiang/project-videzzo/videzzo/videzzo.c:329:9
    #29 0x55e0d81a872c in videzzo_qemu /home/liuqiang/project-videzzo/videzzo/videzzo_qemu/qemu/out-san/../tests/qtest/videzzo/videzzo_qemu.c:1529:12
    #30 0x55e0dba27bbb in LLVMFuzzerTestOneInput /home/liuqiang/project-videzzo/videzzo/videzzo.c:1910:18
    #31 0x55e0d808a574 in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:589:17
    #32 0x55e0d806e7d4 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #33 0x55e0d807b27b in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:882:19
    #34 0x55e0d8064fc6 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #35 0x7f43dbee2082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #36 0x55e0d806501d in _start (/home/liuqiang/project-videzzo/virtfuzz-bugs/metadata/ehci-01/qemu-videzzo-i386-target-videzzo-fuzz-ehci+0x28d901d)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000
```

## Contact

Let us know if I need to provide more information.
