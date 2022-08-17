# Assertion failed in usb_msd_transfer_data

# dev-storage: assertion (s->mode == USB_MSDM_DATAOUT) == (req->cmd.mode == SCSI_XFER_TO_DEV) failed

When I fuzzed ohci with dev-storage device, I found the assertion in
usb_msd_handle_data() failed due to req->cmd.mode != SCSI_XFER_TO_DEV. This
new bug (AFAIK) happens because of two reasons.

1) The control flow goes into usb_msd_transfer_data() that is not easily covered.

2) The value of `cbw.cmd` in usb_msd_handle_data() is controlled and then
`req->cmd.mode` that is coped from `cbw.cmd` is controlled.

Details are in the following.
## More technique details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 7.0.50, 5288bee45fbd33203b61f8c76e41b15bb5913e6e, Ubuntu 20.04

### VM architecture, device, device type
i386, ohci, usb

### Bug Type: Assertion Failure

### Stack traces, crash details

```
root@37d14d202b64:~/videzzo/videzzo_qemu/out-san# DEFAULT_INPUT_MAXSIZE=10000000 /root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci  -max_len=10000000 poc-qemu-videzzo-i386-target-videzzo-fuzz-ohci-crash-8fdccd1d02357f8b8870163b21b32d9ebcc126b7
==591201==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x55c64422eb10). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1962413397
INFO: Loaded 1 modules   (422784 inline 8-bit counters): 422784 [0x55c6468b0000, 0x55c646917380), 
INFO: Loaded 1 PC tables (422784 PCs): 422784 [0x55c64623c100,0x55c6468af900), 
/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
Matching objects by name , *ohci*
This process will fuzz the following MemoryRegions:
  * ohci[0] (size 100)
This process will fuzz through the following interfaces:
  * clock_step, EVENT_TYPE_CLOCK_STEP, 0xffffffff +0xffffffff, 255,255
  * ohci, EVENT_TYPE_MMIO_READ, 0xe0000000 +0x100, 1,4
  * ohci, EVENT_TYPE_MMIO_WRITE, 0xe0000000 +0x100, 1,4
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 193Mb
Running: poc-qemu-videzzo-i386-target-videzzo-fuzz-ohci-crash-8fdccd1d02357f8b8870163b21b32d9ebcc126b7
qemu-videzzo-i386-target-videzzo-fuzz-ohci: ../hw/usb/dev-storage.c:228: void usb_msd_transfer_data(SCSIRequest *, uint32_t): Assertion `(s->mode == USB_MSDM_DATAOUT) == (req->cmd.mode == SCSI_XFER_TO_DEV)' failed.
==591201== ERROR: libFuzzer: deadly signal
    #0 0x55c6409d974e in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86:3
    #1 0x55c6409283c1 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:38
    #2 0x55c640901c06 in fuzzer::Fuzzer::CrashCallback() (.part.0) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:235:18
    #3 0x55c640901cd2 in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207:1
    #4 0x55c640901cd2 in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:206:19
    #5 0x7f9bd6e9341f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f)
    #6 0x7f9bd6ca500a in __libc_signal_restore_set /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/internal-signals.h:86:3
    #7 0x7f9bd6ca500a in raise /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/raise.c:48:3
    #8 0x7f9bd6c84858 in abort /build/glibc-SzIz7B/glibc-2.31/stdlib/abort.c:79:7
    #9 0x7f9bd6c84728 in __assert_fail_base /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:92:3
    #10 0x7f9bd6c95fd5 in __assert_fail /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:101:3
    #11 0x55c641fba0c0 in usb_msd_transfer_data /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/dev-storage.c:228:5
    #12 0x55c641a247d9 in scsi_req_data /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/scsi/scsi-bus.c:1413:9
    #13 0x55c641a36bf2 in scsi_target_read_data /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/scsi/scsi-bus.c:639:9
    #14 0x55c641a23010 in scsi_req_continue /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/scsi/scsi-bus.c:1395:9
    #15 0x55c641fc830b in usb_msd_handle_data /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/dev-storage.c:425:17
    #16 0x55c641da6a4b in usb_device_handle_data /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/bus.c:180:9
    #17 0x55c641dd729d in usb_process_one /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/core.c:406:9
    #18 0x55c641dd3312 in usb_handle_packet /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/core.c:438:9
    #19 0x55c641e7393c in ohci_service_td /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:959:9
    #20 0x55c641e70190 in ohci_service_ed_list /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1111:21
    #21 0x55c641e62fb9 in ohci_frame_boundary /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1181:9
    #22 0x55c643fdb43e in timerlist_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:576:9
    #23 0x55c643fdb76c in qemu_clock_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:590:12
    #24 0x55c64326e474 in qtest_clock_warp /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:358:9
    #25 0x55c64326d346 in qtest_process_command /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:751:9
    #26 0x55c6432609bd in qtest_process_inbuf /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:796:9
    #27 0x55c6432606df in qtest_server_inproc_recv /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:927:9
    #28 0x55c643bc5be5 in send_wrapper /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:1386:5
    #29 0x55c643bbfea1 in qtest_sendf /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:453:5
    #30 0x55c643bc0065 in qtest_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:810:5
    #31 0x55c640a182c1 in dispatch_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1185:5
    #32 0x55c64422abef in videzzo_dispatch_event /root/videzzo/videzzo.c:1116:5
    #33 0x55c6442287d4 in dispatch_group_event /root/videzzo/videzzo.c:1011:9
    #34 0x55c64422abef in videzzo_dispatch_event /root/videzzo/videzzo.c:1116:5
    #35 0x55c644221c73 in __videzzo_execute_one_input /root/videzzo/videzzo.c:256:9
    #36 0x55c644221ac0 in videzzo_execute_one_input /root/videzzo/videzzo.c:297:9
    #37 0x55c640a1c5cc in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1418:12
    #38 0x55c64422edb2 in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1913:18
    #39 0x55c64090273d in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:589:17
    #40 0x55c6408e54c4 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #41 0x55c6408f043e in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:882:19
    #42 0x55c6408dca46 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #43 0x7f9bd6c86082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #44 0x55c6408dca9d in _start (/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci+0x264fa9d)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000
```

## Contact

Let us know if I need to provide more information.
