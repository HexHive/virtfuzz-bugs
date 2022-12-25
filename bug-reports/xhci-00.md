# Abort in xhci_find_stream()

I triggered an abort in xhci_find_stream() [1]. This is because the
secondary stream arrays is enabled by setting linear stream array (LSA) bit (in
endpoint context) to 0. We may show warnings and drop this operation.

``` c
static XHCIStreamContext *xhci_find_stream(XHCIEPContext *epctx,
                                           unsigned int streamid,
                                           uint32_t *cc_error)
{
    // ...
    if (epctx->lsa) {
        // ...
    } else {
        FIXME("secondary streams not implemented yet"); // <----------- [1]
    }
    // ...
```


## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 7.0.94, 9a99f964b152f8095949bbddca7841744ad418da, Ubuntu 20.04

### VM architecture, device, device type

i386, xhci, usb

### Bug Type: Abort

### Stack traces, crash details

```
root@5b4fda3ee725:~/videzzo/videzzo_qemu/out-san# DEFAULT_INPUT_MAXSIZE=10000000 /root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-xhci  -max_len=10000000 -detect_leaks=0 poc-qemu-videzzo-i386-target-videzzo-fuzz-xhci-crash-4a11736abb111efe4b29a6931f403561f9a0f9ec
==71545==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x55e05e05e640). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2668437424
INFO: Loaded 1 modules   (423456 inline 8-bit counters): 423456 [0x55e0606e8000, 0x55e06074f620), 
INFO: Loaded 1 PC tables (423456 PCs): 423456 [0x55e060071ae0,0x55e0606e7ce0), 
/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-xhci: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
Matching objects by name , *capabilities*, *operational*, *runtime*, *doorbell*, *usb3 port*
This process will fuzz the following MemoryRegions:
  * usb3 port #1[0] (size 10)
  * usb3 port #4[0] (size 10)
  * capabilities[0] (size 40)
  * usb3 port #3[0] (size 10)
  * operational[0] (size 400)
  * usb3 port #2[0] (size 10)
  * runtime[0] (size 220)
  * doorbell[0] (size 820)
This process will fuzz through the following interfaces:
  * clock_step, EVENT_TYPE_CLOCK_STEP, 0xffffffff +0xffffffff, 255,255
  * capabilities, EVENT_TYPE_MMIO_READ, 0xe0000000 +0x40, 4,4
  * capabilities, EVENT_TYPE_MMIO_WRITE, 0xe0000000 +0x40, 4,4
  * operational, EVENT_TYPE_MMIO_READ, 0xe0000040 +0x400, 4,8
  * operational, EVENT_TYPE_MMIO_WRITE, 0xe0000040 +0x400, 4,8
  * runtime, EVENT_TYPE_MMIO_READ, 0xe0001000 +0x220, 4,8
  * runtime, EVENT_TYPE_MMIO_WRITE, 0xe0001000 +0x220, 4,8
  * doorbell, EVENT_TYPE_MMIO_READ, 0xe0002000 +0x820, 4,4
  * doorbell, EVENT_TYPE_MMIO_WRITE, 0xe0002000 +0x820, 4,4
  * usb3 port #4, EVENT_TYPE_MMIO_READ, 0xe0000470 +0x10, 4,4
  * usb3 port #4, EVENT_TYPE_MMIO_WRITE, 0xe0000470 +0x10, 4,4
  * usb3 port #1, EVENT_TYPE_MMIO_READ, 0xe0000440 +0x10, 4,4
  * usb3 port #1, EVENT_TYPE_MMIO_WRITE, 0xe0000440 +0x10, 4,4
  * usb3 port #2, EVENT_TYPE_MMIO_READ, 0xe0000450 +0x10, 4,4
  * usb3 port #2, EVENT_TYPE_MMIO_WRITE, 0xe0000450 +0x10, 4,4
  * usb3 port #3, EVENT_TYPE_MMIO_READ, 0xe0000460 +0x10, 4,4
  * usb3 port #3, EVENT_TYPE_MMIO_WRITE, 0xe0000460 +0x10, 4,4
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 197Mb
Running: poc-qemu-videzzo-i386-target-videzzo-fuzz-xhci-crash-4a11736abb111efe4b29a6931f403561f9a0f9ec
../hw/usb/hcd-xhci.c:1099:25: runtime error: shift exponent 156 is too large for 32-bit type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../hw/usb/hcd-xhci.c:1099:25 in 
FIXME xhci_find_stream:998 secondary streams not implemented yet
==71545== ERROR: libFuzzer: deadly signal
    #0 0x55e05a7f874e in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86:3
    #1 0x55e05a7473c1 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:38
    #2 0x55e05a720c06 in fuzzer::Fuzzer::CrashCallback() (.part.0) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:235:18
    #3 0x55e05a720cd2 in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207:1
    #4 0x55e05a720cd2 in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:206:19
    #5 0x7fa0b025c41f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f)
    #6 0x7fa0b006e00a in __libc_signal_restore_set /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/internal-signals.h:86:3
    #7 0x7fa0b006e00a in raise /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/raise.c:48:3
    #8 0x7fa0b004d858 in abort /build/glibc-SzIz7B/glibc-2.31/stdlib/abort.c:79:7
    #9 0x55e05a828c9a in __wrap_abort /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/less_crashes_wrappers.c:24:12
    #10 0x55e05bd528c3 in xhci_find_stream /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-xhci.c:998:9
    #11 0x55e05bd46ca5 in xhci_kick_epctx /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-xhci.c:1922:17
    #12 0x55e05bd7d7ff in xhci_kick_ep /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-xhci.c:1838:5
    #13 0x55e05bd94ab9 in xhci_doorbell_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-xhci.c:3163:13
    #14 0x55e05cfed443 in memory_region_write_accessor /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:492:5
    #15 0x55e05cfecd81 in access_with_adjusted_size /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:554:18
    #16 0x55e05cfeb68c in memory_region_dispatch_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:1514:16
    #17 0x55e05d0760be in flatview_write_continue /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2825:23
    #18 0x55e05d06443b in flatview_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2867:12
    #19 0x55e05d063ef8 in address_space_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2963:18
    #20 0x55e05a83813b in qemu_writel /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1072:5
    #21 0x55e05a8365b5 in dispatch_mmio_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1197:28
    #22 0x55e05e059fff in videzzo_dispatch_event /root/videzzo/videzzo.c:1122:5
    #23 0x55e05e05137b in __videzzo_execute_one_input /root/videzzo/videzzo.c:272:9
    #24 0x55e05e051250 in videzzo_execute_one_input /root/videzzo/videzzo.c:313:9
    #25 0x55e05a83f17c in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1472:12
    #26 0x55e05e05e8e2 in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1891:18
    #27 0x55e05a72173d in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:589:17
    #28 0x55e05a7044c4 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #29 0x55e05a70f43e in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:882:19
    #30 0x55e05a6fba46 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #31 0x7fa0b004f082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #32 0x55e05a6fba9d in _start (/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-xhci+0x265aa9d)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000

```

### Reproducer steps

Step 1: download the prepared rootfs and the image.

https://drive.google.com/file/d/10C2110VH-GrwACiPebC8-Vgcf5_Ny8Sd/view?usp=sharing
https://drive.google.com/file/d/1jAMf8rtTM8p88gamhNk4HC5Z34XtjUHw/view?usp=sharing

Step 2: run the following script.

``` bash
QEMU_PATH=../../../qemu/build/qemu-system-x86_64
KERNEL_PATH=./bzImage
ROOTFS_PATH=./rootfs.ext2
$QEMU_PATH \
    -M q35 -m 1G \
    -kernel $KERNEL_PATH \
    -drive file=$ROOTFS_PATH,if=virtio,format=raw \
    -append "root=/dev/vda console=ttyS0" \
    -net nic,model=virtio -net user \
    -drive file=null-co://,if=none,format=raw,id=disk0 \
    -device qemu-xhci,id=xhci -device usb-storage,drive=disk0 \
    -device usb-bot -device usb-tablet,bus=xhci.0 \
    -chardev null,id=cd0 -chardev null,id=cd1 \
    -device usb-braille,chardev=cd0 -device usb-ccid -device usb-ccid \
    -device usb-kbd -device usb-mouse -device usb-serial,chardev=cd1 \
    -device usb-tablet -device usb-wacom-tablet -device usb-audio \
    -nographic
```

Step 3: with spawned shell (the user is root and the password is empty), run
`xhci-00`.


## Contact

Let us know if I need to provide more information.
