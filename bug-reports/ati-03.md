# hw/display/ati_2d: Third SEGV in ati_2d.c

This is the 3rd segment fault in pixman_fill through ati-vga device.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 6.2.50, aeb0ae95b7f18c66158792641cb6ba0cde5789ab, Ubuntu 18.04

### VM architecture, device, device type
i386, ati, display

### Bug Type: SEGV Write

### Stack traces, crash details

```
==5678==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x5558083e84d0). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2637545377
INFO: Loaded 1 modules   (912158 inline 8-bit counters): 912158 [0x55580fb9f000, 0x55580fc7db1e), 
INFO: Loaded 1 PC tables (912158 PCs): 912158 [0x55580edb3bb0,0x55580fb9ed90),
./qemu-fuzz-i386-target-videzzo-fuzz-ati: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
Matching objects by name , *ati.mmregs*
This process will fuzz the following MemoryRegions:
  * ati.mmregs[0] (size 4000)
This process will fuzz through the following interfaces:
  * clock_step, EVENT_TYPE_CLOCK_STEP, 0xffffffff +0xffffffff, 255,255
  * socket_write, EVENT_TYPE_SOCKET_WRITE, 0xffffffff +0xffffffff, 255,255
  * ati.mmregs, EVENT_TYPE_MMIO_READ, 0xe2000000 +0x4000, 1,4
  * ati.mmregs, EVENT_TYPE_MMIO_WRITE, 0xe2000000 +0x4000, 1,4
24/01/2022 14:22:56 ConnectClientToTcpAddr6: getaddrinfo (Name or service not known)
24/01/2022 14:22:56 VNC server supports protocol version 3.8 (viewer 3.8)
24/01/2022 14:22:56 We have 1 security types to read
24/01/2022 14:22:56 0) Received security type 1
24/01/2022 14:22:56 Selecting security type 1 (0/1 in the list)
24/01/2022 14:22:56 Selected Security Scheme 1
24/01/2022 14:22:56 No authentication needed
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 8 ft: 9 corp: 1/1b exec/s: 0 rss: 208Mb
Running: 6525e71a-7d17-11ec-9cd4-0242ac110004
24/01/2022 14:22:56 VNC authentication succeeded
24/01/2022 14:22:56 Desktop name "QEMU"
24/01/2022 14:22:56 Connected to VNC server, using protocol version 3.8
24/01/2022 14:22:56 VNC server default format:
24/01/2022 14:22:56   32 bits per pixel.
24/01/2022 14:22:56   Least significant byte first in each pixel.
24/01/2022 14:22:56   TRUE colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
AddressSanitizer:DEADLYSIGNAL
=================================================================
==5678==ERROR: AddressSanitizer: SEGV on unknown address 0x7fe103a00000 (pc 0x7fe12d986a8b bp 0x00000000364e sp 0x7ffeb7beadf0 T0)
==5678==The signal is caused by a WRITE memory access.
    #0 0x7fe12d986a8b  (/usr/lib/x86_64-linux-gnu/libpixman-1.so.0+0x6ca8b)
    #1 0x7fe12d96bb28  (/usr/lib/x86_64-linux-gnu/libpixman-1.so.0+0x51b28)
    #2 0x7fe12d924fe8 in pixman_fill (/usr/lib/x86_64-linux-gnu/libpixman-1.so.0+0xafe8)
    #3 0x5558090e0784 in ati_2d_blt /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../hw/display/ati_2d.c:186:9
    #4 0x5558090ca041 in ati_mm_write /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../hw/display/ati.c:843:9
    #5 0x55580a926560 in memory_region_write_accessor /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:492:5
    #6 0x55580a925ae6 in access_with_adjusted_size /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:554:18
    #7 0x55580a923a28 in memory_region_dispatch_write /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:1514:16
    #8 0x55580a8da519 in flatview_write_continue /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2782:23
    #9 0x55580a8c33e2 in flatview_write /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2822:14
    #10 0x55580a8c2f31 in address_space_write /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2914:18
    #11 0x5558083daa79 in __wrap_qtest_writel /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/fuzz/qtest_wrappers.c:177:9
    #12 0x5558083e5c58 in dispatch_mmio_write /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/fuzz/videzzo_qemu.c:51:28
    #13 0x55580bf7d87f in videzzo_dispatch_event /home/liuqiang/videzzo/videzzo.c:744:5
    #14 0x55580bf7d653 in __videzzo_execute_one_input /home/liuqiang/videzzo/videzzo.c:140:9
    #15 0x55580bf7da6f in videzzo_execute_one_input /home/liuqiang/videzzo/videzzo.c:161:9
    #16 0x5558083ea5c0 in videzzo_qemu /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/fuzz/videzzo_qemu.c:344:5
    #17 0x5558083d0d0e in __LLVMFuzzerTestOneInput /home/liuqiang/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/fuzz/fuzz.c:151:5
    #18 0x5558082c9a76 in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:595
    #19 0x5558082acf9a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #20 0x5558082b7c80 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:883
    #21 0x5558082a3372 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #22 0x7fe12ae08bf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
    #23 0x5558082a33c9 in _start (/home/liuqiang/videzzo/videzzo_qemu/out/qemu-fuzz-i386-target-videzzo-fuzz-ati+0x32173c9)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/usr/lib/x86_64-linux-gnu/libpixman-1.so.0+0x6ca8b)
==5678==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
24/01/2022 14:22:57 VNC server closed connection
```

### Reproducer steps

1. Please check the attachment and run: qemu-fuzz-i386-target-videzzo-fuzz-ati 6525e71a-7d17-11ec-9cd4-0242ac110004

## Contact

Let us know if I need to provide more information.
