# Index out of bounds for type uint32_t[64] in xilinx_spips_write()

# Index out of bounds for type uint32_t [64] in xilinx_spips_write

#0  0x000055555c4b8398 in memory_region_do_init (mr=0x7ffff0214680, owner=0x7ffff0214350, name=0x55555d843540 <str> "spi", size=0x200) at ../softmmu/memory.c:1166
#1  0x000055555c4b80e2 in memory_region_init (mr=0x7ffff0214680, owner=0x7ffff0214350, name=0x55555d843540 <str> "spi", size=0x200) at ../softmmu/memory.c:1195
#2  0x000055555c4bea38 in memory_region_init_io (mr=0x7ffff0214680, owner=0x7ffff0214350, ops=0x55555e2750a0 <spips_ops>, opaque=0x7ffff0214350, name=0x55555d843540 <str> "spi", size=0x200) at ../softmmu/memory.c:1536
#3  0x000055555a5f4ece in xilinx_spips_realize (dev=0x7ffff0214350, errp=0x7fffffff8da0) at ../hw/ssi/xilinx_spips.c:1301
#4  0x000055555c865e5c in device_set_realized (obj=0x7ffff0214350, value=0x1, errp=0x7fffffffbee0) at ../hw/core/qdev.c:553

This sets the size of memory region to 0x200 but only 0x100 is valid.

I do a simple change in the following:

- #define XLNX_SPIPS_R_MAX        (0x100 / 4)
+ #define XLNX_SPIPS_R_MAX        (0x200 / 4)

This will work but break some regression testing. So, think up a new patch later.


## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 7.0.94, 9a99f964b152f8095949bbddca7841744ad418da, Ubuntu 20.04

### VM architecture, device, device type
aarch64, xlnx_zynqmp_qspips, bus

### Bug Type: Out-of-bound Write

### Stack traces, crash details

```
root@f693d096eafa:~/videzzo/videzzo_qemu/out-san# DEFAULT_INPUT_MAXSIZE=10000000 /root/videzzo/videzzo_qemu/out-san/./qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-zynqmp-qspips  -max_len=10000000 -detect_leaks=0 /root/videzzo/videzzo_qemu/out-san/crash-66c132a47f4d360be45af57826d838c0793a2bf7.minimized
==134726==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x564be1740bd0). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1567456761
INFO: Loaded 1 modules   (618615 inline 8-bit counters): 618615 [0x564be489f000, 0x564be4936077), 
INFO: Loaded 1 PC tables (618615 PCs): 618615 [0x564be3f2df00,0x564be489e670), 
/root/videzzo/videzzo_qemu/out-san/./qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-zynqmp-qspips: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
Matching objects by name , *spi*, *lqspi*
This process will fuzz the following MemoryRegions:
  * lqspi[0] (size 2000000)
  * spi[0] (size 200)
  * spi[0] (size 200)
  * spi[0] (size 200)
This process will fuzz through the following interfaces:
  * clock_step, EVENT_TYPE_CLOCK_STEP, 0xffffffff +0xffffffff, 255,255
  * spi, EVENT_TYPE_MMIO_READ, 0xff050000 +0x200, 1,4
  * spi, EVENT_TYPE_MMIO_WRITE, 0xff050000 +0x200, 1,4
  * spi, EVENT_TYPE_MMIO_READ, 0xff040000 +0x200, 1,4
  * spi, EVENT_TYPE_MMIO_WRITE, 0xff040000 +0x200, 1,4
  * spi, EVENT_TYPE_MMIO_READ, 0xff0f0000 +0x200, 1,4
  * spi, EVENT_TYPE_MMIO_WRITE, 0xff0f0000 +0x200, 1,4
  * lqspi, EVENT_TYPE_MMIO_READ, 0xc0000000 +0x2000000, 4,4
  * lqspi, EVENT_TYPE_MMIO_WRITE, 0xc0000000 +0x2000000, 4,4
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 491Mb
Running: /root/videzzo/videzzo_qemu/out-san/crash-66c132a47f4d360be45af57826d838c0793a2bf7.minimized
../hw/ssi/xilinx_spips.c:1031:22: runtime error: index 66 out of bounds for type 'uint32_t [64]'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../hw/ssi/xilinx_spips.c:1031:22 in 
../hw/ssi/xilinx_spips.c:1031:5: runtime error: index 66 out of bounds for type 'uint32_t [64]'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../hw/ssi/xilinx_spips.c:1031:5 in 
../qom/object.c:867:56: runtime error: member access within misaligned address 0x6110000029be for type 'ObjectClass' (aka 'struct ObjectClass'), which requires 8 byte alignment
0x6110000029be: note: pointer points here
 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  c0 91 a9 e0 4b 56 00 00  40 92
             ^ 
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../qom/object.c:867:56 in 
../qom/object.c:867:56: runtime error: load of misaligned address 0x6110000029be for type 'Type' (aka 'struct TypeImpl *'), which requires 8 byte alignment
0x6110000029be: note: pointer points here
 00 00 00 00 00 00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  c0 91 a9 e0 4b 56 00 00  40 92
             ^ 
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../qom/object.c:867:56 in 
../qom/object.c:867:62: runtime error: member access within null pointer of type 'struct TypeImpl'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../qom/object.c:867:62 in 
../qom/object.c:867:62: runtime error: load of null pointer of type 'const char *'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../qom/object.c:867:62 in 
AddressSanitizer:DEADLYSIGNAL
=================================================================
==134726==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x564be0ac57d6 bp 0x7ffce50a6d60 sp 0x7ffce50a6d10 T0)
==134726==The signal is caused by a READ memory access.
==134726==Hint: address points to the zero page.
    #0 0x564be0ac57d6 in object_dynamic_cast_assert /root/videzzo/videzzo_qemu/qemu/build-san-6/../qom/object.c:867:62
    #1 0x564bde84244e in XLNX_ZYNQMP_QSPIPS /root/videzzo/videzzo_qemu/qemu/include/hw/ssi/xilinx_spips.h:141:1
    #2 0x564bde847e3f in xlnx_zynqmp_qspips_read /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/ssi/xilinx_spips.c:933:27
    #3 0x564be07338bb in memory_region_read_accessor /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:440:11
    #4 0x564be06f3b91 in access_with_adjusted_size /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:554:18
    #5 0x564be06f0f5c in memory_region_dispatch_read1 /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:1424:16
    #6 0x564be06f0698 in memory_region_dispatch_read /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:1457:9
    #7 0x564be076c90d in flatview_read_continue /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2892:23
    #8 0x564be076df18 in flatview_read /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2934:12
    #9 0x564be076d9d8 in address_space_read_full /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2947:18
    #10 0x564bdcb4a7fa in address_space_read /root/videzzo/videzzo_qemu/qemu/include/exec/memory.h:2869:18
    #11 0x564bdcb4a7fa in qemu_readb /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1016:5
    #12 0x564bdcb4998e in dispatch_mmio_read /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1040:35
    #13 0x564be173c58f in videzzo_dispatch_event /root/videzzo/videzzo.c:1122:5
    #14 0x564be173390b in __videzzo_execute_one_input /root/videzzo/videzzo.c:272:9
    #15 0x564be17337e0 in videzzo_execute_one_input /root/videzzo/videzzo.c:313:9
    #16 0x564bdcb6010c in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1503:12
    #17 0x564be1740e72 in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1891:18
    #18 0x564bdca41826 in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:594:17
    #19 0x564bdca24454 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #20 0x564bdca2f3fe in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:885:19
    #21 0x564bdca1b9e6 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #22 0x7f6228a86082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #23 0x564bdca1ba3d in _start (/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-zynqmp-qspips+0x3291a3d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /root/videzzo/videzzo_qemu/qemu/build-san-6/../qom/object.c:867:62 in object_dynamic_cast_assert
==134726==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
0x1,0x9,0x8,0x1,0x5,0xff,0x0,0x0,0x0,0x0,0x2,0x0,0x0,0x0,0xbe,0x29,0x9a,0x11,0x0,0x0,0x0,0x0,0x0,0xc,0x6c,0x1,0xf,0xff,0x0,0x0,0x0,0x0,0x1,0x0,0x0,0x0,
\x01\x09\x08\x01\x05\xff\x00\x00\x00\x00\x02\x00\x00\x00\xbe)\x9a\x11\x00\x00\x00\x00\x00\x0cl\x01\x0f\xff\x00\x00\x00\x00\x01\x00\x00\x00
```

### Reproducer steps

root@fff5a5933072:~/qemu/build-san-5# ./qemu-fuzz-aarch64 --fuzz-target=stateful-fuzz-xlnx-zynqmp-qspips crash-69ad8465205e9ac08b9fc1f0d469674e81a73019 
## Contact

Let us know if I need to provide more information.