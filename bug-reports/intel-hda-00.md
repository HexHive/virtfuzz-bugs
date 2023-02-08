# Global buffer overflow in hdaMmioWrite()

cbBefore[1] can be too large for g_afMasks[2], which only has five elements.

```
static DECLCALLBACK(VBOXSTRICTRC) hdaMmioWrite(PPDMDEVINS pDevIns, void *pvUser, RTGCPHYS off, void const *pv, unsigned cb) {
    // ...
    idxRegDsc = hdaR3RegLookupWithin(off);
    if (idxRegDsc != -1)
    {
        uint32_t const cbBefore = (uint32_t)off - g_aHdaRegMap[idxRegDsc].off; // [1]
        Assert(cbBefore > 0 && cbBefore < 4);
        off      -= cbBefore;
        idxRegMem = g_aHdaRegMap[idxRegDsc].idxReg;
        u64Value <<= cbBefore * 8;
        u64Value  |= pThis->au32Regs[idxRegMem] & g_afMasks[cbBefore]; // ------> [2]
```

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

vbox, 7.0.7, r98339, Ubuntu 20.04

### VM architecture, device, device type

i386, intel-hda, audio

### Bug Type: Global Buffer Overflow

### Stack traces, crash details

```
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
Matching objects by name , *HDA*
This process will fuzz the following MemoryRegions:
  * hda (size 4000)
This process will fuzz through the following interfaces:
  * clock_step, EVENT_TYPE_CLOCK_STEP, 0xffffffff +0xffffffff, 255,255
  * HDA, EVENT_TYPE_MMIO_READ, 0xf0404000 +0x4000, 1,4
  * HDA, EVENT_TYPE_MMIO_WRITE, 0xf0404000 +0x4000, 1,4
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 1 ft: 2 corp: 1/1b exec/s: 0 rss: 214Mb
Running: /root/bugs/metadata/intel-hda-00/crash-ef8f9faf1e8280b1320cfaf82fff92f30167a190.minimized
/root/videzzo/videzzo_vbox/vbox/src/VBox/Devices/Audio/DevHda.cpp:3410:26: runtime error: shift exponent 65552 is too large for 64-bit type 'uint64_t' (aka 'unsigned long')
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /root/videzzo/videzzo_vbox/vbox/src/VBox/Devices/Audio/DevHda.cpp:3410:26 in 
/root/videzzo/videzzo_vbox/vbox/src/VBox/Devices/Audio/DevHda.cpp:3411:59: runtime error: index 8194 out of bounds for type 'const uint32_t [5]'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /root/videzzo/videzzo_vbox/vbox/src/VBox/Devices/Audio/DevHda.cpp:3411:59 in 
=================================================================
==384==ERROR: AddressSanitizer: global-buffer-overflow on address 0x7f0807d578c8 at pc 0x7f080714a97e bp 0x7fff74406e90 sp 0x7fff74406e88
READ of size 4 at 0x7f0807d578c8 thread T0
    #0 0x7f080714a97d in hdaMmioWrite(PDMDEVINSR3*, void*, unsigned long, void const*, unsigned int) /root/videzzo/videzzo_vbox/vbox/src/VBox/Devices/Audio/DevHda.cpp:3411:59
    #1 0x7f08159d8fc8 in iomMmioDoWrite(VM*, VMCPU*, IOMMMIOENTRYR3*, unsigned long, unsigned long, void const*, unsigned int, IOMMMIOSTATSENTRY*) /root/videzzo/videzzo_vbox/vbox/src/VBox/VMM/VMMAll/IOMAllMmioNew.cpp:348:24
    #2 0x7f08159d9949 in iomMmioHandlerNew /root/videzzo/videzzo_vbox/vbox/src/VBox/VMM/VMMAll/IOMAllMmioNew.cpp:939:24
    #3 0x7f0815a56c7d in pgmPhysWriteHandler(VM*, PGMPAGE*, unsigned long, void const*, unsigned long, PGMACCESSORIGIN) /root/videzzo/videzzo_vbox/vbox/src/VBox/VMM/VMMAll/PGMAllPhys.cpp:2746:28
    #4 0x7f0815a5621f in PGMPhysWrite /root/videzzo/videzzo_vbox/vbox/src/VBox/VMM/VMMAll/PGMAllPhys.cpp:3027:46
    #5 0x570386 in vbox_writeb(unsigned long, unsigned char) /root/videzzo/videzzo_vbox/vbox/src/VBox/Frontends/VBoxManage/VBoxViDeZZo.cpp:495:5
    #6 0x57023c in dispatch_mmio_write /root/videzzo/videzzo_vbox/vbox/src/VBox/Frontends/VBoxManage/VBoxViDeZZo.cpp:588:28
    #7 0x81c10f in videzzo_dispatch_event /root/videzzo/videzzo.c:1140:5
    #8 0x81348d in __videzzo_execute_one_input /root/videzzo/videzzo.c:288:9
    #9 0x813234 in videzzo_execute_one_input /root/videzzo/videzzo.c:329:9
    #10 0x571902 in videzzo_vbox(unsigned char*, unsigned long) /root/videzzo/videzzo_vbox/vbox/src/VBox/Frontends/VBoxManage/VBoxViDeZZo.cpp:694:12
    #11 0x820f5b in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1910:18
    #12 0x467246 in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:594:17
    #13 0x449e74 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #14 0x454e1e in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:885:19
    #15 0x440ed6 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #16 0x7f0813d7f082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #17 0x44145d in _start (/root/videzzo/videzzo_vbox/out-san/vbox-videzzo-i386-target-videzzo-fuzz-hda+0x44145d)

0x7f0807d578c8 is located 24 bytes to the left of global variable '<string literal>' defined in '/root/videzzo/videzzo_vbox/vbox/src/VBox/Devices/Audio/DevHda.cpp:471:5' (0x7f0807d578e0) of size 12
  '<string literal>' is ascii string 'SD2: Status'
0x7f0807d578c8 is located 33 bytes to the right of global variable '<string literal>' defined in '/root/videzzo/videzzo_vbox/vbox/src/VBox/Devices/Audio/DevHda.cpp:471:5' (0x7f0807d578a0) of size 7
  '<string literal>' is ascii string 'SD2STS'
SUMMARY: AddressSanitizer: global-buffer-overflow /root/videzzo/videzzo_vbox/vbox/src/VBox/Devices/Audio/DevHda.cpp:3411:59 in hdaMmioWrite(PDMDEVINSR3*, void*, unsigned long, void const*, unsigned int)
Shadow bytes around the buggy address:
  0x0fe180fa2ec0: f9 f9 f9 f9 00 07 f9 f9 f9 f9 f9 f9 07 f9 f9 f9
  0x0fe180fa2ed0: f9 f9 f9 f9 00 00 03 f9 f9 f9 f9 f9 00 f9 f9 f9
  0x0fe180fa2ee0: f9 f9 f9 f9 00 00 00 00 00 00 07 f9 f9 f9 f9 f9
  0x0fe180fa2ef0: 00 f9 f9 f9 f9 f9 f9 f9 00 00 00 00 00 00 07 f9
  0x0fe180fa2f00: f9 f9 f9 f9 07 f9 f9 f9 f9 f9 f9 f9 00 00 00 07
=>0x0fe180fa2f10: f9 f9 f9 f9 07 f9 f9 f9 f9[f9]f9 f9 00 04 f9 f9
  0x0fe180fa2f20: f9 f9 f9 f9 00 f9 f9 f9 f9 f9 f9 f9 00 00 00 05
  0x0fe180fa2f30: f9 f9 f9 f9 07 f9 f9 f9 f9 f9 f9 f9 00 00 00 02
  0x0fe180fa2f40: f9 f9 f9 f9 07 f9 f9 f9 f9 f9 f9 f9 00 00 06 f9
  0x0fe180fa2f50: f9 f9 f9 f9 00 01 f9 f9 f9 f9 f9 f9 00 00 04 f9
  0x0fe180fa2f60: f9 f9 f9 f9 00 01 f9 f9 f9 f9 f9 f9 00 07 f9 f9
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==384==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
0x1,0x9,0x46,0x61,0x40,0xf0,0x0,0x0,0x0,0x0,0x1,0x0,0x0,0x0,0xc2,0x62,0xd0,0x5b,0x0,0x0,0x0,0x0,
\x01\x09Fa@\xf0\x00\x00\x00\x00\x01\x00\x00\x00\xc2b\xd0[\x00\x00\x00\x00
```

## Contact

Let us know if I need to provide more information.
