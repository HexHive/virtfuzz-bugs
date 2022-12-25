# Heap buffer overflow in aspeed_smc_flash_do_select()

# HBO in aspeed_smc_flash_do_select because accessible AspeedSMCFlash is unchecked

I found a heap buffer overflow in aspeed_smc_flash_do_select because the check of accessible AspeedSMCFlash is missing. This issue is related to two bugs. I will explain them in the following.

## Bug 1
1 `s->cs_lines` is allocated in `aspeed_smc_realize`, where `s->num_cs` is 1 by default.
```
s->cs_lines = g_new0(qemu_irq, s->num_cs);
```
2 In `aspeed_smc_flash_do_select`, we can overflow `s->cs_lines` by `fl->id` that is larger than 0.
```
static void aspeed_smc_flash_do_select(AspeedSMCFlash *fl, bool unselect) {
    ....
    qemu_set_irq(s->cs_lines[fl->id], unselect);
                           // ---if fl->id is 1, then overflow here ---
}
```
3 The root cause is that we can access the second or the third Flash chip without any check when the index of the current Flash chip is larger than `s->num_cs`, say some fmcs,  e.g., aspeed.fmc-ast2400, have more than one Flash chip.
4 Security impact: this primitive can assist in exploiting QEMU vulnerabilities. I think the primitive cannot be used standalone, but with other arbitrary write primitives, putting a malicious qemu_irq pointer at s->cs_lines[fl->id], the malicious qemu irq handler (a dangerous function) will be triggered when unselect is 1.

## Bug 2
1 The above overflow is not found by directly testing the aspeed smc but found by testing the ftgmac100, a NIC.
2 Root Cause: In `ftgmac100_read_bd`, the range of `dma_memory_read` is not checked, thus with this primitive, I can load sizeof(*bd)=16 bytes into local variable bd from any a) registered MMIO regions, b) ram. Because of a), I can access the second Flash chip even if the default number of valid Flash chips is 1 and finally trigger the heap buffer overflow.
```
static int ftgmac100_read_bd(FTGMAC100Desc *bd, dma_addr_t addr) {
    if (dma_memory_read(&address_space_memory, addr, bd, sizeof(*bd))) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: failed to read descriptor @ 0x%"
                      HWADDR_PRIx "\n", __func__, addr);
        return -1;
    }
    // omit
```
3 Security impact 1: Furthermore, the controlled `bd` can affect the control flow in the following.
```
static bool ftgmac100_can_receive(NetClientState *nc) {
    FTGMAC100Desc bd; // local variable
    if (ftgmac100_read_bd(&bd, s->rx_descriptor)) {
        return false;
    }
    return !(bd.des0 & FTGMAC100_RXDES0_RXPKT_RDY);
           // ---- may return true
}
```
4 Security impact 2: When fixing the first bug, if we don’t expose the invalid Flash chips to the guest, we still can access the invalid Flash chips by ftgmac100.
5 Security impact 3: If fixing the first bug properly, this primitive seems to be useless. However, without IOMMU to control the range the DMA can access, it is still not good. This bug inspires us to check similar issues in i386/86_64 and other arches. I’d like to discuss more.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type

arm, ftgmac100, net

### Bug Type: Heap-Buffer-Overflow

### Stack traces, crash details

```
==563==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000bde18 at pc 0x55b0ee793575 bp 0x7ffe8f6a3690 sp 0x7ffe8f6a3688
READ of size 8 at 0x6020000bde18 thread T0
    #0 0x55b0ee793574 in aspeed_smc_flash_do_select /root/qemu/build-oss-fuzz/../hw/ssi/aspeed_smc.c:665:18
    #1 0x55b0ee793931 in aspeed_smc_flash_select /root/qemu/build-oss-fuzz/../hw/ssi/aspeed_smc.c:670:5
    #2 0x55b0ee793931 in aspeed_smc_flash_read /root/qemu/build-oss-fuzz/../hw/ssi/aspeed_smc.c:756:9
    #3 0x55b0ef650dac in memory_region_read_accessor /root/qemu/build-oss-fuzz/../softmmu/memory.c:442:11
    #4 0x55b0ef6391b5 in access_with_adjusted_size /root/qemu/build-oss-fuzz/../softmmu/memory.c:552:18
    #5 0x55b0ef6391b5 in memory_region_dispatch_read1 /root/qemu/build-oss-fuzz/../softmmu/memory.c:1422:16
    #6 0x55b0ef6391b5 in memory_region_dispatch_read /root/qemu/build-oss-fuzz/../softmmu/memory.c:1450:9
    #7 0x55b0ef4d83a3 in flatview_read_continue /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2810:23
    #8 0x55b0ef4d9d97 in flatview_read /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2849:12
    #9 0x55b0ef4d953c in address_space_read_full /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2862:18
    #10 0x55b0ee7d8493 in dma_memory_rw_relaxed /root/qemu/include/sysemu/dma.h:88:12
    #11 0x55b0ee7d8493 in dma_memory_rw /root/qemu/include/sysemu/dma.h:127:12
    #12 0x55b0ee7d8493 in dma_memory_read /root/qemu/include/sysemu/dma.h:145:12
    #13 0x55b0ee7d8493 in ftgmac100_read_bd /root/qemu/build-oss-fuzz/../hw/net/ftgmac100.c:456:9
    #14 0x55b0ee7d8493 in ftgmac100_can_receive /root/qemu/build-oss-fuzz/../hw/net/ftgmac100.c:626:9
    #15 0x55b0ee7d6c2d in ftgmac100_write /root/qemu/build-oss-fuzz/../hw/net/ftgmac100.c:849:13
    #16 0x55b0ef63a227 in memory_region_write_accessor /root/qemu/build-oss-fuzz/../softmmu/memory.c:491:5
    #17 0x55b0ef639c0d in access_with_adjusted_size /root/qemu/build-oss-fuzz/../softmmu/memory.c:552:18
    #18 0x55b0ef639c0d in memory_region_dispatch_write /root/qemu/build-oss-fuzz/../softmmu/memory.c:1502:16
    #19 0x55b0ef4e7cc1 in flatview_write_continue /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2746:23
    #20 0x55b0ef4da857 in flatview_write /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2786:14
    #21 0x55b0ef4d9ffc in address_space_write /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2878:18
    #22 0x55b0ef5916e9 in qtest_process_command /root/qemu/build-oss-fuzz/../softmmu/qtest.c:534:13
    #23 0x55b0ef5916e9 in qtest_process_inbuf /root/qemu/build-oss-fuzz/../softmmu/qtest.c:797:9
    #24 0x55b0ef58f6fb in qtest_server_inproc_recv /root/qemu/build-oss-fuzz/../softmmu/qtest.c:904:9
    #25 0x55b0efa00d0c in qtest_sendf /root/qemu/build-oss-fuzz/../tests/qtest/libqtest.c:446:5
    #26 0x55b0efa014ee in qtest_write /root/qemu/build-oss-fuzz/../tests/qtest/libqtest.c:1034:5
    #27 0x55b0efa014ee in qtest_writel /root/qemu/build-oss-fuzz/../tests/qtest/libqtest.c:1050:5
    #28 0x55b0ee62ef13 in __wrap_qtest_writel /root/qemu/build-oss-fuzz/../tests/qtest/fuzz/qtest_wrappers.c:180:9
    #29 0x55b0ee629d4a in stateful_fuzz /root/qemu/build-oss-fuzz/../tests/qtest/fuzz/stateful_fuzz.c:415:13
    #30 0x55b0ee62b5e0 in LLVMFuzzerTestOneInput /root/qemu/build-oss-fuzz/../tests/qtest/fuzz/fuzz.c:151:5
    #31 0x55b0ee51a203 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:603
    #32 0x55b0ee4fd64a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #33 0x55b0ee508421 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:858
    #34 0x55b0ee4f3f92 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #35 0x7f85f55f6bf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
    #36 0x55b0ee4f3fe9 in _start (/root/qemu/build-oss-fuzz/qemu-fuzz-arm+0x1147fe9)

0x6020000bde18 is located 0 bytes to the right of 8-byte region [0x6020000bde10,0x6020000bde18)
allocated by thread T0 here:
    #0 0x55b0ee5d7148 in __interceptor_calloc /root/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:154
    #1 0x7f85f67fbc30 in g_malloc0 (/usr/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x51c30)
    #2 0x55b0ef798890 in device_set_realized /root/qemu/build-oss-fuzz/../hw/core/qdev.c:761:13
    #3 0x55b0ef7cf7c5 in property_set_bool /root/qemu/build-oss-fuzz/../qom/object.c:2257:5
    #4 0x55b0ef7ca61c in object_property_set /root/qemu/build-oss-fuzz/../qom/object.c:1402:5
    #5 0x55b0ef7d34a7 in object_property_set_qobject /root/qemu/build-oss-fuzz/../qom/qom-qobject.c:28:10
    #6 0x55b0ef7caf5f in object_property_set_bool /root/qemu/build-oss-fuzz/../qom/object.c:1472:15
    #7 0x55b0eefa2c1b in aspeed_soc_realize /root/qemu/build-oss-fuzz/../hw/arm/aspeed_soc.c:308:10
    #8 0x55b0ef798890 in device_set_realized /root/qemu/build-oss-fuzz/../hw/core/qdev.c:761:13
    #9 0x55b0ef7cf7c5 in property_set_bool /root/qemu/build-oss-fuzz/../qom/object.c:2257:5
    #10 0x55b0ef7ca61c in object_property_set /root/qemu/build-oss-fuzz/../qom/object.c:1402:5
    #11 0x55b0ef7d34a7 in object_property_set_qobject /root/qemu/build-oss-fuzz/../qom/qom-qobject.c:28:10
    #12 0x55b0ef7caf5f in object_property_set_bool /root/qemu/build-oss-fuzz/../qom/object.c:1472:15
    #13 0x55b0eeff96ff in aspeed_machine_init /root/qemu/build-oss-fuzz/../hw/arm/aspeed.c:340:5
    #14 0x55b0eea7c2e5 in machine_run_board_init /root/qemu/build-oss-fuzz/../hw/core/machine.c:1237:5

    #15 0x55b0ef57c7ba in qemu_init_board /root/qemu/build-oss-fuzz/../softmmu/vl.c:2514:5
    #16 0x55b0ef57c7ba in qmp_x_exit_preconfig /root/qemu/build-oss-fuzz/../softmmu/vl.c:2588:5
    #17 0x55b0ef584ad9 in qemu_init /root/qemu/build-oss-fuzz/../softmmu/vl.c:3611:9
    #18 0x55b0ee62bb2e in LLVMFuzzerInitialize /root/qemu/build-oss-fuzz/../tests/qtest/fuzz/fuzz.c:238:5
    #19 0x55b0ee5058be in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:645
    #20 0x55b0ee4f3f92 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #21 0x7f85f55f6bf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310

SUMMARY: AddressSanitizer: heap-buffer-overflow /root/qemu/build-oss-fuzz/../hw/ssi/aspeed_smc.c:665:18 in aspeed_smc_flash_do_select
Shadow bytes around the buggy address:
  0x0c048000fb70: fa fa fd fa fa fa fd fa fa fa fd fd fa fa fd fa
  0x0c048000fb80: fa fa fd fa fa fa fd fd fa fa 00 01 fa fa 00 03
  0x0c048000fb90: fa fa fd fd fa fa fd fd fa fa 00 06 fa fa 00 02
  0x0c048000fba0: fa fa 00 00 fa fa 00 00 fa fa 00 01 fa fa 05 fa
  0x0c048000fbb0: fa fa 04 fa fa fa fd fd fa fa 04 fa fa fa 00 03
=>0x0c048000fbc0: fa fa 00[fa]fa fa fd fd fa fa fd fd fa fa 00 06
  0x0c048000fbd0: fa fa 00 02 fa fa 00 02 fa fa 05 fa fa fa 07 fa
  0x0c048000fbe0: fa fa 00 01 fa fa 07 fa fa fa 05 fa fa fa 07 fa
  0x0c048000fbf0: fa fa 00 02 fa fa 05 fa fa fa 07 fa fa fa 00 01
  0x0c048000fc00: fa fa 07 fa fa fa 05 fa fa fa 07 fa fa fa 00 02
  0x0c048000fc10: fa fa 05 fa fa fa 07 fa fa fa 00 01 fa fa 07 fa
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
==563==ABORTING
```

### Reproducer steps

I use QTest to reproduce this crash. Note that qemu should be instrumented by ASAN.

```
#!/bin/bash -x
export QEMU=/root/qemu/build-oss-fuzz/qemu-system-arm
export BUILDROOT=./
# 0x24242400 is the address of the second aspeed Flash chip
cat << EOF | $QEMU \
-M palmetto-bmc,accel=qtest -qtest stdio -monitor none -serial none \
-display none -nodefaults -qtest stdio
writel 0x1e660424 0x24242400
writel 0x1e661050 0x1a1a1a1a
EOF
```

## Contact

Let us know if I need to provide more information.
