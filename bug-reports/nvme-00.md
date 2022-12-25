# Null pointer deference in memory_region_set_enabled()

An access on an unknown address is triggered in memory_region_set_enabled
because the check of PMR capability is missing for the PMRCTL register write
when PMR is not set in the launch command line.

## Root Cause Analysis

```
static void nvme_write_bar(NvmeCtrl *n, hwaddr offset, uint64_t data, ...) {
  switch (offset) {
    case 0xE04: /* PMRCTL */
       // ROOT CAUSE: there should be a check here
       // when PMR is not configured, return directly
       // otherwise, n->pmr.dev will be NULL
       n->bar.pmrctl = data;
       if (NVME_PMRCTL_EN(data)) {
           memory_region_set_enabled(&n->pmr.dev->mr, true);
           n->bar.pmrsts = 0;        //--------------
       } else {                      // null pointer
           // omit
       }
       return;

void memory_region_set_enabled(MemoryRegion *mr, bool enabled) {
    if (enabled == mr->enabled) {    // crash at the deref of mr->enabled
        return;
    }
    // omit
}
```


## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubunut 18.04

### VM architecture, device, device type

i386, nvme, storage

### Bug Type: Null Pointer Dereference

### Stack traces, crash details

```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==144==ERROR: AddressSanitizer: SEGV on unknown address 0x0000000000ea (pc 0x55ac399a2783 bp 0x7ffe09be78f0 sp 0x7ffe09be78d0 T0)
==144==The signal is caused by a READ memory access.
==144==Hint: address points to the zero page.
    #0 0x55ac399a2783 in memory_region_set_enabled /root/qemu/build-oss-fuzz/../softmmu/memory.c:2482:24
    #1 0x55ac3942691b in nvme_write_bar /root/qemu/build-oss-fuzz/../hw/block/nvme.c:5588:13
    #2 0x55ac3942691b in nvme_mmio_write /root/qemu/build-oss-fuzz/../hw/block/nvme.c:5814:9
    #3 0x55ac39999757 in memory_region_write_accessor /root/qemu/build-oss-fuzz/../softmmu/memory.c:491:5
    #4 0x55ac3999911d in access_with_adjusted_size /root/qemu/build-oss-fuzz/../softmmu/memory.c:552:18
    #5 0x55ac3999911d in memory_region_dispatch_write /root/qemu/build-oss-fuzz/../softmmu/memory.c:1502:16
    #6 0x55ac398191d0 in flatview_write_continue /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2746:23
    #7 0x55ac3980b7e7 in flatview_write /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2786:14
    #8 0x55ac3980af8c in address_space_write /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2878:18
    #9 0x55ac38d12f6c in __wrap_qtest_writel /root/qemu/build-oss-fuzz/../tests/qtest/fuzz/qtest_wrappers.c:177:9
    #10 0x55ac38d0de6a in stateful_fuzz /root/qemu/build-oss-fuzz/../tests/qtest/fuzz/stateful_fuzz.c:402:13
    #11 0x55ac38d0f5e0 in LLVMFuzzerTestOneInput /root/qemu/build-oss-fuzz/../tests/qtest/fuzz/fuzz.c:151:5
    #12 0x55ac38bfe383 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:603
    #13 0x55ac38c01d48 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:509
    #14 0x55ac38c03afe in fuzzer::Fuzzer::MutateAndTestOne() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:750
    #15 0x55ac38c06f87 in fuzzer::Fuzzer::Loop(std::vector<fuzzer::SizedFile, fuzzer::fuzzer_allocator<fuzzer::SizedFile> >&) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:887
    #16 0x55ac38bec439 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:908
    #17 0x55ac38bd8112 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #18 0x7f5225198bf6 in __libc_start_main (/root/qemu/build-oss-fuzz/DEST_DIR/lib/libc.so.6+0x21bf6)
    #19 0x55ac38bd8169 in _start (/root/qemu/build-oss-fuzz/DEST_DIR/qemu-fuzz-i386-target-stateful-fuzz-nvme+0xed2169)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /root/qemu/build-oss-fuzz/../softmmu/memory.c:2482:24 in memory_region_set_enabled

```

### Reproducer steps

I wrote a kernel module to reproduce this crash.
>uint32_t address = (uint32_t)ioremap(0xfebd0000, 16 * 1024);
>writel(0xffffffff, (void *)(address + 0xe04)); // trigger

Execute
```
#!/bin/bash
export QEMU=/root/qemu/build-coverage/qemu-system-i386
export BUILDROOT=/root/images
$QEMU \
    -M q35 \
    -kernel $BUILDROOT/bzImage \
    -drive file=$BUILDROOT/rootfs.ext2,if=virtio,format=raw \
    -append "root=/dev/vda console=ttyS0" \
    -nic user,model=virtio-net-pci \
    -drive id=nvm,file=null-co://,file.read-zeroes=on,if=none,format=raw \
    -device nvme,serial=deadbeef,drive=nvm \
    -nographic \
    -m 64
```

The username is root and the password is empty.
Then, `modprobe nvme-00` and you will see the crash.

```
# modprobe nvme-00
nvme_00: loading out-of-tree module taints kernel.
UndefinedBehaviorSanitizer:DEADLYSIGNAL
==34==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x0000000000ea (pc 0x56486060a980 bp 0x7f413b2fbfb0 sp 0x7f413b2fbf90 T36)
==34==The signal is caused by a READ memory access.
==34==Hint: address points to the zero page.
```

Attachment: https://drive.google.com/file/d/1Ou7hcu_tdFNJAF5W1M0XPAqevxZ_jO8V/view?usp=sharing


## Contact

Let us know if I need to provide more information.
