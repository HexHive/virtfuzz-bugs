# Out of bounds in imx_usbphy_read()

# Out of bounds in imx_usbphy_read
## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type

arm, imx_usb_phy, usb

### Bug Type: Out-of-bounds Read

### Stack traces, crash details

```
root@fff5a5933072:~/qemu/build-san-5# ./qemu-fuzz-arm --fuzz-target=stateful-fuzz-imx-usb-phy crash-3f7a852b52d0e3fb62175442730b5b7092218430 
INFO: found LLVMFuzzerCustomMutator (0x560b87224700). Disabling -len_control by default.
INFO: libFuzzer ignores flags that start with '--'
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3615372409
INFO: Loaded 1 modules   (997152 inline 8-bit counters): 997152 [0x560b8ad5a000, 0x560b8ae4d720),
INFO: Loaded 1 PC tables (997152 PCs): 997152 [0x560b89e22c70,0x560b8ad59e70),
./qemu-fuzz-arm: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
Matching objects by name , *imx-usbphy*
This process will fuzz the following MemoryRegions:
  * imx-usbphy[0] (size 1000)
  * imx-usbphy[0] (size 1000)
This process will fuzz through the following interfaces:
  * imx-usbphy, EVENT_TYPE_MMIO_READ, 0x20c9000 +0x1000, 4,4
  * imx-usbphy, EVENT_TYPE_MMIO_WRITE, 0x20c9000 +0x1000, 4,4
  * imx-usbphy, EVENT_TYPE_MMIO_READ, 0x20ca000 +0x1000, 4,4
  * imx-usbphy, EVENT_TYPE_MMIO_WRITE, 0x20ca000 +0x1000, 4,4
  * imx-usbphy, EVENT_TYPE_MMIO_READ, 0x20c9000 +0x1000, 4,4
  * imx-usbphy, EVENT_TYPE_MMIO_WRITE, 0x20c9000 +0x1000, 4,4
  * imx-usbphy, EVENT_TYPE_MMIO_READ, 0x20ca000 +0x1000, 4,4
  * imx-usbphy, EVENT_TYPE_MMIO_WRITE, 0x20ca000 +0x1000, 4,4
INFO: A corpus is not provided, starting from an empty corpus
#2	INITED cov: 11 ft: 12 corp: 1/1b exec/s: 0 rss: 220Mb
Running: crash-3f7a852b52d0e3fb62175442730b5b7092218430
/root/qemu/hw/usb/imx-usb-phy.c:94:17: runtime error: index 1023 out of bounds for type 'uint32_t [33]'
    #0 0x560b86108eea in imx_usbphy_read imx-usb-phy.c
    #1 0x560b83ccaa21 in memory_region_read_accessor memory.c
    #2 0x560b83c5c2f6 in access_with_adjusted_size memory.c
    #3 0x560b83c584ab in memory_region_dispatch_read1 memory.c
    #4 0x560b83c576dd in memory_region_dispatch_read (/root/qemu/build-san-5/qemu-fuzz-arm+0x45886dd)
    #5 0x560b82f04b68 in flatview_read_continue (/root/qemu/build-san-5/qemu-fuzz-arm+0x3835b68)
    #6 0x560b82f0744b in flatview_read exec.c
    #7 0x560b82f06fa1 in address_space_read_full (/root/qemu/build-san-5/qemu-fuzz-arm+0x3837fa1)
    #8 0x560b8720e048 in __wrap_qtest_readl (/root/qemu/build-san-5/qemu-fuzz-arm+0x7b3f048)
    #9 0x560b872b496a in dispatch_mmio_read stateful_fuzz.c
    #10 0x560b8722e927 in dispatch_event stateful_fuzz.c
    #11 0x560b872b6e0a in stateful_fuzz stateful_fuzz.c
    #12 0x560b872066be in LLVMFuzzerTestOneInput (/root/qemu/build-san-5/qemu-fuzz-arm+0x7b376be)
    #13 0x560b82dba7f3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:607
    #14 0x560b82d9db1a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #15 0x560b82da87d4 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:883
    #16 0x560b82d7e3c2 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #17 0x7f49274ecbf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
    #18 0x560b82d93f49 in _start (/root/qemu/build-san-5/qemu-fuzz-arm+0x36c4f49)

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /root/qemu/hw/usb/imx-usb-phy.c:94:17 in 
MS: 0 ; base unit: 0000000000000000000000000000000000000000```

### Reproducer steps

# With USBAN
./qemu-fuzz-arm --fuzz-target=stateful-fuzz-imx-usb-phy crash-3f7a852b52d0e3fb62175442730b5b7092218430 
## Contact

Let us know if I need to provide more information.
