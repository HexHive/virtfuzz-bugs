# Out of memory in hw/omap-dss for ARM

In omap-dss, g_realloc() can allocate a large buffer using out of the memory.

- [1] set pixels to any value
- [2] double pixels
- [3] allocate a large buffer

```
static void omap_rfbi_write(...) {
   switch (addr) {
     case 0x44:	/* RFBI_PIXELCNT */
        s->rfbi.pixels = value; // ------------------------------------> [1]
        break;

static void omap_rfbi_transfer_start(struct omap_dss_s *s) {
    len = s->rfbi.pixels * 2;  // -------------------------------------> [2]
    if (!data) {
        if (len > bounce_len) {
            bounce_buffer = g_realloc(bounce_buffer, len); // ---------> [3]
        }
```

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 7.2.50, 222059a0fccf4af3be776fe35a5ea2d6a68f9a0b, Ubuntu 20.04

### VM architecture, device, device type

arm, omap_dss, display

### Bug Type: Out-of-Memory

### Stack traces, crash details

```

=================================================================
==1029323==ERROR: AddressSanitizer: requested allocation size 0xfffffffffffffffe (0x800 after adjustments for alignment, red zones etc.) exceeds maximum supported size of 0x10000000000 (thread T0)
    #0 0x7f4650b4ec3e in __interceptor_realloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:163
    #1 0x7f464fa27f3f in g_realloc (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x57f3f)
    #2 0x55cf6212c85b in omap_rfbi_write ../hw/display/omap_dss.c:761
    #3 0x55cf636b9c9b in memory_region_write_accessor ../softmmu/memory.c:493
    #4 0x55cf636ba132 in access_with_adjusted_size ../softmmu/memory.c:555
    #5 0x55cf636c76f8 in memory_region_dispatch_write ../softmmu/memory.c:1515
    #6 0x55cf637049b9 in flatview_write_continue ../softmmu/physmem.c:2825
    #7 0x55cf63704ddc in flatview_write ../softmmu/physmem.c:2867
    #8 0x55cf637057c4 in address_space_write ../softmmu/physmem.c:2963
    #9 0x55cf63716261 in qtest_process_command ../softmmu/qtest.c:533
    #10 0x55cf6371ac52 in qtest_process_inbuf ../softmmu/qtest.c:802
    #11 0x55cf6371ad43 in qtest_read ../softmmu/qtest.c:814
    #12 0x55cf63d4d5e5 in qemu_chr_be_write_impl ../chardev/char.c:201
    #13 0x55cf63d4d68c in qemu_chr_be_write ../chardev/char.c:213
    #14 0x55cf63d544c9 in fd_chr_read ../chardev/char-fd.c:72
    #15 0x55cf63938b9b in qio_channel_fd_source_dispatch ../io/channel-watch.c:84
    #16 0x7f464fa2204d in g_main_context_dispatch (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x5204d)

==1029323==HINT: if you don't care about these errors you may set allocator_may_return_null=1
SUMMARY: AddressSanitizer: allocation-size-too-big ../../../../src/libsanitizer/asan/asan_malloc_linux.cc:163 in __interceptor_realloc
==1029323==ABORTING
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
