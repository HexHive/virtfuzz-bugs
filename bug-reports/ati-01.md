# OOB write in ati_2d_blt()

There is an inconsistent check and use of dst_[x|y] and s->regs.dst_[x|y] in
ati_2d_blt. This inconsistent check will cause an OOB write of vram_ptr.

## Root Cause Analysis

In the latest ati_2d_blt(), according to s->regs.dp_cntrl, dst_[x|y] has
different semantics.

```
    unsigned dst_x = (s->regs.dp_cntl & DST_X_LEFT_TO_RIGHT ?
                      s->regs.dst_x : s->regs.dst_x + 1 - s->regs.dst_width);
    unsigned dst_y = (s->regs.dp_cntl & DST_Y_TOP_TO_BOTTOM ?
                      s->regs.dst_y : s->regs.dst_y + 1 - s->regs.dst_height);
```
Especially, when DST_X_RIGHT_TO_LEFT is set, dst_x will be s->regs.dst_x + 1 -
s->regs.dst_width.

Following is a check to fix CVE-2020-27616.
```
   if (dst_x > 0x3fff || dst_y > 0x3fff || dst_bits >= end
        || dst_bits + dst_x
         + (dst_y + s->regs.dst_height) * dst_stride >= end) {
        qemu_log_mask(LOG_UNIMP, "blt outside vram not implemented\n");
        return;
    }
```

So far so good. However, in the following branch switch(s->regs.dp_mix &
GMC_ROP3_MASK) case ROP3_WHITENESS,
 when DST_X_RIGHT_TO_LEFT or
DST_Y_BOTTOM_TO_TOP is set, pixman_fill will use s->regs.dst_[x|y] that are not
equal to dst_[x|y] in the check, which will cause an OOB write of vram_ptr.

```
        pixman_fill((uint32_t *)dst_bits, dst_stride, bpp,
                    s->regs.dst_x, s->regs.dst_y,
                    s->regs.dst_width, s->regs.dst_height,
                    filler);
```

pixman_fill, e.g., pixman_fill8, will write `filler` to the destination bytes.

```
static void pixman_fill8 (
	uint32_t *bits,  int stride, int x, int y,
	int width, int height, uint32_t  filler) {
    int byte_stride = stride * (int) sizeof (uint32_t);
    uint8_t *dst = (uint8_t *) bits;
    uint8_t v = filler & 0xff;
    int i;

    dst = dst + y * byte_stride + x;

    while (height--)
    {
	for (i = 0; i < width; ++i)
	    dst[i] = v;

	dst += byte_stride;
    }
}
```

## Security Impact

The parameter of pixman_fill, i.e., dst_stride, bpp, s->regs.dst_x,
s->regs.dst_y, s->regs.dst_width, and s->regs.dst_height, all can be controlled
by a malicious guest. But not I am not clear what memory objects can be written by
this primitive.


## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type
i386, ati, display

### Bug Type: Out-of-bounds Write

### Stack traces, crash details

```
AddressSanitizer:DEADLYSIGNAL
=================================================================
==698==ERROR: AddressSanitizer: SEGV on unknown address 0x7f471e600000 (pc 0x7f476b3f1a80 bp 0x0000fffffffe sp 0x7f471f9fd8c0 T2)
==698==The signal is caused by a WRITE memory access.
    #0 0x7f476b3f1a80  (/usr/lib/x86_64-linux-gnu/libpixman-1.so.0+0x6ca80)
    #1 0x7f476b3d6b28  (/usr/lib/x86_64-linux-gnu/libpixman-1.so.0+0x51b28)
    #2 0x7f476b38ffe8 in pixman_fill (/usr/lib/x86_64-linux-gnu/libpixman-1.so.0+0xafe8)
    #3 0x55668538d545 in ati_2d_blt /root/qemu/build-oss-fuzz/../hw/display/ati_2d.c:201:9
    #4 0x556685886e5a in ati_mm_write /root/qemu/build-oss-fuzz/../hw/display/ati.c
    #5 0x556685f90f67 in memory_region_write_accessor /root/qemu/build-oss-fuzz/../softmmu/memory.c:491:5
    #6 0x556685f9092d in access_with_adjusted_size /root/qemu/build-oss-fuzz/../softmmu/memory.c:552:18
    #7 0x556685f9092d in memory_region_dispatch_write /root/qemu/build-oss-fuzz/../softmmu/memory.c:1502:16
    #8 0x556685eb663e in io_writex /root/qemu/build-oss-fuzz/../accel/tcg/cputlb.c:1425:9
    #9 0x556685ea0963 in store_helper /root/qemu/build-oss-fuzz/../accel/tcg/cputlb.c:2444:13
    #10 0x7f472b32e836  (<unknown module>)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/usr/lib/x86_64-linux-gnu/libpixman-1.so.0+0x6ca80)
Thread T2 created by T0 here:
    #0 0x55668524c0df in __interceptor_pthread_create /root/llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp:205
    #1 0x55668654e45a in qemu_thread_create /root/qemu/build-oss-fuzz/../util/qemu-thread-posix.c:558:11
    #2 0x556685f7d736 in mttcg_start_vcpu_thread /root/qemu/build-oss-fuzz/../accel/tcg/tcg-accel-ops-mttcg.c:127:5
    #3 0x556685e215fe in qemu_init_vcpu /root/qemu/build-oss-fuzz/../softmmu/cpus.c:628:5
    #4 0x556685b5766a in x86_cpu_realizefn /root/qemu/build-oss-fuzz/../target/i386/cpu.c:6910:5
    #5 0x5566860df960 in device_set_realized /root/qemu/build-oss-fuzz/../hw/core/qdev.c:761:13
    #6 0x556686116895 in property_set_bool /root/qemu/build-oss-fuzz/../qom/object.c:2257:5
    #7 0x5566861116ec in object_property_set /root/qemu/build-oss-fuzz/../qom/object.c:1402:5
    #8 0x55668611a577 in object_property_set_qobject /root/qemu/build-oss-fuzz/../qom/qom-qobject.c:28:10
    #9 0x55668611202f in object_property_set_bool /root/qemu/build-oss-fuzz/../qom/object.c:1472:15
    #10 0x556685aed696 in x86_cpu_new /root/qemu/build-oss-fuzz/../hw/i386/x86.c:111:5
    #11 0x556685aed847 in x86_cpus_init /root/qemu/build-oss-fuzz/../hw/i386/x86.c:138:9
    #12 0x556685af71e9 in pc_q35_init /root/qemu/build-oss-fuzz/../hw/i386/pc_q35.c:180:5
    #13 0x5566856602a5 in machine_run_board_init /root/qemu/build-oss-fuzz/../hw/core/machine.c:1237:5
    #14 0x556685ec7a1a in qemu_init_board /root/qemu/build-oss-fuzz/../softmmu/vl.c:2514:5
    #15 0x556685ec7a1a in qmp_x_exit_preconfig /root/qemu/build-oss-fuzz/../softmmu/vl.c:2588:5
    #16 0x556685ecfd39 in qemu_init /root/qemu/build-oss-fuzz/../softmmu/vl.c:3611:9
    #17 0x55668530a820 in main /root/qemu/build-oss-fuzz/../softmmu/main.c:49:5
    #18 0x7f4769227bf6 in __libc_start_main /build/glibc-S9d2JN/glibc-2.27/csu/../csu/libc-start.c:310
==698==ABORTING

```

### Reproducer steps

I wrote a kernel module to reproduce this crash.

```
#!/bin/bash
export QEMU=/root/qemu/build-oss-fuzz/qemu-system-i386
export BUILDROOT=./
$QEMU \
    -M q35 \
    -kernel $BUILDROOT/bzImage \
    -drive file=$BUILDROOT/rootfs.ext2,if=virtio,format=raw \
    -append "root=/dev/vda console=ttyS0" \
    -nic user,model=virtio-net-pci \
    -device ati-vga,romfile="" \
    -nographic \
    -m 64
```

Execute. The username is root and the password is empty.
Then, `modprobe ati-00`, and you will see the crash.

The bzImage and rootfs.ext2 are attached.

Attachment: https://drive.google.com/file/d/17ZxZcq2Wt0kzNyxXsF1sXRirh37jIGk-/view?usp=sharing

## Suggested fix

```
From: "Philippe Mathieu-Daudé" <philmd@redhat.com>
To: qemu-devel@nongnu.org
Cc: "Mauro Matteo Cascella" <mcascell@redhat.com>,
	"Qiang Liu" <qiangliu@zju.edu.cn>,
	"Prasad J Pandit" <pjp@fedoraproject.org>,
	"Gerd Hoffmann" <kraxel@redhat.com>,
	"Gaoning Pan" <pgn@zju.edu.cn>,
	"Philippe Mathieu-Daudé" <philmd@redhat.com>,
	"Ziming Zhang" <ezrakiez@gmail.com>,
	"Salvatore Bonaccorso" <carnil@debian.org>
Subject: [PATCH] hw/display/ati_2d: Fix buffer overflow in ati_2d_blt (CVE-2021-3638)
Date: Mon,  6 Sep 2021 17:31:03 +0200	[thread overview]
Message-ID: <20210906153103.1661195-1-philmd@redhat.com> (raw)

When building QEMU with DEBUG_ATI defined then running with
'-device ati-vga,romfile="" -d unimp,guest_errors -trace ati\*'
we get:

  ati_mm_write 4 0x16c0 DP_CNTL <- 0x1
  ati_mm_write 4 0x146c DP_GUI_MASTER_CNTL <- 0x2
  ati_mm_write 4 0x16c8 DP_MIX <- 0xff0000
  ati_mm_write 4 0x16c4 DP_DATATYPE <- 0x2
  ati_mm_write 4 0x224 CRTC_OFFSET <- 0x0
  ati_mm_write 4 0x142c DST_PITCH_OFFSET <- 0xfe00000
  ati_mm_write 4 0x1420 DST_Y <- 0x3fff
  ati_mm_write 4 0x1410 DST_HEIGHT <- 0x3fff
  ati_mm_write 4 0x1588 DST_WIDTH_X <- 0x3fff3fff
  ati_2d_blt: vram:0x7fff5fa00000 addr:0 ds:0x7fff61273800 stride:2560 bpp:32 rop:0xff
  ati_2d_blt: 0 0 0, 0 127 0, (0,0) -> (16383,16383) 16383x16383 > ^
  ati_2d_blt: pixman_fill(dst:0x7fff5fa00000, stride:254, bpp:8, x:16383, y:16383, w:16383, h:16383, xor:0xff000000)
  Thread 3 "qemu-system-i38" received signal SIGSEGV, Segmentation fault.
  (gdb) bt
  #0  0x00007ffff7f62ce0 in sse2_fill.lto_priv () at /lib64/libpixman-1.so.0
  #1  0x00007ffff7f09278 in pixman_fill () at /lib64/libpixman-1.so.0
  #2  0x0000555557b5a9af in ati_2d_blt (s=0x631000028800) at hw/display/ati_2d.c:196
  #3  0x0000555557b4b5a2 in ati_mm_write (opaque=0x631000028800, addr=5512, data=1073692671, size=4) at hw/display/ati.c:843
  #4  0x0000555558b90ec4 in memory_region_write_accessor (mr=0x631000039cc0, addr=5512, ..., size=4, ...) at softmmu/memory.c:492

Commit 584acf34cb0 ("ati-vga: Fix reverse bit blts") introduced
the local dst_x and dst_y which adjust the (x, y) coordinates
depending on the direction in the SRCCOPY ROP3 operation, but
forgot to address the same issue for the PATCOPY, BLACKNESS and
WHITENESS operations, which also call pixman_fill().

Fix that now by using the adjusted coordinates in the pixman_fill
call, and update the related debug printf().

Reported-by: Qiang Liu <qiangliu@zju.edu.cn>
Fixes: 584acf34cb0 ("ati-vga: Fix reverse bit blts")
Signed-off-by: Philippe Mathieu-Daudé <philmd@redhat.com>
---
 hw/display/ati_2d.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/hw/display/ati_2d.c b/hw/display/ati_2d.c
index 4dc10ea7952..692bec91de4 100644
--- a/hw/display/ati_2d.c
+++ b/hw/display/ati_2d.c
@@ -84,7 +84,7 @@ void ati_2d_blt(ATIVGAState *s)
     DPRINTF("%d %d %d, %d %d %d, (%d,%d) -> (%d,%d) %dx%d %c %c\n",
             s->regs.src_offset, s->regs.dst_offset, s->regs.default_offset,
             s->regs.src_pitch, s->regs.dst_pitch, s->regs.default_pitch,
-            s->regs.src_x, s->regs.src_y, s->regs.dst_x, s->regs.dst_y,
+            s->regs.src_x, s->regs.src_y, dst_x, dst_y,
             s->regs.dst_width, s->regs.dst_height,
             (s->regs.dp_cntl & DST_X_LEFT_TO_RIGHT ? '>' : '<'),
             (s->regs.dp_cntl & DST_Y_TOP_TO_BOTTOM ? 'v' : '^'));
@@ -180,11 +180,11 @@ void ati_2d_blt(ATIVGAState *s)
         dst_stride /= sizeof(uint32_t);
         DPRINTF("pixman_fill(%p, %d, %d, %d, %d, %d, %d, %x)\n",
                 dst_bits, dst_stride, bpp,
-                s->regs.dst_x, s->regs.dst_y,
+                dst_x, dst_y,
                 s->regs.dst_width, s->regs.dst_height,
                 filler);
         pixman_fill((uint32_t *)dst_bits, dst_stride, bpp,
-                    s->regs.dst_x, s->regs.dst_y,
+                    dst_x, dst_y,
                     s->regs.dst_width, s->regs.dst_height,
                     filler);
         if (dst_bits >= s->vga.vram_ptr + s->vga.vbe_start_addr &&
-- 
2.31.1
```

## Contact

Let us know if I need to provide more information.
