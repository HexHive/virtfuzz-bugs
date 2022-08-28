# Assertion failure in usb_cancel_packet

When I ran hcd-ohci with dev-storage, I found an assertion failure in
usb_cancel_packet() [1] due to p->state == USB_PACKET_COMPLETE. This is due to
the inconsistency when resetting device.

``` c
static inline bool usb_packet_is_inflight(USBPacket *p)
{
    return (p->state == USB_PACKET_QUEUED ||
            p->state == USB_PACKET_ASYNC);
}

void usb_cancel_packet(USBPacket * p)
{
    bool callback = (p->state == USB_PACKET_ASYNC);
    assert(usb_packet_is_inflight(p)); // <------------------------------- [1]
    usb_packet_set_state(p, USB_PACKET_CANCELED);
    QTAILQ_REMOVE(&p->ep->queue, p, queue);
    if (callback) {
        usb_device_cancel_packet(p->ep->dev, p);
    }
}
```

## Crash analysis

1 With crafted ED and TD, we can have the ohci->usb_packet's status to be
USB_RET_ASYNC [5]. And thus ohci->async_td is not NULL anymore [2].

```
ed0 = { flags = 0x685f0900, tail = 0x0, head = &td0, next = 0 }

td0 = { flags = 0x0, cbp = 0x1b8ffc, next = 0, be = 0x1b901a }
# data from cbp to be
55 53 42 43 00 00 00 00 00 00 00 00 00 00 00 03    USBC............
e8 56 20 40 e8 56 20 40 e8 56 20 40 e8 56 20

ed1 = { flags = 0x08303080, tail = 0x0, head = &td1, next = 0 }

td1 = { flags = 0x90000000, cbp = 0x19affc, next = 0, be = 0x19b01a }
# data from cbp to be
55 53 42 43 00 00 00 00 00 00 00 00 00 00 00 03    USBC............
e8 56 20 40 e8 56 20 40 e8 56 20 40 e8 56 20
```

``` c
static int ohci_service_td(OHCIState *ohci, struct ohci_ed *ed)
{
        // ...
        usb_handle_packet(dev, &ohci->usb_packet); // <------------------- [4]
        if (ohci->usb_packet.status == USB_RET_ASYNC) {
            usb_device_flush_ep_queue(dev, ep);
            ohci->async_td = addr; // <----------------------------------- [2]
            return 1;
        }
```

At the same time, the dev-storage will ref the current usb_packet
(ohci->usb_packet) [4][3].

```
static void usb_msd_handle_data(USBDevice *dev, USBPacket *p) {
        // ...
        s->packet = p; // <----------------------------------------------- [3]
        p->status = USB_RET_ASYNC; // <----------------------------------- [5]
        // ...
}
```

2 We can first issue `MMIO_WRITE, 0xe0000054, 0x4, 0x4e33b4bf` to reset
the dev-storage device. This will mark the state of ohci->usb_packet to
USB_PACKET_COMPLETE and clear s->packet.

```
ohci_mem_write
    ohci_port_set_status
        usb_device_reset
            usb_device_handle_reset
                usb_msd_handle_reset
                    usb_msd_packet_complete
                        usb_packet_complete
```

3  We can then issue `MMIO_WRITE, 0xe0000004, 0x4, 0x3d8d323a` to reset the
roothub and this will invoke ohci_stop_endpoints() where usb_cancel_packet()
is invoked and thus [1] fails as the state of ohci->usb_packet has been changed
to USB_PACKET_COMPLETE.

```
ohci_set_ctl
    ohci_roothub_reset
        ohci_stop_endpoints
            if (ohci->async_td != NULL) usb_cancel_packet(&ohci->usb_packet);
            assert(usb_packet_is_inflight(p)); // boom
```

The above callstack are simplified. The complete callstack is in the following.

```
ohci_set_ctl
    ohci_roothub_reset
        usb_port_reset
            usb_detach
                ohci_detach
                    ohci_child_detach // <-------------------------------- [8]
            usb_device_reset // <----------------------------------------- [6]
                usb_device_handle_reset
                    usb_msd_handle_reset
                        usb_msd_packet_complete
                            usb_packet_complete
        ohci_stop_endpoints // <------------------------------------------ [7]
            if (ohci->async_td != NULL) usb_cancel_packet(&ohci->usb_packet);
            assert(usb_packet_is_inflight(p)); // boom
```

Interestingly, in ohci_roothub_reset(), usb_device_reset() is also invoked [6]
just like what in step 2. I adjusted my PoC by removing step 2. However, I
cannot reproduce this assertion failure. Therefore, there is something different
bewteen [6] and step 2.

Then, I found at [8], ohci_child_detach() cancels the ohci->usb_packet and reset
ohci->async_td. With step 2, as the status of the ohci->usb_packet has changed
to USB_PACKET_COMPLETE, usb_cancel_packet() will not be invoked. Without step 2,
as the status of the ohci->usb_packet is still USB_PACKET_ASYNC,
usb_cancel_packet() will be invoked and thus everything goes fine.

```
static void ohci_child_detach(USBPort *port1, USBDevice *dev)
{
    OHCIState *ohci = port1->opaque;

    if (ohci->async_td &&
        usb_packet_is_inflight(&ohci->usb_packet) &&
        ohci->usb_packet.ep->dev == dev) {
        usb_cancel_packet(&ohci->usb_packet);
        ohci->async_td = 0;
    }
}
```

## Suggested fix

I think we may want to detach the port before usb_device_reset() in
ohci_port_set_status().

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 7.0.91, c669f22f1a47897e8d1d595d6b8a59a572f9158c, Ubuntu 20.04

### VM architecture, device, device type
i386, ohci, usb

### Bug Type: Assertion Failure

### Stack traces, crash details

```
root@54773e3cfadc:~/videzzo/videzzo_qemu/out-san# /tmp/tmp.SmtxWaZl9r/picire_reproduce.sh /tmp/tmp.SmtxWaZl9r/picire_inputs.20220815_084552/tests/a0_r13_assert/picire_inputs 
==133815==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x55f9c6f45930). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3011583389
INFO: Loaded 1 modules   (423101 inline 8-bit counters): 423101 [0x55f9c95cb000, 0x55f9c96324bd), 
INFO: Loaded 1 PC tables (423101 PCs): 423101 [0x55f9c8f55b50,0x55f9c95ca720), 
/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci: Running 1 inputs 1 time(s) each.
INFO: Reading pre_seed_input if any ...
INFO: Executing pre_seed_input if any ...
Matching objects by name , *ohci*
This process will fuzz the following MemoryRegions:
  * ohci[0] (size 100)
This process will fuzz through the following interfaces:
  * clock_step, EVENT_TYPE_CLOCK_STEP, 0xffffffff +0xffffffff, 255,255
  * ohci, EVENT_TYPE_MMIO_READ, 0xe0000000 +0x100, 1,4
  * ohci, EVENT_TYPE_MMIO_WRITE, 0xe0000000 +0x100, 1,4
INFO: seed corpus: files: 2511 min: 10b max: 3303848b total: 301897420b rss: 193Mb
i386: usb-msd: Bad CBW size
#1024   pulse  cov: 2681 ft: 6553 corp: 214/43Mb exec/s: 341 rss: 376Mb
#2048   pulse  cov: 2693 ft: 7601 corp: 282/50Mb exec/s: 341 rss: 404Mb
#2512   INITED cov: 3125 ft: 8321 corp: 305/56Mb exec/s: 358 rss: 412Mb
Running: /root/videzzo/videzzo_qemu/out-san/./crash-2dd2c6ca803314e8f5ae24133d11d7964215d14f
qemu-videzzo-i386-target-videzzo-fuzz-ohci: ../hw/usb/core.c:520: void usb_cancel_packet(USBPacket *): Assertion `usb_packet_is_inflight(p)' failed.
==133815== ERROR: libFuzzer: deadly signal
    #0 0x55f9c36e674e in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86:3
    #1 0x55f9c36353c1 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:38
    #2 0x55f9c360ec06 in fuzzer::Fuzzer::CrashCallback() (.part.0) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:235:18
    #3 0x55f9c360ecd2 in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207:1
    #4 0x55f9c360ecd2 in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:206:19
    #5 0x7fc94811a41f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f)
    #6 0x7fc947f2c00a in __libc_signal_restore_set /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/internal-signals.h:86:3
    #7 0x7fc947f2c00a in raise /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/raise.c:48:3
    #8 0x7fc947f0b858 in abort /build/glibc-SzIz7B/glibc-2.31/stdlib/abort.c:79:7
    #9 0x7fc947f0b728 in __assert_fail_base /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:92:3
    #10 0x7fc947f1cfd5 in __assert_fail /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:101:3
    #11 0x55f9c4aeed4d in usb_cancel_packet /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/core.c:520:5
    #12 0x55f9c4b6f490 in ohci_stop_endpoints /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:285:9
    #13 0x55f9c4b75a46 in ohci_frame_boundary /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1186:9
    #14 0x55f9c6cf121e in timerlist_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:576:9
    #15 0x55f9c6cf154c in qemu_clock_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:590:12
    #16 0x55f9c5f83a44 in qtest_clock_warp /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:358:9
    #17 0x55f9c5f82916 in qtest_process_command /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:751:9
    #18 0x55f9c5f75f8d in qtest_process_inbuf /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:796:9
    #19 0x55f9c5f75caf in qtest_server_inproc_recv /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:927:9
    #20 0x55f9c68db9c5 in send_wrapper /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:1386:5
    #21 0x55f9c68d5c81 in qtest_sendf /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:453:5
    #22 0x55f9c68d5e45 in qtest_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:810:5
    #23 0x55f9c37252c1 in dispatch_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1202:5
    #24 0x55f9c6f412ef in videzzo_dispatch_event /root/videzzo/videzzo.c:1118:5
    #25 0x55f9c6f3f09c in dispatch_group_event /root/videzzo/videzzo.c:1013:9
    #26 0x55f9c6f412ef in videzzo_dispatch_event /root/videzzo/videzzo.c:1118:5
    #27 0x55f9c6f385cb in __videzzo_execute_one_input /root/videzzo/videzzo.c:256:9
    #28 0x55f9c6f384a0 in videzzo_execute_one_input /root/videzzo/videzzo.c:297:9
    #29 0x55f9c372987c in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1435:12
    #30 0x55f9c6f45bd2 in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1887:18
    #31 0x55f9c360f73d in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:589:17
    #32 0x55f9c35f24c4 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #33 0x55f9c35fd43e in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:882:19
    #34 0x55f9c35e9a46 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #35 0x7fc947f0d082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #36 0x55f9c35e9a9d in _start (/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci+0x2655a9d)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000
```

### Reproducer steps

Step 1: download the prepared rootfs and the image.

https://drive.google.com/file/d/1B95zWWcomvZt1wms31Ddc9Xwlq-bfqhq/view?usp=sharing
https://drive.google.com/file/d/1pxFzn49MKYmMMIIsaL9aUkzebRSYfq3J/view?usp=sharing

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
    -usb \
    -device pci-ohci,num-ports=6 \
    -drive file=null-co://,if=none,format=raw,id=disk0 \
    -device usb-storage,port=1,drive=disk0 \
    -nographic
```

Step 3: with spawned shell (the user is root and the password is empty), run
`ohci-03`.


## Suggested fix

```
From f63659addb97c7a3af810bed45f41fc293358121 Mon Sep 17 00:00:00 2001
From: Qiang Liu <cyruscyliu@gmail.com>
Date: Sun, 28 Aug 2022 18:56:48 +0800
Subject: [PATCH] hcd-ohci: Fix inconsistency when resetting root hubs

---
 hw/usb/hcd-ohci.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/hw/usb/hcd-ohci.c b/hw/usb/hcd-ohci.c
index 895b29fb86..72df917834 100644
--- a/hw/usb/hcd-ohci.c
+++ b/hw/usb/hcd-ohci.c
@@ -1426,7 +1426,7 @@ static void ohci_port_set_status(OHCIState *ohci, int portnum, uint32_t val)
 
     if (ohci_port_set_if_connected(ohci, portnum, val & OHCI_PORT_PRS)) {
         trace_usb_ohci_port_reset(portnum);
-        usb_device_reset(port->port.dev);
+        usb_port_reset(&port->port);
         port->ctrl &= ~OHCI_PORT_PRS;
         /* ??? Should this also set OHCI_PORT_PESC.  */
         port->ctrl |= OHCI_PORT_PES | OHCI_PORT_PRSC;
-- 
2.25.1

```

## Contact

Let us know if I need to provide more information.
