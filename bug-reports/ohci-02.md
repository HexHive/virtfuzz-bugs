# Heap use after free in usb_cancel_packet()

A heap-use-after-free related to a USBPacket whose status is USB_RET_ASYNC was
found. I trigger it through hcd-ohci with dev-storage. The packet is allocated
at [1], freed at [2], and used at [3] or [4].

How to exploit: Through GDB, after [2], the pkt is put into an unsorted bin. By
this artical:
https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/unsorted_bin_attack/, this UAF
has potential to bypass ALSR and excute random functions.

How to fix: As pkt is freed at [2], maybe we should fully drop the USBPacket,
even from the endpoint queue.

``` c
static int ohci_service_iso_td(OHCIState *ohci, struct ohci_ed *ed)
{
    // ...
    ep = usb_ep_get(dev, pid, OHCI_BM(ed->flags, ED_EN));
    pkt = g_new0(USBPacket, 1); // <----------------- allocate [1]
    usb_packet_init(pkt);       // <---------------------------[8]
    int_req = relative_frame_number == frame_count &&
              OHCI_BM(iso_td.flags, TD_DI) == 0;
    usb_packet_setup(pkt, pid, ep, 0, addr, false, int_req);
    usb_packet_addbuf(pkt, buf, len);
    usb_handle_packet(dev, pkt);
    if (pkt->status == USB_RET_ASYNC) {
        usb_device_flush_ep_queue(dev, ep);
        g_free(pkt); // <-------------------------------- free [2]
        return 1;
    }
    // ...

void usb_cancel_packet(USBPacket * p)
{
    bool callback = (p->state == USB_PACKET_ASYNC);
    assert(usb_packet_is_inflight(p));
    usb_packet_set_state(p, USB_PACKET_CANCELED);
    QTAILQ_REMOVE(&p->ep->queue, p, queue); // <---------- use [3]
    if (callback) {
        usb_device_cancel_packet(p->ep->dev, p);
    }
}

void usb_msd_handle_reset(USBDevice *dev)
{
    // ...
    if (s->packet) {
        s->packet->status = USB_RET_STALL; // <----------- use [4]
        usb_msd_packet_complete(s);
    }
    // ...
}
```

## Crash analysis

1 Unlinking

Let's review some data structs in USBPacket

``` c
typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

union {
    struct USBPacket *tqe_next;
    QTailQLink tqe_circ;
} queue;

// +000 USBPacket p
// +104           p->queue
// +104           p->queue.tqe_next
// +104           p->queue.tql_circ->tql_next
// +112           p->queue.tql_circ->tql_prev

// QTAILQ_REMOVE(&p->ep->queue, p, queue)
if (p->queue.tqe_next != NULL)
    p->queue.tqe_next->queue.tqe_circ.tql_prev = \
//                     +104           +112
        p->queue.tqe_circ.tql_prev;
else
    (&p->ep->queue)->tqh_circ.tql_prev = \
        p->queue.tqe_circ.tql_prev;
// ...
```

In usb_cancel_packet(p=0x623000001260), packet p (0x627000001260) still thinks
packet p1 = p->queue.tqe_next (0x60d000005c10) exists, while packet p1 has been
freed. p1->queue.tqe_circ.tql_prev points to a freed space and thus [3] fails.

2 usb_msd_handle_reset()

In usb_msd_handle_reset(), s->packet has been freed at [2] and thus [4] fails.

## How to trigger this Heap UAF?

1 Craft ED and TD, visit usb_msd_handle_data() with USB_TOKEN_OUT + USB_MSDM_CBW

We want to make dev-storage to USB_MSDM_CSW.

```
0x1d4000 ed = { flags = 0xda9d3900, tail = 0x0, head = 0x137000, next = 0x140000 }

# the following is in ohci_service_td()
completion = 0
0x137000 td = { flags = 0xb548ffdd, cbp = 0x138ffc, next = 0x0, be = 0x13901a }
dir = 3
pid = USB_TOKEN_OUT
len = 0x1f
pktlen = 0x1f
# data between cbp to be
0x00007fffffff7b40     55 53 42 43 00 00 00 00 00 00 00 00 00 00 00 03    USBC............
0x00007fffffff7b50     d0 9d ea 81 d0 9d ea 81 d0 9d ea 81 d0 9d ea

# control flow
ohci_service_iso_td
    usb_handle_packet(dev=dev, p=ohci->usb_packet)
        usb_process_one(p=p)
            usb_msd_handle_data(dev=dev, p=p)
                // USB_TOKEN_OUT + USB_MSDM_CBW
                if (s->data_len == 0) {
                    s->mode = USB_MSDM_CSW;
                assert(s->req)
```

As such, s->mode is USB_MSDM_CSW and s->req is not NULL.

2 Craft ED and TD, visit usb_msd_handle_data() with USB_TOKEN_IN + USB_MSDM_CSW

We want to trigger ohci_service_td() and control the endpoint of and the status
of ohci->usb_packet.

```
0x137000 ed = { flags = 0x1a31080, tail = 0x0, head = 0x138000, next = 0x141000 }

# the following is in ohci_service_td()
completion = 0
0x138000 td = { flags = 0x0, cbp = 0x139ffc, next = 0x0, be = 0xf4e15e23 }
dir = 2
pid = USB_TOKEN_IN
len = 0xe28
pktlen = 0xe28
flag_r = 0
ep = (USBEndpoint *) 0x623000001248

# control flow
ohci_service_iso_td
    usb_handle_packet(dev=dev, p=ohci->usb_packet)
        usb_process_one(p=p)
            usb_msd_handle_data(dev=dev, p=p)
                // USB_TOKEN_IN + USB_MSDM_CSW
                if (s->req) p->status = USB_RET_ASYNC    // s->req is not NULL
        if (p->status == USB_RET_ASYNC) 
            QTAILQ_INSERT_TAIL(&p->ep->queue, p, queue); // <-- [7]
```

As shown, ohci->usb_packet is the tail of the endpoint's USBPacket queue [7].
Besides, ohci->usb_packet's status is USB_RET_ASYNC.

3 Craft ED and TD and visit usb_queue_one()

We want to allocate a new USBPacket and free it immediately.

```
0x1c0000 ed = { flags = 0xadb9080, tail = 0x0, head = 0x1c1000, next = 0x0 }

# the following is in ohci_service_iso_td()
0x1c1000 iso_td = { flags = 0xa4200000, bp = 0x22a2edc3, next = 0x0, be = 0x1173548,
                    offset = {0x0, 0x749b, 0xcbe3, 0x0, 0x0, 0x0, 0x0, 0x0} }
starting_frame = 0
frame_count = 4
relative_frame_number = 1 ( 0 < 1 < frame_count )
dir = 2
pid = USB_TOKEN_IN
start_offset = 0x749b
next_offset = 0xcbe3
start_addr = 0x117349b
end_addr = 0x22a2edc3
len = 0x1748
ep = (USBEndpoint *) 0x623000001248
```

Interesting, usb_handle_packet() invokes usb_queue_one() where the pkt is added
to the tail of the USBPacket queue of the endpoint (p->ep) [5]. However, the pkt
is immediately freed at [6].

```
ohci_service_iso_td
    pkt = g_new0(USBPacket, 1);
    usb_handle_packet(dev=dev, p=pkt)
        usb_queue_one(p=p)
            usb_packet_set_state(p, USB_PACKET_QUEUED);
            QTAILQ_INSERT_TAIL(&p->ep->queue, p, queue); // <--- [5]
            p->status = USB_RET_ASYNC
    if (p->status == USB_RET_ASYNC) g_free(pkt) // <------------ [6]
```

4 Detach USBPort and cancel ohci->usb_packet

```
MMIO_WRITE addr=0x4, val=0x4993d90b, size=0x4
```

The above mmio write will invoke ohci_child_detach() and then invoke
usb_cancel_packet() which will unlink ohci->usb_packet from the endpoint
USBPacket queue [7].

``` c
static void ohci_child_detach(USBPort *port1, USBDevice *dev)
{
    OHCIState *ohci = port1->opaque;

    if (ohci->async_td &&
        usb_packet_is_inflight(&ohci->usb_packet) &&
        ohci->usb_packet.ep->dev == dev) {
        usb_cancel_packet(&ohci->usb_packet); // <------------- [7]
        ohci->async_td = 0;
    }
}
```

Occasionally, ohci->usb_packet and pkt share the same endpoint and
ohci->usb_packet is in front of the pkt. When unlinking the USBPacket
ohci->usb_packet, as ohci does not know that pkt is freed, and thus [3] fails.

## Fixes

As pkt is freed at [2], maybe we should fully drop the USBPacket, even from the
endpoint queue. BTW, there is a small memory leakage at [8].


## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 7.0.50, c669f22f1a47897e8d1d595d6b8a59a572f9158c, Ubuntu 20.04

### VM architecture, device, device type
i386, ohci, usb

### Bug Type: Heap-Use-After-Free

### Stack traces, crash details

```
root@2210c9b13aa1:~/videzzo/videzzo_qemu/out-san# DEFAULT_INPUT_MAXSIZE=10000000 /root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci  -max_len=10000000 -detect_leaks=0 poc-qemu-videzzo-i386-target-videzzo-fuzz-ohci-crash-8cc902a05593b7cff5c12aedc22bd740ffcd824b
==14383==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x55993decefc0). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1849068663
INFO: Loaded 1 modules   (423123 inline 8-bit counters): 423123 [0x559940554000, 0x5599405bb4d3), 
INFO: Loaded 1 PC tables (423123 PCs): 423123 [0x55993fedee50,0x559940553b80), 
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
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 193Mb
Running: poc-qemu-videzzo-i386-target-videzzo-fuzz-ohci-crash-8cc902a05593b7cff5c12aedc22bd740ffcd824b
=================================================================
==14383==ERROR: AddressSanitizer: heap-use-after-free on address 0x60d000006090 at pc 0x55993ba78577 bp 0x7ffe83a8b8c0 sp 0x7ffe83a8b8b8
WRITE of size 8 at 0x60d000006090 thread T0
    #0 0x55993ba78576 in usb_cancel_packet /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/core.c:522:5
    #1 0x55993bb04f61 in ohci_child_detach /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1750:9
    #2 0x55993bb03a3d in ohci_detach /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1761:5
    #3 0x55993ba66a21 in usb_detach /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/core.c:70:5
    #4 0x55993ba66d51 in usb_port_reset /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/core.c:79:5
    #5 0x55993bafc04a in ohci_roothub_reset /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:314:13
    #6 0x55993bb35666 in ohci_set_ctl /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1346:9
    #7 0x55993bb2fdbe in ohci_mem_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1601:9
    #8 0x55993ce5ea93 in memory_region_write_accessor /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:492:5
    #9 0x55993ce5e3d1 in access_with_adjusted_size /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:554:18
    #10 0x55993ce5ccdc in memory_region_dispatch_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/memory.c:1514:16
    #11 0x55993cee770e in flatview_write_continue /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2825:23
    #12 0x55993ced5a8b in flatview_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2867:12
    #13 0x55993ced5548 in address_space_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/physmem.c:2963:18
    #14 0x55993a6ab83b in qemu_writel /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1072:5
    #15 0x55993a6a9cbe in dispatch_mmio_write /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1165:28
    #16 0x55993deca97f in videzzo_dispatch_event /root/videzzo/videzzo.c:1115:5
    #17 0x55993dec1cfb in __videzzo_execute_one_input /root/videzzo/videzzo.c:265:9
    #18 0x55993dec1bd0 in videzzo_execute_one_input /root/videzzo/videzzo.c:306:9
    #19 0x55993a6b287c in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1440:12
    #20 0x55993decf262 in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1884:18
    #21 0x55993a59873d in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:589:17
    #22 0x55993a57b4c4 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #23 0x55993a58643e in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:882:19
    #24 0x55993a572a46 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #25 0x7f4b42ce0082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #26 0x55993a572a9d in _start (/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci+0x2656a9d)

0x60d000006090 is located 112 bytes inside of 136-byte region [0x60d000006020,0x60d0000060a8)
freed by thread T0 here:
    #0 0x55993a665a27 in __interceptor_free /root/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:127:3
    #1 0x55993bb16c1e in ohci_service_iso_td /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:730:9
    #2 0x55993bb0b8b1 in ohci_service_ed_list /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1125:21
    #3 0x55993bafe689 in ohci_frame_boundary /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1191:9
    #4 0x55993dc7a8ae in timerlist_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:576:9
    #5 0x55993dc7abdc in qemu_clock_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:590:12
    #6 0x55993cf0d0d4 in qtest_clock_warp /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:358:9
    #7 0x55993cf0bfa6 in qtest_process_command /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:751:9
    #8 0x55993ceff61d in qtest_process_inbuf /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:796:9
    #9 0x55993ceff33f in qtest_server_inproc_recv /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:927:9
    #10 0x55993d865055 in send_wrapper /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:1386:5
    #11 0x55993d85f311 in qtest_sendf /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:453:5
    #12 0x55993d85f4d5 in qtest_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:810:5
    #13 0x55993a6ae2c1 in dispatch_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1207:5
    #14 0x55993deca97f in videzzo_dispatch_event /root/videzzo/videzzo.c:1115:5
    #15 0x55993dec872c in dispatch_group_event /root/videzzo/videzzo.c:1010:9
    #16 0x55993deca97f in videzzo_dispatch_event /root/videzzo/videzzo.c:1115:5
    #17 0x55993dec1cfb in __videzzo_execute_one_input /root/videzzo/videzzo.c:265:9
    #18 0x55993dec1bd0 in videzzo_execute_one_input /root/videzzo/videzzo.c:306:9
    #19 0x55993a6b287c in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1440:12
    #20 0x55993decf262 in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1884:18
    #21 0x55993a59873d in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:589:17
    #22 0x55993a57b4c4 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #23 0x55993a58643e in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:882:19
    #24 0x55993a572a46 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #25 0x7f4b42ce0082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16

previously allocated by thread T0 here:
    #0 0x55993a665ed7 in __interceptor_calloc /root/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:154:3
    #1 0x7f4b43f97ef0 in g_malloc0 (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x57ef0)
    #2 0x55993bb0b8b1 in ohci_service_ed_list /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1125:21
    #3 0x55993bafe689 in ohci_frame_boundary /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1191:9
    #4 0x55993dc7a8ae in timerlist_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:576:9
    #5 0x55993dc7abdc in qemu_clock_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:590:12
    #6 0x55993cf0d0d4 in qtest_clock_warp /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:358:9
    #7 0x55993cf0bfa6 in qtest_process_command /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:751:9
    #8 0x55993ceff61d in qtest_process_inbuf /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:796:9
    #9 0x55993ceff33f in qtest_server_inproc_recv /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:927:9
    #10 0x55993d865055 in send_wrapper /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:1386:5
    #11 0x55993d85f311 in qtest_sendf /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:453:5
    #12 0x55993d85f4d5 in qtest_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:810:5
    #13 0x55993a6ae2c1 in dispatch_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1207:5
    #14 0x55993deca97f in videzzo_dispatch_event /root/videzzo/videzzo.c:1115:5
    #15 0x55993dec872c in dispatch_group_event /root/videzzo/videzzo.c:1010:9
    #16 0x55993deca97f in videzzo_dispatch_event /root/videzzo/videzzo.c:1115:5
    #17 0x55993dec1cfb in __videzzo_execute_one_input /root/videzzo/videzzo.c:265:9
    #18 0x55993dec1bd0 in videzzo_execute_one_input /root/videzzo/videzzo.c:306:9
    #19 0x55993a6b287c in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1440:12
    #20 0x55993decf262 in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1884:18
    #21 0x55993a59873d in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:589:17
    #22 0x55993a57b4c4 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #23 0x55993a58643e in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:882:19
    #24 0x55993a572a46 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #25 0x7f4b42ce0082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16

SUMMARY: AddressSanitizer: heap-use-after-free /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/core.c:522:5 in usb_cancel_packet
Shadow bytes around the buggy address:
  0x0c1a7fff8bc0: fd fd fd fd fd fd fd fa fa fa fa fa fa fa fa fa
  0x0c1a7fff8bd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c1a7fff8be0: 00 fa fa fa fa fa fa fa fa fa fd fd fd fd fd fd
  0x0c1a7fff8bf0: fd fd fd fd fd fd fd fd fd fd fd fa fa fa fa fa
  0x0c1a7fff8c00: fa fa fa fa fd fd fd fd fd fd fd fd fd fd fd fd
=>0x0c1a7fff8c10: fd fd[fd]fd fd fa fa fa fa fa fa fa fa fa fa fa
  0x0c1a7fff8c20: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c1a7fff8c30: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c1a7fff8c40: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c1a7fff8c50: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c1a7fff8c60: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==14383==ABORTING
MS: 0 ; base unit: 0000000000000000000000000000000000000000
```

### Reproducer steps

Step 1: download the prepared rootfs and the image.

https://drive.google.com/file/d/1-tEjnRF6suKsNCBcHxYi9aOyv-docj_J/view?usp=sharing
https://drive.google.com/file/d/18BE7zk1_-yBSyLJDuDlIwlZySbUZahTR/view?usp=sharing

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
`ohci-02`.


## Contact

Let us know if I need to provide more information.
