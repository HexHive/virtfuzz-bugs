# Assertion failure in usb_msd_transfer_data()

When I fuzzed ohci with dev-storage device, I found the assertion (s->mode ==
USB_MSDM_DATAOUT) == (req->cmd.mode == SCSI_XFER_TO_DEV) failed in
usb_msd_transfer_data(). As we can control both s->mode and req->cmd.mode, we
somehow trigger a logic conflict. In our case, s->mode is USB_MSDM_DATAOUT,
while req->cmd.mode is SCSI_XFER_FROM_DEV. We can trigger this new bug (AFAIK)
    via crafted OHCI ED and TD along with incompatible SCSI commands.

## crash analysis

1 First, I want to leave an impression on the related control flow and date
flow.

1.1 key control flow

We must drive to usb_msd_transfer_data().

``` text
ohci_service_ed_list
ohci_service_td
usb_handle_packet
usb_process_one
    usb_device_handle_data
        usb_msd_handle_data
            scsi_req_enqueue
                scsi_target_send_command
            scsi_req_continue
                scsi_target_read_data
                    scsi_req_data
                        usb_msd_transfer_data // boom!
```

Note that scsi_req_enqueue() must return a non-zero value and thus
scsi_req_continue() can be invoked.


``` c
static void usb_msd_handle_data(USBDevice *dev, USBPacket *p)
{
    // ...
    switch (p->pid) {
    case USB_TOKEN_OUT:
        // ...
        switch (s->mode) {
            case USB_MSDM_CBW:
                // ...
                len = scsi_req_enqueue(s->req);
                if (len) {
                    scsi_req_continue(s->req);
                }
```
                
1.2 data flow (lines starting with >)

1.2.1 A simplified version:

``` text
In ohci_service_td,
> a) memcpy: CONTROLLED DMA => td
> b) memcpy: td->cbp => ohci->usb_buf
> c) let p=&ohci->usb_packet
> d) reference: ohci->usb_buf => p->iov
> e) memcpy: p->iov => cwb
> f) s->mode = USB_MSDM_DATAOUT
> g) scsi_req_parse_cdb(cwb.cmd) => req->cmd  <------------ [5]
> h) s->mode and req->cmd.mod are controlled due to a-e) and g)
```

This means we can control s->mode and req->cmd.mod to trigger the assertion.

``` c
void usb_msd_transfer_data(SCSIRequest *req, uint32_t len)
{
    // ...
    assert((s->mode == USB_MSDM_DATAOUT) == (req->cmd.mode == SCSI_XFER_TO_DEV));
    // ...
```

Note that req->cmd.mod is set at [5].

1.2.2 A detailed version:

``` text
|ohci_service_td
    |ohci_read_td(ohci=ohci, addr=addr, td=&td)
    > a) memcpy: CONTROLLER DMA => td
    |ohci_copy_td(ohci=ohci, td=&td, buf=ohci->usb_buf, len=pktlen, dir=DMA_DIRECTION_TO_DEVICE)
        |ptr = td->cbp
        |dma_memory_rw(ohci->as, ptr + ohci->localmem_base, buf, n, dir, MEMTXATTRS_UNSPECIFIED)
        |dma_memory_rw(ohci->as, ptr + ohci->localmem_base, buf, len - n, dir, MEMTXATTRS_UNSPECIFIED)
    > b) memcpy: td->cbp => ohci->usb_buf
    > c) let p=&ohci->usb_packet
    |usb_packet_addbuf(p=&ohci->usb_packet, ptr=ohci->usb_buf, len=pktlen);
    > d) ref: ohci->usb_buf => p->iov
    |usb_handle_packet(dev=dev, p=&ohci->usb_packet)
    |usb_process_one(p=p)
        |usb_device_handle_data(dev=dev, p=p)
            |usb_msd_handle_data(dev=p, p=p)
                |usb_packet_copy(p=p, ptr=&cbw, bytes=31);
                    |iov=p->combined ? &p->combined->iov : &p->iov;
                    |iov_to_buf(iov=iov->iov, iov_cnt=iov->niov, offset=p->actual_length, buf=ptr, bytes=bytes);
                        |iov_from_buf_full(iov=iov, iov_cnt=iov_cnt, offset=offset, buf=buf, bytes=bytes);
                            |memcpy(buf + done, iov[i].iov_base + offset, len);
                > e) memcpy: p->iov => cwb
                if (s->data_len == 0) { // important
                    s->mode = USB_MSDM_CSW;
                } else if (cbw.flags & 0x80) {
                    s->mode = USB_MSDM_DATAIN;
                } else {
                    s->mode = USB_MSDM_DATAOUT;
                }
                > f) s->mode = USB_MSDM_DATAOUT
                |s->req = scsi_req_new(d=scsi_dev, tag=tag, len=cbw.lun, buf=cbw.cmd, hba_private=NULL)
                    |ret = scsi_req_parse_cdb(dev=d, cmd=&cmd, buf=buf);
                        |cmd->len = scsi_cdb_length(buf);
                        |memcpy(cmd->buf, buf, cmd->len);
                        |scsi_cmd_xfer_mode(cmd); <------------ [5]
                        |cmd->lba = scsi_cmd_lba(cmd);
                    |req->cmd = cmd
                > g) scsi_req_parse_cdb(cwb.cmd) => req->cmd
                |scsi_req_continue(req=s->req)
                    |req->ops->read_data(req=req) // scsi_target_read_data(req)
                        |SCSITargetReq *r = DO_UPCAST(SCSITargetReq, req, req);
                        |n = r->len;
                        |scsi_req_data(req=&r->req, len=n);
                            |req->bus->info->transfer_data(req=req, len=len); //usb_msd_transfer_data(req, len)
                                | req->cmd.mod = SCSI_XFER_FROM_DEV (1) but SCSI_XFER_TO_DEV (2) is required
                > h) req->cmd.mod is controlled due to a) to f)
```

2 How can we trigger the assertion failure?

The idea to trigger this assertion failure is to craft ED and TD to invoke
usb_msd_transfer_data() and propagate controlled data to s->mode and
req->cmd.mod.

2.1 Craft ED and TD

I derive the following ed, ed, and a buffer from our fuzzer. 

```
ed.flags=0xfde70900
ed.tail=<tail td> 
ed.head=<td>
ed.next=<next ed>

td.flags=0xdedc9979
td.cbp=<buf_start>
td.next=<next_td>
td.be=<buf_end>

data between td.cbp and td.be (let's mark it cbw)
55 53 42 43 6a 92 44 08 64 00 00 00 66 ef 08 03    USBCj.D.d...f...
b9 bf 70 55 b9 bf 70 55 b9 bf 70 55 b9 bf 70       ..pU..pU..pU..p
```

We have

```
cbw = {
  sig = 0x43425355,
  tag = 0x844926a,
  data_len = 0x64,
  flags = 0x66,
  lun = 0xef,
  cmd_len = 0x8,
  cmd = "03 b9 bf 70 55 b9 bf 70 55 b9 bf 70 55 b9 bf 70"
}

req->cmd = {
  buf = "03 b9 bf 70 55 b9"
  len = 0x6, // due to buf[0] >> 5 == 0, see scsi_cdb_length
  xfer = 0x55, // due to buf[0] >> 5 == 0, see scsi_cdb_xfer
  lba = 0x19bf70, // due to buf[0] >> 5 == 0, see scsi_cmd_lba
  mode = SCSI_XFER_FROM_DEV // due to buf[0], see scsi_cmd_xfer_mode
}
```

Constructing these data needs constraints along the control flow and the data
flow. I list part of these constraints I manually collected in the following.

``` c
#define OHCI_DPTR_MASK    0xfffffff0
#define OHCI_ED_K         (1<<14)
#define OHCI_ED_F         (1<<15)
#define OHCI_ED_H         1
#define OHCI_ED_D_SHIFT   11
#define OHCI_ED_D_MASK    (3<<OHCI_ED_D_SHIFT)
#define OHCI_ED_MPS_SHIFT 16
#define OHCI_ED_MPS_MASK  (0x7ff<<OHCI_ED_MPS_SHIFT)

#define OHCI_BM(val, field) \
  (((val) & OHCI_##field##_MASK) >> OHCI_##field##_SHIFT)

assert(ed.head != 0)
assert(((ed.head & OHCI_ED_H) || (ed.flags & OHCI_ED_K)) == 0)
assert((ed.head & OHCI_DPTR_MASK) != ed.tail) // the number of tds must be larger than 1
assert((ed.flags & OHCI_ED_F) == 0)
assert((ed->head & OHCI_DPTR_MASK) != ohci->async_td)
assert(OHCI_BM(ed->flags, ED_D) == 1)
assert(tb.cbp && td.be)
if assert((td.cbp & 0xfffff000) != (td.be & 0xfffff000))
    assert(((td.be & 0xfff) + 0x1001 - (td.cbp & 0xfff)) == 0x1f)
else
    assert(td.be - td.cbp + 1 == 0x1f)
assert(((ed->flags & OHCI_ED_MPS_MASK) >> OHCI_ED_MPS_SHIFT) > 0x1f)
assert(cbw.sig == 0x43425355)
```

2.2 Make sure the control flow go to usb_msd_transfer_data()

Recalling that scsi_req_enqueue() must return non-zero, we have to carefully
choose req->ops->send_command() [1]. We don't want scsi_unit_attention() [2] as
its always return 0 and we want scsi_target_send_command() [3].

``` c
int32_t scsi_req_enqueue(SCSIRequest *req)
{
    // ...
    rc = req->ops->send_command(req, req->cmd.buf); <------------------ [1]
    // ...
    return rc;
}

SCSIRequest *scsi_req_new(SCSIDevice *d, uint32_t tag, uint32_t lun,
                          uint8_t *buf, void *hba_private)
{
    // ...
    if ((d->unit_attention.key == UNIT_ATTENTION ||
        // ...
        ops = &reqops_unit_attention; <-------------------------------- [2]
    } else if (lun != d->lun ||
               buf[0] == REPORT_LUNS || <-------------------------------[4]
               (buf[0] == REQUEST_SENSE && d->sense_len)) {
        ops = &reqops_target_command; <-------------------------------- [3]
    } else {
        ops = NULL;
    }
    // ...
}
```

The key to choose scsi_target-send_command() [3] is to update
d->unit_attention.key (not to be UNIT_ATTENTION). Interestingly,
d->unit_attention.key goes to 0 at the end of scsi_unit_attention() [2].
Therefore, we want trigger scsi_req_new() two times. In the first time, we clear
d->unit_attention.key and in the second time, we assign &reqops_target_command
to ops.

Note that I omit some details how to invoke ohci_service_td(). This is done by
setting OHCI_CTL_PLE and crafting hcca.

2.3 scsi_target_send_command()

In scsi_req_enqueue(), scsi_target_send_command() is invoked and returns 8.

``` c
req->cmd = {
  buf = "03 b9 bf 70 55 b9"
  len = 0x6, xfer = 0x55, lba = 0x19bf70,
  mode = SCSI_XFER_FROM_DEV
}
```

Specifically, scsi_target_send_commands() accepts an SCSIRequest object and the
req->cmd.buf that is "03 b9 bf 70 55 b9". In the branch REQUEST_SENSE
(buf[0]==0x3), scsi_build_sense_buf() is invoked with req->cmd.xfer (0x55),
fixed_sense (0);

``` c
static int32_t scsi_target_send_command(SCSIRequest *req, uint8_t *buf)
{
    // ...
    switch (buf[0]) {
    // ...
    case REQUEST_SENSE:
        scsi_target_alloc_buf(&r->req, scsi_sense_len(req));
        if (req->lun != 0) {
            const struct SCSISense sense = SENSE_CODE(LUN_NOT_SUPPORTED);

            r->len = scsi_build_sense_buf(r->buf, req->cmd.xfer,
                                          sense, fixed_sense);
        } else {
        // ...
```

In scsi_build_sense_buf(), we will get 8 or 18 returned.

``` c
#define SCSI_SENSE_LEN         18
int scsi_build_sense_buf(uint8_t *out_buf, size_t size, SCSISense sense,
                         bool fixed_sense)
{
    int len;
    uint8_t buf[SCSI_SENSE_LEN] = { 0 };

    if (fixed_sense) {
        buf[0] = 0x70;
        buf[2] = sense.key;
        buf[7] = 10;
        buf[12] = sense.asc;
        buf[13] = sense.ascq;
        len = 18;
    } else {
        buf[0] = 0x72;
        buf[1] = sense.key;
        buf[2] = sense.asc;
        buf[3] = sense.ascq;
        len = 8;
    }
    len = MIN(len, size); <------------ [6] always 8
    memcpy(out_buf, buf, len);
    return len;
}
```

## Some thoughts of fixes

According to scsi_cmd_xfer_mode(), REQUEST_SENSE (0x3) will enforce cmd->mode to
SCSI_XFER_FROM_DEV, while dev-storage doesn't know and doesn't think so. We
maybe check it in the dev-storage in advance to avoid the assertion. However,
I'm not sure about this fix. I'd like to discuss more.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 7.0.50, 5288bee45fbd33203b61f8c76e41b15bb5913e6e, Ubuntu 20.04

### VM architecture, device, device type
i386, ohci, usb

### Bug Type: Assertion Failure

### Stack traces, crash details

```
root@37d14d202b64:~/videzzo/videzzo_qemu/out-san# DEFAULT_INPUT_MAXSIZE=10000000 /root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci  -max_len=10000000 poc-qemu-videzzo-i386-target-videzzo-fuzz-ohci-crash-8fdccd1d02357f8b8870163b21b32d9ebcc126b7
==591201==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x55c64422eb10). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1962413397
INFO: Loaded 1 modules   (422784 inline 8-bit counters): 422784 [0x55c6468b0000, 0x55c646917380), 
INFO: Loaded 1 PC tables (422784 PCs): 422784 [0x55c64623c100,0x55c6468af900), 
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
Running: poc-qemu-videzzo-i386-target-videzzo-fuzz-ohci-crash-8fdccd1d02357f8b8870163b21b32d9ebcc126b7
qemu-videzzo-i386-target-videzzo-fuzz-ohci: ../hw/usb/dev-storage.c:228: void usb_msd_transfer_data(SCSIRequest *, uint32_t): Assertion `(s->mode == USB_MSDM_DATAOUT) == (req->cmd.mode == SCSI_XFER_TO_DEV)' failed.
==591201== ERROR: libFuzzer: deadly signal
    #0 0x55c6409d974e in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86:3
    #1 0x55c6409283c1 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:38
    #2 0x55c640901c06 in fuzzer::Fuzzer::CrashCallback() (.part.0) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:235:18
    #3 0x55c640901cd2 in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207:1
    #4 0x55c640901cd2 in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:206:19
    #5 0x7f9bd6e9341f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f)
    #6 0x7f9bd6ca500a in __libc_signal_restore_set /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/internal-signals.h:86:3
    #7 0x7f9bd6ca500a in raise /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/raise.c:48:3
    #8 0x7f9bd6c84858 in abort /build/glibc-SzIz7B/glibc-2.31/stdlib/abort.c:79:7
    #9 0x7f9bd6c84728 in __assert_fail_base /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:92:3
    #10 0x7f9bd6c95fd5 in __assert_fail /build/glibc-SzIz7B/glibc-2.31/assert/assert.c:101:3
    #11 0x55c641fba0c0 in usb_msd_transfer_data /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/dev-storage.c:228:5
    #12 0x55c641a247d9 in scsi_req_data /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/scsi/scsi-bus.c:1413:9
    #13 0x55c641a36bf2 in scsi_target_read_data /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/scsi/scsi-bus.c:639:9
    #14 0x55c641a23010 in scsi_req_continue /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/scsi/scsi-bus.c:1395:9
    #15 0x55c641fc830b in usb_msd_handle_data /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/dev-storage.c:425:17
    #16 0x55c641da6a4b in usb_device_handle_data /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/bus.c:180:9
    #17 0x55c641dd729d in usb_process_one /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/core.c:406:9
    #18 0x55c641dd3312 in usb_handle_packet /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/core.c:438:9
    #19 0x55c641e7393c in ohci_service_td /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:959:9
    #20 0x55c641e70190 in ohci_service_ed_list /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1111:21
    #21 0x55c641e62fb9 in ohci_frame_boundary /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1181:9
    #22 0x55c643fdb43e in timerlist_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:576:9
    #23 0x55c643fdb76c in qemu_clock_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:590:12
    #24 0x55c64326e474 in qtest_clock_warp /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:358:9
    #25 0x55c64326d346 in qtest_process_command /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:751:9
    #26 0x55c6432609bd in qtest_process_inbuf /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:796:9
    #27 0x55c6432606df in qtest_server_inproc_recv /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:927:9
    #28 0x55c643bc5be5 in send_wrapper /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:1386:5
    #29 0x55c643bbfea1 in qtest_sendf /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:453:5
    #30 0x55c643bc0065 in qtest_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:810:5
    #31 0x55c640a182c1 in dispatch_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1185:5
    #32 0x55c64422abef in videzzo_dispatch_event /root/videzzo/videzzo.c:1116:5
    #33 0x55c6442287d4 in dispatch_group_event /root/videzzo/videzzo.c:1011:9
    #34 0x55c64422abef in videzzo_dispatch_event /root/videzzo/videzzo.c:1116:5
    #35 0x55c644221c73 in __videzzo_execute_one_input /root/videzzo/videzzo.c:256:9
    #36 0x55c644221ac0 in videzzo_execute_one_input /root/videzzo/videzzo.c:297:9
    #37 0x55c640a1c5cc in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1418:12
    #38 0x55c64422edb2 in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1913:18
    #39 0x55c64090273d in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:589:17
    #40 0x55c6408e54c4 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #41 0x55c6408f043e in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:882:19
    #42 0x55c6408dca46 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #43 0x7f9bd6c86082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #44 0x55c6408dca9d in _start (/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci+0x264fa9d)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000
```

### Reproducer steps

Step 1: download the prepared rootfs and the image.

https://drive.google.com/file/d/1qn0FlGBWSnE7L6X08f-6lMhDG--YKr6C/view?usp=sharing
https://drive.google.com/file/d/1Z6b2X00C7zXMoRrmyXi6Poas1OeCC4Ni/view?usp=sharing

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
`ohci-00`.


## Suggested fix

```
From 1b56f7c3fe6fb235ce6d1a98ec98e5660b1339d6 Mon Sep 17 00:00:00 2001
From: Qiang Liu <cyruscyliu@gmail.com>
Date: Thu, 25 Aug 2022 15:50:22 +0800
Subject: [PATCH] dev-storage: workaround to fix the assertion in
 usb_msd_transfer_data

---
 hw/usb/dev-storage.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/hw/usb/dev-storage.c b/hw/usb/dev-storage.c
index dca62d544f..99a0f6ea75 100644
--- a/hw/usb/dev-storage.c
+++ b/hw/usb/dev-storage.c
@@ -414,6 +414,11 @@ static void usb_msd_handle_data(USBDevice *dev, USBPacket *p)
             trace_usb_msd_cmd_submit(cbw.lun, tag, cbw.flags,
                                      cbw.cmd_len, s->data_len);
             assert(le32_to_cpu(s->csw.residue) == 0);
+            if (s->mode == USB_MSDM_DATAOUT && cbw.cmd[0] == 0x3 &&
+                    (s->req->cmd.mode != SCSI_XFER_TO_DEV)) {
+                error_report("usb-msd: Incompatible s->mode and s->req->cmd.mode");
+                goto fail;
+            }
             s->scsi_len = 0;
             s->req = scsi_req_new(scsi_dev, tag, cbw.lun, cbw.cmd, NULL);
             if (s->commandlog) {
-- 
2.25.1

```

## Contact

Let us know if I need to provide more information.
