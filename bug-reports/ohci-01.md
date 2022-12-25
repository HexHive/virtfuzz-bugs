# Abort in ohci_frame_boundary()

I managed to trigger an abort in ohci_frame_boundary and make QEMU dos.

``` c
static void ohci_frame_boundary(void *opaque)
{
    // ...
    if (ohci->done_count == 0 && !(ohci->intr_status & OHCI_INTR_WD)) {
        if (!ohci->done)
            abort();
```

This was reported in https://bugs.launchpad.net/qemu/+bug/1911216/,
https://lists.gnu.org/archive/html/qemu-devel/2021-06/msg03613.html, and
https://gitlab.com/qemu-project/qemu/-/issues/545. 

This crash is triggered based on three assumptions.

Suppose that a user with root priviledge is an attacker,

1) the attacker can craft ED and put the attached TD at 0x0 (guest phys)
2) ohci can read/write data from/to 0x0 (guest phys)
3) the attacker can modify the guest phys from 0 to sizeof(ohci_iso_td)

Potenial fixes are
1) drop ohci_service_td when ed->head & OHCI_DPTR_MASK is 0
2) drop ohci_service_iso_td when ed->head & OHCI_DPTR_MASK is 0

## Some background about acca, ED and TD.

I double checked the OHCI spec
[here](https://composter.com.ua/documents/OHCI_Specification_Rev.1.0a.pdf).

+ Page 7: HCCA is the second communication channel. The Host Controller is
the master for all communication on this channel. The HCCA contains the head
pointers to the interrupt Endpoint Descriptor lists, the head pointer to the
done queue, and status information associated with startof-frame processing.

+ Page 8: Endpoint Descriptors are linked in a list.  A queue of Transfer
Descriptors is linked to the Endpoint Descriptor for the specific endpoint.


``` txt

                ┌──┐  ┌──┐  ┌──┐
 hcca.intr[1]──►│ED├─►│ED├─►│ED│
                └─┬┘  └─┬┘  └─┬┘
                  │     │     │
                  ▼     ▼     ▼
                ┌──┐  ┌──┐  ┌──┐
                │TD│  │TD│  │TD│
                └─┬┘  └──┘  └──┘
                  │
                  ▼
                ┌──┐
                │TD│
                └──┘
```

## Crash analysis

a) set ohci->ctl and enable OHCI_CTL_PLE

    MMIO_WRITE, addr=0xe0000004, size=0x4, valu=0x1fd0298e

    Note that 0x1fd02983 is derived from our fuzzer

b) sleep, invoke ohci_frame_boundary and increase ohci->frame by 1

    In this step, we make hcca all zeros. ohci_service_ed_list will immediatly
    return. ohci->frame_number will be increased by 1.

``` c
static void ohci_frame_boundary(void *opaque)
{
    // ...
    if (ohci_read_hcca(ohci, ohci->hcca, &hcca)) { // 1) controllable
    }

    if (ohci->ctl & OHCI_CTL_PLE) {                // 2) ohci->ctl, controllable
        n = ohci->frame_number & 0x1f;
        ohci_service_ed_list(ohci, le32_to_cpu(hcca.intr[n]));
                                                   // 3) hcca.intr controllable
                                                   // due to 1)
    }
    // ...
    ohci->frame_number = (ohci->frame_number + 1) & 0xffff;
    // ...
```


c) fill hcca and make sure hcca.intr[1] (ED) is avaiable as ohci->frame_number is 1

    hcca = { intr = {0x0, 0x101000, 0x0 <repeats 30 times>},
             frame = 0x0, pad = 0x0, done = 0x0 }
    0x0:
        iso_td0 = { 0 }
    0x101000: 
        ed0 = hcca->intr[1] =
        { flags = 0x0, tail = 0x0, head = 0x0, next = 0x129000 }
    0x129000: 
        ed1 = ed0->next =
        { flags = 0x25be8080, tail = 0x12b000, head = 0x0, next = 0x0 }

d) sleep, invoke ohci_frame_boundary again

    In this step, we enforce the control flow to ohci_service_iso_td. Here, as
    we can control ed, then `addr = ed->head & OHCI_DPTR_MASK (= 0)`. As we
    can control the guest physical memory from 0 to sizeof(ohci_iso_td), we
    can make sure the control flow to `ohci->done = addr (= 0)`.

``` c
static int ohci_service_ed_list(OHCIState *ohci, uint32_t head)
{
    // ...
    for (cur = head; cur && link_cnt++ < ED_LINK_LIMIT; cur = next_ed) {
        if (ohci_read_ed(ohci, cur, &ed)) {        // 4)  controllable due to 3
            // ...
        }

        next_ed = ed.next & OHCI_DPTR_MASK;

        // ...
        while ((ed.head & OHCI_DPTR_MASK) != ed.tail) {
            // ...
            if ((ed.flags & OHCI_ED_F) == 0) {     // 5) controllable due to 4
                // ...
            } else {
                if (ohci_service_iso_td(ohci, &ed)) {
                                                   // goes here, 
                                                   // 6) controllable due to 4
                    break;
                }
            }
        }

static int ohci_service_iso_td(OHCIState *ohci, struct ohci_ed *ed)
{
    // ...
    addr = ed->head & OHCI_DPTR_MASK;              // 0, 
                                                   // 7) controllable due to 6
    if (ohci_read_iso_td(ohci, addr, &iso_td)) {   // 8) controllable due to 7
        // ...

    starting_frame = OHCI_BM(iso_td.flags, TD_SF); // 0, 
                                                   // 9) controllable due to 8
    frame_count = OHCI_BM(iso_td.flags, TD_FC);    // 0,
                                                   // 10) controllable due to 8
    relative_frame_number = USUB(ohci->frame_number, starting_frame);

    if (relative_frame_number < 0) {
        return 1;
    } else if (relative_frame_number > frame_count) {
        // ...
        ohci->done = addr;                         // ohci->done = addr = 0
        // ...
        if (ohci_put_iso_td(ohci, addr, &iso_td)) {// iso_td.flags+TD_CC
        // ...
    }
```

e) ohci_service_iso_td returns, then ohci_service_ed_list returns,
ohci_frame_boundary will then abort due to ohci->done is NULL.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 7.0.50, c669f22f1a47897e8d1d595d6b8a59a572f9158c, Ubuntu 20.04

### VM architecture, device, device type

i386, ohci, usb

### Bug Type: Abort

### Stack traces, crash details

```
root@933c2b01a079:~/videzzo/videzzo_qemu/out-san# DEFAULT_INPUT_MAXSIZE=10000000 /root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci  -max_len=10000000 /root/videzzo/videzzo_qemu/out-san/poc-qemu-videzzo-i386-target-videzzo-fuzz-ohci-crash-9a5bf80e15f7ecfe3f8c918b3b5cb629d96a5f57.minimized
==133258==WARNING: ASan doesn't fully support makecontext/swapcontext functions and may produce false positives in some cases!
INFO: found LLVMFuzzerCustomMutator (0x558a7525a7a0). Disabling -len_control by default.
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 4034389130
INFO: Loaded 1 modules   (423101 inline 8-bit counters): 423101 [0x558a778e0000, 0x558a779474bd), 
INFO: Loaded 1 PC tables (423101 PCs): 423101 [0x558a7726aaf0,0x558a778df6c0), 
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
Running: /root/videzzo/videzzo_qemu/out-san/poc-qemu-videzzo-i386-target-videzzo-fuzz-ohci-crash-9a5bf80e15f7ecfe3f8c918b3b5cb629d96a5f57.minimized
==133258== ERROR: libFuzzer: deadly signal
    #0 0x558a719fb74e in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86:3
    #1 0x558a7194a3c1 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:38
    #2 0x558a71923c06 in fuzzer::Fuzzer::CrashCallback() (.part.0) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:235:18
    #3 0x558a71923cd2 in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:207:1
    #4 0x558a71923cd2 in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:206:19
    #5 0x7feb96da541f  (/lib/x86_64-linux-gnu/libpthread.so.0+0x1441f)
    #6 0x7feb96bb700a in __libc_signal_restore_set /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/internal-signals.h:86:3
    #7 0x7feb96bb700a in raise /build/glibc-SzIz7B/glibc-2.31/signal/../sysdeps/unix/sysv/linux/raise.c:48:3
    #8 0x7feb96b96858 in abort /build/glibc-SzIz7B/glibc-2.31/stdlib/abort.c:79:7
    #9 0x558a71a2bc9a in __wrap_abort /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/less_crashes_wrappers.c:24:12
    #10 0x558a72e8bbff in ohci_frame_boundary /root/videzzo/videzzo_qemu/qemu/build-san-6/../hw/usb/hcd-ohci.c:1205:13
    #11 0x558a7500621e in timerlist_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:576:9
    #12 0x558a7500654c in qemu_clock_run_timers /root/videzzo/videzzo_qemu/qemu/build-san-6/../util/qemu-timer.c:590:12
    #13 0x558a74298a44 in qtest_clock_warp /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:358:9
    #14 0x558a74297916 in qtest_process_command /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:751:9
    #15 0x558a7428af8d in qtest_process_inbuf /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:796:9
    #16 0x558a7428acaf in qtest_server_inproc_recv /root/videzzo/videzzo_qemu/qemu/build-san-6/../softmmu/qtest.c:927:9
    #17 0x558a74bf09c5 in send_wrapper /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:1386:5
    #18 0x558a74beac81 in qtest_sendf /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:453:5
    #19 0x558a74beae45 in qtest_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/libqtest.c:810:5
    #20 0x558a71a3a2c1 in dispatch_clock_step /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1202:5
    #21 0x558a7525615f in videzzo_dispatch_event /root/videzzo/videzzo.c:1118:5
    #22 0x558a7524d43b in __videzzo_execute_one_input /root/videzzo/videzzo.c:256:9
    #23 0x558a7524d310 in videzzo_execute_one_input /root/videzzo/videzzo.c:297:9
    #24 0x558a71a3e87c in videzzo_qemu /root/videzzo/videzzo_qemu/qemu/build-san-6/../tests/qtest/videzzo/videzzo_qemu.c:1435:12
    #25 0x558a7525aa42 in LLVMFuzzerTestOneInput /root/videzzo/videzzo.c:1883:18
    #26 0x558a7192473d in fuzzer::Fuzzer::ExecuteCallback(unsigned char*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:589:17
    #27 0x558a719074c4 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323:21
    #28 0x558a7191243e in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:882:19
    #29 0x558a718fea46 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:30
    #30 0x7feb96b98082 in __libc_start_main /build/glibc-SzIz7B/glibc-2.31/csu/../csu/libc-start.c:308:16
    #31 0x558a718fea9d in _start (/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci+0x2655a9d)

NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 0 ; base unit: 0000000000000000000000000000000000000000
0x7,0x1,0xc,0x10,0x10,0x10,0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x0,0x0,0x90,0x12,0x0,0x7,0x1,0x0,0x90,0x12,0x10,0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x0,0x80,0x80,0xbe,0x25,0x7,0x1,0x4,0x90,0x12,0x10,0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x0,0x0,0xb0,0x12,0x0,0x1,0x9,0x4,0x0,0x0,0xe0,0x0,0x0,0x0,0x0,0x2,0x0,0x0,0x0,0x8e,0x29,0xd0,0x1f,0x0,0x0,0x0,0x0,0x4,0x2,0x8d,0x3d,0xc,0x0,0x0,0x0,0x0,0x0,0x4,0x2,0x16,0x3c,0x5,0x0,0x0,0x0,0x0,0x0,0x7,0x1,0x4,0x0,0x0,0x10,0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x0,0x0,0x10,0x10,0x0,0x4,0x2,0x80,0xa4,0xd,0x0,0x0,0x0,0x0,0x0,
\x07\x01\x0c\x10\x10\x10\x00\x00\x00\x00\x04\x00\x00\x00\x00\x90\x12\x00\x07\x01\x00\x90\x12\x10\x00\x00\x00\x00\x04\x00\x00\x00\x80\x80\xbe%\x07\x01\x04\x90\x12\x10\x00\x00\x00\x00\x04\x00\x00\x00\x00\xb0\x12\x00\x01\x09\x04\x00\x00\xe0\x00\x00\x00\x00\x02\x00\x00\x00\x8e)\xd0\x1f\x00\x00\x00\x00\x04\x02\x8d=\x0c\x00\x00\x00\x00\x00\x04\x02\x16<\x05\x00\x00\x00\x00\x00\x07\x01\x04\x00\x00\x10\x00\x00\x00\x00\x04\x00\x00\x00\x00\x10\x10\x00\x04\x02\x80\xa4\x0d\x00\x00\x00\x00\x00
```

### Reproducer steps

Step 1: download the prepared rootfs and the image.

https://drive.google.com/file/d/15UrSybIik_lgNNX357KRy9NYYfqjNio7/view?usp=sharing
https://drive.google.com/file/d/1ZyiQdl98y-pKS1awrDrBZlu4829kWHJ5/view?usp=sharing

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
`ohci-01`.


## Existing patches

https://github.com/qemu/qemu/commit/d8c2e6f2f6d29ccb766197181eb1c65c1d46b3a4

## Contact

Let us know if I need to provide more information.
