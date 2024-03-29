# Assertion failure in address_space_stw_le_cached()

An assertion failure is triggered in address_space_stw_le_cached() through
virtio-blk. This was reported in
https://gitlab.com/qemu-project/qemu/-/issues/781,
https://bugs.launchpad.net/qemu/+bug/1910941,
https://lists.gnu.org/archive/html/qemu-devel/2018-09/msg03947.html.

It's not difficult to trigger this bug.

Some necessary background.

address-space: IO
    000000000000c000-000000000000c07f (prio 1, i/o): virtio-pci

memory-region: system
    00000000febd2000-00000000febd2fff (prio 1, i/o): virtio-blk-pci-msix
      00000000febd2000-00000000febd201f (prio 0, i/o): msix-table
      00000000febd2800-00000000febd2807 (prio 0, i/o): msix-pba

    00000000fe004000-00000000fe007fff (prio 1, i/o): virtio-pci
      00000000fe004000-00000000fe004fff (prio 0, i/o): virtio-pci-common-virtio-blk
      00000000fe005000-00000000fe005fff (prio 0, i/o): virtio-pci-isr-virtio-blk
      00000000fe006000-00000000fe006fff (prio 0, i/o): virtio-pci-device-virtio-blk
      00000000fe007000-00000000fe007fff (prio 0, i/o): virtio-pci-notify-virtio-blk

breakpoints
    virtio_ioport_write     at ../hw/virtio/virtio-pci.c:299
    virtio_pci_common_write at ../hw/virtio/virtio-pci.c:1263
    virtio_pci_notify_write at ../hw/virtio/virtio-pci.c:1382

virtio-blk has one virtqueue

1 PIO_WRITE, 0xc008, 0x4, 0x7e83a579

This write will update the address vring.desc, vring.avail, and vring.used. The
vring.num is initialized to 0x100. Therefore, the memory layout is as below.

vring.desc  = val
vring.avail = val + 0x100 * sizeof(VRingDesc);
vring.used  = val.avail + offset(VRingAvail, ring[0x100])  

This write will also initialize region cache.

XXX

2 MMIO_WRITE, 0xe0004018, 0x1, 0x6e

This write will update the viring.num to 0x6e.

3 PIO_WRITE, 0xc004, 0x4, 0x2443a858

This write will set vdev->guest_features to 0x20002850.

0x20002850
     v
b'0010 0000 0000 0000 0010 1000 0110 0000
   ||
   |+-------------------------------------> VIRTIO_RING_F_EVENT_IDX true
   +--------------------------------------> VIRTIO_F_BAD_FEATURE    false

This write will also intialize region cache.

XXX

4 MMIO_WRITE, 0xe0004018, 0x1, 0xea

This write will update the viring.num to 0xea.

5 MMIO_WRITE, 0xe0007000, 0x4, 0x214c8698




## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 7.0.94, 9a99f964b152f8095949bbddca7841744ad418da, Ubuntu 20.04

### VM architecture, device, device type

i386, virtio-blk, storage

### Bug Type: Assertion failure

### Existing bug reports

https://gitlab.com/qemu-project/qemu/-/issues/781
https://bugs.launchpad.net/qemu/+bug/1910941
https://lists.gnu.org/archive/html/qemu-devel/2018-09/msg03947.html

## Contact

Let us know if I need to provide more information.
