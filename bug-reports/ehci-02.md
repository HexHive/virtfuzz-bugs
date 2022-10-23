# Assertion failure in address_space_unmap() through ehci_execute_complete()

# Assertion failure in address_space_unmap through ehci_execute_complete

Similar issues are in the following.
+ [hw/ide/ahci: Do not dma_memory_unmap(NULL)](https://github.com/qemu/qemu/commit/1d1c4bdb736688b20d864831b90c07dc59c7b10c)
+ [Assertion failure in address_space_unmap through virtio-blk](https://bugs.launchpad.net/qemu/+bug/1890360)
+ (hw: xhci: check return value of 'usb_packet_map')[https://lists.nongnu.org/archive/html/qemu-devel/2020-08/msg08050.html]

This bug was found in QEMU 5.1.0 but fixed by
[2fdb42d840400d58f2e706ecca82c142b97bcbd6](https://github.com/qemu/qemu/commit/2fdb42d840400d58f2e706ecca82c142b97bcbd6).

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type
i386, ehci, usb

### Bug Type: Assertion Failure

### Existing bug reports

## Existing patcheshttps://github.com/qemu/qemu/commit/2fdb42d840400d58f2e706ecca82c142b97bcbd6## Contact

Let us know if I need to provide more information.
