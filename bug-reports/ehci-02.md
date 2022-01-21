tag: arch: i386
tag: type: ASS failure

# Assertion failure in address_space_unmap through ehci_execute_complete

Similar issues are in the following.
+ [hw/ide/ahci: Do not dma_memory_unmap(NULL)](https://github.com/qemu/qemu/commit/1d1c4bdb736688b20d864831b90c07dc59c7b10c)
+ [Assertion failure in address_space_unmap through virtio-blk](https://bugs.launchpad.net/qemu/+bug/1890360)
+ (hw: xhci: check return value of 'usb_packet_map')[https://lists.nongnu.org/archive/html/qemu-devel/2020-08/msg08050.html]

This bug was found in QEMU 5.1.0 but fixed by
[2fdb42d840400d58f2e706ecca82c142b97bcbd6](https://github.com/qemu/qemu/commit/2fdb42d840400d58f2e706ecca82c142b97bcbd6).

## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Reproducer steps

../dd.sh --target=/root/qemu/build-coverage-5/qemu-fuzz-i386-target-stateful-fuzz-ehci --crash=./crash-adbde9c604a2acb954df8b7c500427246188957f --seeds=./ehci-1*

## Contact

Let me know if I need to provide more information.
