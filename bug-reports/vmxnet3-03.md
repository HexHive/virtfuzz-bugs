# Out of memory net_tx_pkt_init()

# Allocator is trying to allocate 0xffffffff0 bytes in net_tx_pkt_init

[1](https://lists.gnu.org/archive/html/qemu-devel/2020-08/msg00156.html)

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type

i386, vmxnet3, net

### Bug Type: Out of Memory

### Existing bug reports

https://bugs.launchpad.net/qemu/+bug/1890152
https://lists.gnu.org/archive/html/qemu-devel/2020-08/msg00156.html
https://bugs.launchpad.net/qemu/+bug/1913873

## Existing patches

https://gitlab.com/qemu-project/qemu/-/commit/d05dcd94aee88728facafb993c7280547eb4d645

## Contact

Let us know if I need to provide more information.
