# Assertion failure in net_tx_pkt_reset()

# void net_tx_pkt_reset(struct NetTxPkt *): Assertion `pkt->raw' failed

[1](https://gitlab.com/qemu-project/qemu/-/commit/283f0a05e24a5e5fab783)
[2](https://bugs.launchpad.net/qemu/+bug/1890157)
## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type

i386, vmxnet3, net

### Bug Type: Assertion Failure

### Existing bug reports

https://bugs.launchpad.net/qemu/+bug/1890157

## Existing patches

https://gitlab.com/qemu-project/qemu/-/commit/283f0a05e24a5e5fab783

## Contact

Let us know if I need to provide more information.
