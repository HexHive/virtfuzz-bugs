# Code should not be reached vmxnet3_io_bar1_write()

# Code should not be reached vmxnet3_io_bar1_write

Because this bug was reported
[here](https://gitlab.com/qemu-project/qemu/-/issues/309), I just provide our
reproducer. This bug can also be reproduced in the QEMU 6.0.50,
3e13d8e34b53d8f9a3421a816ccfbdc5fa874e98.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type

i386, vmxnet3, net

### Bug Type: Assertion Failure

### Existing bug reports

https://gitlab.com/qemu-project/qemu/-/issues/309

## Existing patches

https://gitlab.com/qemu-project/qemu/-/commit/f3e5a17593b972a9a6079ccf7677b4389d74d5a1

## Contact

Let us know if I need to provide more information.
