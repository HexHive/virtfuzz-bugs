# Assertion failure in fifo8_push()

This is intesting as if there is no aasertion there, this will become a out of bound write.

Somehow the number of bytes is not aligned.

gef➤  p s->rx_fifo->fifo.num
$25 = 0x39c

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 7.0.94, 9a99f964b152f8095949bbddca7841744ad418da, Ubuntu 20.04

### VM architecture, device, device type

aarch64, xlnx_zynqmp_can, net

### Bug Type: Assertion Failure

## Contact

Let us know if I need to provide more information.
