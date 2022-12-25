# Out of bounds write in ati_2d_blt()

# Out-of-bounds write in ati_2d_blt because if either of s->regs.[src|dst]_[xy] is
zero

Found by Pan and fixed [here](https://github.com/qemu/qemu/commit/ca1f9cbfdce4d63b10d57de80fef89a89d92a540?diff=unified)

QEMU 5.1.0

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type

i386, ati, display

### Bug Type: Out-of-bounds Write

### Existing bug reports


## Existing patches

https://github.com/qemu/qemu/commit/ca1f9cbfdce4d63b10d57de80fef89a89d92a540?diff=unified

## Contact

Let us know if I need to provide more information.
