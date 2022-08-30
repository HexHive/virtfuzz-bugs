tag: arch: i386
tag: type: OOB write

# Out-of-bounds write in ati_2d_blt because if either of s->regs.[src|dst]_[xy] is
zero

Found by Pan and fixed [here](https://github.com/qemu/qemu/commit/ca1f9cbfdce4d63b10d57de80fef89a89d92a540?diff=unified)

QEMU 5.1.0

## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Reproducer steps


## Contact

Let me know if I need to provide more information.
