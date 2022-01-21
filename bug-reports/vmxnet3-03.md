tag: arch: i386
tag: type: OOM

# Allocator is trying to allocate 0xffffffff0 bytes in net_tx_pkt_init

[1](https://lists.gnu.org/archive/html/qemu-devel/2020-08/msg00156.html)
## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Reproducer steps

./qemu-fuzz-i386 --fuzz-target=stateful-fuzz-vmxnet3 crash-8e383bc213a0d9f5232b5e63eabe89b4ecdf4f4f
## Contact

Let me know if I need to provide more information.
