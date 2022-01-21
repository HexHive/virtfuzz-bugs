tag: arch: i386
tag: type: ASS failure

# Three hw_error() in vmxnet3_validate_queues (vmxnet3)

[1](https://bugs.launchpad.net/qemu/+bug/1890160)
## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Reproducer steps

./qemu-fuzz-i386 --fuzz-target=stateful-fuzz-vmxnet3 crash-eb61666b091595cce62b00139cc6d45e7470edbc 
## Contact

Let me know if I need to provide more information.
