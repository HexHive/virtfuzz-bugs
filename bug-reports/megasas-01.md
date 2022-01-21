tag: arch: i386
tag: type: ASS failure

# Assertion `child->perm & BLK_PERM_WRITE' failed in bdrv_co_write_req_prepare

It is reported [here](https://www.mail-archive.com/qemu-devel@nongnu.org/msg782182.html).



## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Reproducer steps


## Contact

Let me know if I need to provide more information.
