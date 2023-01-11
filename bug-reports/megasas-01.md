# Assertion failure in bdrv_co_write_req_prepare()

# Assertion `child->perm & BLK_PERM_WRITE' failed in bdrv_co_write_req_prepare

It is reported [here](https://www.mail-archive.com/qemu-devel@nongnu.org/msg782182.html).



## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type

i386, megasas, storage

### Bug Type: Assertaion Failure

### Existing bug reports

https://www.mail-archive.com/qemu-devel@nongnu.org/msg782182.html
https://bugs.launchpad.net/qemu/+bug/1906693

## Existing patches

https://gitlab.com/qemu-project/qemu/-/commit/86b1cf322789b79c8a

## Contact

Let us know if I need to provide more information.
