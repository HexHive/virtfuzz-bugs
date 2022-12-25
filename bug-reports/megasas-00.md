# Assertion failure in scsi_dma_complete()

# Assertion `r->req.aiocb != NULL' failed in scsi_dma_complete

Reported [here](https://bugs.launchpad.net/qemu/+bug/1878263)
and fixed [here](https://github.com/qemu/qemu/commit/4773a5f35b0d83674f92816a226a594b03bbcf60)
and [here](https://github.com/qemu/qemu/commit/5ecfbae201d68a2f13df233260c77b0a25d7cd35)

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type

i386, megasas, storage

### Bug Type: Assertion Failure

### Existing bug reports


## Contact

Let us know if I need to provide more information.
