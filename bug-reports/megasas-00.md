tag: arch: i386
tag: type: ASS failure

# Assertion `r->req.aiocb != NULL' failed in scsi_dma_complete

Reported [here](https://bugs.launchpad.net/qemu/+bug/1878263)
and fixed [here](https://github.com/qemu/qemu/commit/4773a5f35b0d83674f92816a226a594b03bbcf60)
and [here](https://github.com/qemu/qemu/commit/5ecfbae201d68a2f13df233260c77b0a25d7cd35)

## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Reproducer steps

bash -x 38.sh
## Contact

Let me know if I need to provide more information.
