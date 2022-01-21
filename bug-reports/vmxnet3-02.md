tag: arch: i386
tag: type: ASS failure

# Assertion `tx_queue_idx <= s->txq_num' failed

[1](https://www.mail-archive.com/qemu-devel@nongnu.org/msg824272.html)
[2](https://gitlab.com/qemu-project/qemu/-/commit/6a932c4ed8748b08c58c)
## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Reproducer steps

bash 35.sh
## Contact

Let me know if I need to provide more information.
