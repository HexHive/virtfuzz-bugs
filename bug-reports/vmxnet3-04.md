tag: arch: i386
tag: type: ASS failure

# void net_tx_pkt_reset(struct NetTxPkt *): Assertion `pkt->raw' failed

[1](https://gitlab.com/qemu-project/qemu/-/commit/283f0a05e24a5e5fab783)
[2](https://bugs.launchpad.net/qemu/+bug/1890157)
## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Reproducer steps

bash 32.sh
## Contact

Let me know if I need to provide more information.
