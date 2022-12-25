# Global buffer overflow in hdaMmioWrite()

In hdaMmioWrite(), when LOG_ENABLED is defined, idxRegMem can be 0xffffffff if
hdaRegLookup() returns -1.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
vbox, 7.0.0, r95063, Ubuntu 20.04

### VM architecture, device, device type
i386, intel-hda, audio

### Bug Type: Global Buffer Overflow

## Contact

Let us know if I need to provide more information.
