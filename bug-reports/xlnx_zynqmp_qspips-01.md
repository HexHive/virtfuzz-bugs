# Shift exponent is too large in xilinx_spips_read()

This is not harmful.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host

qemu, 7.2.50, 222059a0fccf4af3be776fe35a5ea2d6a68f9a0b, Ubuntu 20.04

### VM architecture, device, device type

aarch64, xlnx_zynqmp_qspips, bus

### Bug Type: Large Shift

### Stack traces, crash details

```
DEFAULT_INPUT_MAXSIZE=10000000 /root/videzzo/videzzo_qemu/out-san/qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-zynqmp-qspips  -max_len=10000000 -detect_leaks=0 poc-qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-zynqmp-qspips-crash-a0a2370456c328eb42053d5f521af526210b0696
```

## Contact

Let us know if I need to provide more information.
