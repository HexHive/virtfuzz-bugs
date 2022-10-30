DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-zynqmp-can \
    -max_len=10000000 -detect_leaks=0 \
    poc-qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-zynqmp-can-crash-8c83f08fb7643e6eb55af43e76de522c6f5fcef2.minimized.minimized
