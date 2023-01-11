DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-zynqmp-qspips \
    -max_len=10000000 -detect_leaks=0 \
    poc-qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-zynqmp-qspips-crash-a2dce6d03fde8dc9cb50fb0c8708f307ca93d7c2.minimized
