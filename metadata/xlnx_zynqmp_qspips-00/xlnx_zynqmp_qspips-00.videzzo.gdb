DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-zynqmp-qspips \
    -max_len=10000000 -detect_leaks=0 \
    crash-66c132a47f4d360be45af57826d838c0793a2bf7.minimized
