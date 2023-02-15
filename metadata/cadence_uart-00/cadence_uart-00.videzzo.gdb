DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-aarch64-target-videzzo-fuzz-cadence-uart \
    -max_len=10000000 -detect_leaks=0 \
    ./poc-qemu-videzzo-aarch64-target-videzzo-fuzz-cadence-uart-crash-cef41ca061384b94899472d8e2e6b5a86b62d259.minimized
