DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args ./qemu-videzzo-i386-target-videzzo-fuzz-ati \
    -max_len=10000000 -detect_leaks=0 \
    ./poc-qemu-videzzo-i386-target-videzzo-fuzz-ati-crash-03fba6b48f66f3e5fd4c78c14d35f0c0b71064a0.minimized
