DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-i386-target-videzzo-fuzz-ehci \
    -max_len=10000000 -detect_leaks=0 \
    ./poc-qemu-videzzo-i386-target-videzzo-fuzz-ehci-crash-c92914f16aa438359c4d57eca1abcff9a28cf593.minimized.minimized
