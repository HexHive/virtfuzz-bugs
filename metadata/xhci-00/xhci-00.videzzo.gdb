DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args ./qemu-videzzo-i386-target-videzzo-fuzz-xhci \
    -max_len=10000000 -detect_leaks=0 \
    poc-qemu-videzzo-i386-target-videzzo-fuzz-xhci-crash-4a11736abb111efe4b29a6931f403561f9a0f9ec.minimized
