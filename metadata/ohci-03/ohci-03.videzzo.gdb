DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-i386-target-videzzo-fuzz-ohci \
    -max_len=10000000 -detect_leaks=0 \
    poc-qemu-videzzo-i386-target-videzzo-fuzz-ohci-crash-45873cdf5b8ce7547e0ccd69facaf5ffef90b07a.minimized
