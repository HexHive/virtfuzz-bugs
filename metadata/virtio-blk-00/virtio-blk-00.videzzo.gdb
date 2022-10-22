DEFAULT_INPUT_MAXSIZE=10000000 \
    gdb --args ./qemu-videzzo-i386-target-videzzo-fuzz-virtio-blk \
    -max_len=10000000 -detect_leaks=0 \
    ./poc-qemu-videzzo-i386-target-videzzo-fuzz-virtio-blk-crash-ef8dc4999e00b5107a47dd9bd82a34ec6fd25f27.minimized
