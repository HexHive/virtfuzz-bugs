DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
./qemu-videzzo-i386-target-videzzo-fuzz-virtio-blk \
    -max_len=10000000 -detect_leaks=0 \
    ./poc-qemu-videzzo-i386-target-videzzo-fuzz-virtio-blk-crash-764d569bf23aceaa24a02cf521ffaf36f2341f35.minimized1
