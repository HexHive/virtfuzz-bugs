DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp \
    -max_len=10000000 -detect_leaks=0 \
    poc-qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp-oom-d0f97aeea8dbfc63f3b311d4f10795ffda6637aa
