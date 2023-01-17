DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-arm-target-videzzo-fuzz-tc6393xb \
    -max_len=10000000 -detect_leaks=0 \
    poc-qemu-videzzo-arm-target-videzzo-fuzz-tc6393xb-crash-35f3f537422c4e74ce65177b3d6369045e60b47f.adjusted
