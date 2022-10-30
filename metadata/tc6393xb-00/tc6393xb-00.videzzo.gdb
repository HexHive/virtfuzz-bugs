DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-arm-target-videzzo-fuzz-tc6393xb \
    -max_len=10000000 -detect_leaks=0 \
    poc-qemu-videzzo-arm-target-videzzo-fuzz-tc6393xb-crash-55c2b01921c18ce020fa35319af4632834e116be.minimized
