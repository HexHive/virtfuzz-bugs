DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-arm-target-videzzo-fuzz-omap-dss \
    -max_len=10000000 -detect_leaks=0 \
    ./poc-qemu-videzzo-arm-target-videzzo-fuzz-omap-dss-crash-1a91663ab720e6e61c1678e61eca8a2d562460b3.minimized
