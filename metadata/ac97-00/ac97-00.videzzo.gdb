DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-i386-target-videzzo-fuzz-ac97 \
    -max_len=10000000 -detect_leaks=0 \
    ./poc-qemu-videzzo-i386-target-videzzo-fuzz-ac97-crash-34f363858ebf594cf9d542440eb245ffc441c3af.minimized
