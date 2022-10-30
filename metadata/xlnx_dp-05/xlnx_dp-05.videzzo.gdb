DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-aarch64-target-videzzo-fuzz-xlnx-dp \
    -max_len=10000000 -detect_leaks=0 \
    crash-8b178268936b24c569a421d702ef5b6d911c99e7.minimized
