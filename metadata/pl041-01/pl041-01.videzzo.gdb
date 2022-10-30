# cp /root/videzzo/videzzo_qemu/out-san/qemu-videzzo-arm-target-videzzo-fuzz-pl041 .
# cp -r pc-bios /root/videzzo/videzzo_qemu/out-san/pc-bios .
ASAN_OPTIONS=detect_leaks=0 \
DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-arm-target-videzzo-fuzz-pl041 \
    -max_len=10000000 -detect_leaks=0 \
    poc-qemu-videzzo-arm-target-videzzo-fuzz-pl041-crash-6f66ee7817e592f52ad9ba38dbe4d3b35bf95215.minimized
