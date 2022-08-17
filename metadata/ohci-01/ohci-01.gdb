# cp /root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci .
# cp -r pc-bios /root/videzzo/videzzo_qemu/out-san/pc-bios .
ASAN_OPTIONS=detect_leaks=0 \
DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-i386-target-videzzo-fuzz-ohci \
    -max_len=10000000 -detect_leaks=0 \
    poc-qemu-videzzo-i386-target-videzzo-fuzz-ohci-crash-9a5bf80e15f7ecfe3f8c918b3b5cb629d96a5f57.minimized
