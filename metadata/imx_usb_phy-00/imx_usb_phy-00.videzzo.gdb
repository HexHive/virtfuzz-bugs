DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./qemu-videzzo-arm-target-videzzo-fuzz-imx-usb-phy \
    -max_len=10000000 -detect_leaks=0 \
    ./crash-2f5e9c8ec69dd69f8db69aaa84dde878482b8690.minimized
