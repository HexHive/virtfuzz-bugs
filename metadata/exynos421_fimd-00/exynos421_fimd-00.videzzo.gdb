DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args ./qemu-videzzo-arm-target-videzzo-fuzz-exynos4210-fimd \
    -max_len=10000000 -detect_leaks=0 \
    ./poc-qemu-videzzo-arm-target-videzzo-fuzz-exynos4210-fimd-crash-eda3de9b6941dd8c14e22959b56dbe5d8d07dae3.minimized
