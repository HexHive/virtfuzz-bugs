QEMU_PATH=../../../qemu-devel/build/x86_64-softmmu/qemu-system-x86_64
KERNEL_PATH=./bzImage
ROOTFS_PATH=./rootfs.ext2
gdb --args $QEMU_PATH \
    -M q35 -m 1G \
    -kernel $KERNEL_PATH \
    -drive file=$ROOTFS_PATH,if=virtio,format=raw \
    -append "root=/dev/vda console=ttyS0" \
    -net nic,model=virtio -net user \
    -device ac97,audiodev=snd0 -audiodev none,id=snd0 \
    -nographic
