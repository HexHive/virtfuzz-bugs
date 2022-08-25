# git checkout -b ohci-00 5288bee45fbd33203b61f8c76e41b15bb5913e6e
# ./configure --target-list=x86_64-softmmu --enable-debug --disable-pie
# make
gdb --args \
    ../../../qemu/build/qemu-system-x86_64 \
    -M q35 -m 1G \
    -kernel ../../../buildroot-2022.02.4/output/images/bzImage \
    -drive file=../../../buildroot-2022.02.4/output/images/rootfs.ext2,if=virtio,format=raw \
    -append "root=/dev/vda console=ttyS0" \
    -net nic,model=virtio -net user \
    -usb \
    -device pci-ohci,num-ports=6 \
    -drive file=null-co://,if=none,format=raw,id=disk0 \
    -device usb-storage,port=1,drive=disk0 \
    -nographic
