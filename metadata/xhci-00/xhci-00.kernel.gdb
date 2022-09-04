# git pull
# git checkout -b xhci-00
# ./configure --target-list=x86_64-softmmu --enable-debug --disable-pie
# make
gdb --args ../../../qemu/build/qemu-system-x86_64 \
    -M q35 -m 1G \
    -kernel ../../../buildroot-2022.02.4/output/images/bzImage \
    -drive file=../../../buildroot-2022.02.4/output/images/rootfs.ext2,if=virtio,format=raw \
    -append "root=/dev/vda console=ttyS0" \
    -net nic,model=virtio -net user \
    -drive file=null-co://,if=none,format=raw,id=disk0 \
    -device qemu-xhci,id=xhci -device usb-storage,drive=disk0 \
    -device usb-bot -device usb-tablet,bus=xhci.0 \
    -chardev null,id=cd0 -chardev null,id=cd1 \
    -device usb-braille,chardev=cd0 -device usb-ccid -device usb-ccid \
    -device usb-kbd -device usb-mouse -device usb-serial,chardev=cd1 \
    -device usb-tablet -device usb-wacom-tablet -device usb-audio \
    -nographic
