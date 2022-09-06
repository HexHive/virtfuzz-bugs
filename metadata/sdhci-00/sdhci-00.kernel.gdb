# git pull
# git checkout -b sdhci-00
# ./configure --target-list=x86_64-softmmu --enable-debug --disable-pie
# make
gdb --args ../../../qemu/build/qemu-system-x86_64 \
    -M q35 -m 1G \
    -kernel ../../../buildroot-2022.02.4/output/images/bzImage \
    -drive file=../../../buildroot-2022.02.4/output/images/rootfs.ext2,if=virtio,format=raw \
    -append "root=/dev/vda console=ttyS0" \
    -net nic,model=virtio -net user \
    -drive if=none,index=0,file=null-co://,format=raw,id=mydrive \
    -device sdhci-pci,sd-spec-version=3 \
    -device sd-card,drive=mydrive \
    -nographic
