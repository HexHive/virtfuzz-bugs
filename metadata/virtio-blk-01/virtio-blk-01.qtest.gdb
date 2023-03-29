export QEMU=/home/liuqiang/project-videzzo/qemu-devel/build-san/qemu-system-x86_64

echo gdb $QEMU
echo "r -M q35 -m 1G \
-net nic,model=virtio -net user \
-device virtio-blk,drive=disk0 \
-drive file=null-co://,id=disk0,if=none,format=raw \
-monitor none -serial none \
-display none -nodefaults -qtest stdio < qtest.txt"
echo outl 0xc004 0xdeadbeef > qtest.txt
