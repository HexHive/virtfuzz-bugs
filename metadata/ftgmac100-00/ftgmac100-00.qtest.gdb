export QEMU=/home/liuqiang/project-videzzo/qemu-devel/build/qemu-system-arm

# 0x24242400 is the address of the second aspeed Flash chip
echo writel 0x1e660424 0x24242400 > qtest.txt
echo writel 0x1e661050 0x1a1a1a1a >> qtest.txt
echo run gdb $QEMU
echo run "r -machine palmetto-bmc -monitor none -serial none -display none -nodefaults -qtest stdio < qtest.txt"
