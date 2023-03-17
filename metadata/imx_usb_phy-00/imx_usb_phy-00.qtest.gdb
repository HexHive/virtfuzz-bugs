export QEMU=/home/liuqiang/project-videzzo/qemu-devel/build-san/qemu-system-arm
export UBSAN_OPTIONS=halt_on_error=1:symbolize=1:print_stacktrace=1

echo readl 0x20c9870 > qtest.txt
echo run gdb $QEMU
echo run "r -machine sabrelite -monitor none -serial none -display none -nodefaults -qtest stdio < qtest.txt"
