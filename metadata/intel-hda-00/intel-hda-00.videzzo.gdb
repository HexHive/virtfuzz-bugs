bugdir=$PWD
pushd /root/videzzo/videzzo_vbox/out-san/
DEFAULT_INPUT_MAXSIZE=10000000 \
gdb --args \
    ./vbox-videzzo-i386-target-videzzo-fuzz-hda \
    -max_len=10000000 -detect_leaks=0 \
    $bugdir/crash-ef8f9faf1e8280b1320cfaf82fff92f30167a190.minimized
popd
