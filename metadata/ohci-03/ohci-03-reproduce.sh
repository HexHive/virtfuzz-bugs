#!/bin/bash
export ASAN_OPTIONS=detect_leaks=0
export DEFAULT_INPUT_MAXSIZE=10000000
/root/videzzo/videzzo_qemu/out-san/qemu-videzzo-i386-target-videzzo-fuzz-ohci /root/videzzo/videzzo_qemu/out-san/crash-2dd2c6ca803314e8f5ae24133d11d7964215d14f  -max_len=10000000 -detect_leaks=0 -pre_seed_inputs=@$1
