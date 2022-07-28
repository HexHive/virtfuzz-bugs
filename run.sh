docker run --rm \
    -e LC_CTYPE=C.UTF-8 \
    -v $PWD/qemu-out-san:/root/videzzo/videzzo_qemu/out-san \
    -v $PWD/vbox-out-san:/root/videzzo/videzzo_vbox/out-san \
    -v $PWD/qemu:/root/videzzo/videzzo_qemu/qemu \
    -v $PWD/vbox:/root/videzzo/videzzo_vbox/vbox \
    -v /usr/src:/usr/src \
    -v /dev:/dev \
    -v /lib/modules:/lib/modules \
    --privileged \
    -it videzzo-bugs:latest /bin/bash
