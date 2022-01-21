tag: arch: i386
tag: type: ASS failure

# Code should not be reached vmxnet3_io_bar1_write

Because this bug was reported
[here](https://gitlab.com/qemu-project/qemu/-/issues/309), I just provide our
reproducer. This bug can also be reproduced in the QEMU 6.0.50,
3e13d8e34b53d8f9a3421a816ccfbdc5fa874e98.

## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Reproducer steps

I wrote a kernel module to reproduce this crash.
>uint32_t address = (uint32_t)ioremap(0xfebd4000, 4 * 1024);
>writel(0x82828282, (void *)(address + 0x38));

Execute
```
#!/bin/bash
export QEMU=/root/qemu/build-coverage/qemu-system-i386
export BUILDROOT=./
$QEMU \
    -M q35 \
    -kernel $BUILDROOT/bzImage \
    -drive file=$BUILDROOT/rootfs.ext2,if=virtio,format=raw \
    -append "root=/dev/vda console=ttyS0" \
    -device vmxnet3,netdev=net0 -netdev user,id=net0 \
    -nographic \
    -m 512M
```

The username is root and the password is empty.
Then, `modprobe vmxnet3-00`.  You will see the crash.

```
# modprobe vmxnet3-00
vmxnet3_00: loading out-of-tree module taints kernel.
**
ERROR:../hw/net/vmxnet3.c:1793:vmxnet3_io_bar1_write: code should not be reached
./run.sh: line 11:   192 Aborted                 (core dumped)
```

Attachment: https://drive.google.com/file/d/1X422a-8eT-hsLaog5J5fx9Z4S5D4_0Qh/view?usp=sharing

## Suggested fix

```
diff --git a/hw/net/vmxnet3.c b/hw/net/vmxnet3.c
index eff299f..a388918 100644
--- a/hw/net/vmxnet3.c
+++ b/hw/net/vmxnet3.c
@@ -1786,13 +1786,6 @@ vmxnet3_io_bar1_write(void *opaque,
         vmxnet3_set_variable_mac(s, val, s->temp_mac);
         break;

-    /* Interrupt Cause Register */
-    case VMXNET3_REG_ICR:
-        VMW_CBPRN("Write BAR1 [VMXNET3_REG_ICR] = %" PRIx64 ", size %d",
-                  val, size);
-        g_assert_not_reached();
-        break;
-
     /* Event Cause Register */
     case VMXNET3_REG_ECR:
         VMW_CBPRN("Write BAR1 [VMXNET3_REG_ECR] = %" PRIx64 ", size %d",
```

## Contact

Let me know if I need to provide more information.
