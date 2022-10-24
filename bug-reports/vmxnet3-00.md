# Code should not be reached vmxnet3_io_bar1_write()

# Code should not be reached vmxnet3_io_bar1_write

Because this bug was reported
[here](https://gitlab.com/qemu-project/qemu/-/issues/309), I just provide our
reproducer. This bug can also be reproduced in the QEMU 6.0.50,
3e13d8e34b53d8f9a3421a816ccfbdc5fa874e98.

## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d, Ubuntu 18.04

### VM architecture, device, device type
i386, vmxnet3, net

### Bug Type: Assertion Failure

### Existing bug reports

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

Let us know if I need to provide more information.
