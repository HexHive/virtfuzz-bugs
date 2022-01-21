tag: arch: aarch64
tag: type: Abort

# Out-of-bounds read in xlnx_dp_read

1. xlnx_dp_read allows one-element-off read at its default branch
because of an improper index.

```
#define DP_CORE_REG_ARRAY_SIZE (0x3AF >> 2)
struct XlnxDPState {
    uint32_t core_registers[DP_CORE_REG_ARRAY_SIZE];
    MemoryRegion core_iomem;
}
static uint64_t xlnx_dp_read(void *opaque, hwaddr ...
    switch (offset) {
        default:                             // (0x3AF >> 2) is equal to (0x3AC >> 2)
            assert(offset <= (0x3AC >> 2));  // the op should be <
            ret = s->core_registers[offset]; // one-element-off access
            break;
```

Because the following object is a MemoryRegion whose first 4 four bytes
are part of the type name, this out-of-bounds read may not be harmful.

2. More information.

According to
https://www.xilinx.com/html_docs/registers/ug1087/ug1087-zynq-ultrascale-registers.html,
offset 0x3AC is allowed.

DP_INT_MASK	0x000003A4	32	mixed	0xFFFFF03F	Interrupt Mask Register for intrN. This is a read-only location and can be atomically altered by either the IDR or the IER.
DP_INT_EN	0x000003A8	32	mixed	0x00000000	Interrupt Enable Register. A write of to this location will unmask the interrupt. (IMR: 0)
DP_INT_DS	0x000003AC	32	mixed	0x00000000	Interrupt Disable Register. A write of one to this location will mask the interrupt. (IMR:

```
memory_region_init_io(&s->core_iomem, obj, &dp_ops, s, TYPE_XLNX_DP, ".core", 0x3AF);
```
The size of this memory region is 0x3AF, which is also reasonable (0x3B0
is better).

According to the implementation of xlnx_dp_write, when the offset is
0x3A8 and 0x3AC, the virtual device will access s->core_registers[0x3A4
>> 2]. That is to say, the maxize of s->core_registers could be ((0x3A4
>> 2) + 1). Therefore, it is also reasonable to define
s->core_registers[DP_CORE_REG_ARRAY_SIZE] where DP_CORE_REG_ARRAY_SIZE
is (0x3AF >> 2) (0x3A8 >> 2 is better). However, in xlxn_dp_read, offset
0x3A8 and 0x3AC is not handled like what is done in the xlnx_dp_write.

## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Stack traces, crash details

```
../hw/display/xlnx_dp.c:717:15: runtime error: index 235 out of bounds for type 'uint32_t [235]'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../hw/display/xlnx_dp.c:717:15 in
```

### Reproducer steps

```
#!/bin/bash -x
export QEMU=/root/qemu/build-ubsan/qemu-system-aarch64
export BUILDROOT=./
cat << EOF | $QEMU \
-machine xlnx-zcu102,accel=qtest -qtest stdio -monitor none -serial none \
-display none -nodefaults -qtest stdio
readl 0xfd4a03ac
EOF
```
## Suggested fix

```
diff --git a/hw/display/xlnx_dp.c b/hw/display/xlnx_dp.c
index 7bcbb13..ff0b8a9 100644
--- a/hw/display/xlnx_dp.c
+++ b/hw/display/xlnx_dp.c
@@ -713,8 +713,10 @@ static uint64_t xlnx_dp_read(void *opaque, hwaddr offset, unsigned size)
         ret = 0;
         break;
     default:
-        assert(offset <= (0x3AC >> 2));
-        ret = s->core_registers[offset];
+        if (offset == (0x3A8 >> 2) || offset == (0x3AC >> 2))
+            ret = s->core_registers[DP_INT_MASK];
+        else:
+            ret = s->core_registers[offset];
         break;
     }

@@ -876,7 +878,6 @@ static void xlnx_dp_write(void *opaque, hwaddr offset, uint64_t value,
         xlnx_dp_update_irq(s);
         break;
     default:
-        assert(offset <= (0x504C >> 2));
         s->core_registers[offset] = value;
         break;
     }
diff --git a/include/hw/display/xlnx_dp.h b/include/hw/display/xlnx_dp.h
index e85e428..99a6d47 100644
--- a/include/hw/display/xlnx_dp.h
+++ b/include/hw/display/xlnx_dp.h
@@ -39,7 +39,7 @@
 #define AUD_CHBUF_MAX_DEPTH                 (32 * KiB)
 #define MAX_QEMU_BUFFER_SIZE                (4 * KiB)

-#define DP_CORE_REG_ARRAY_SIZE              (0x3AF >> 2)
+#define DP_CORE_REG_ARRAY_SIZE              (0x3A8 >> 2)
 #define DP_AVBUF_REG_ARRAY_SIZE             (0x238 >> 2)
 #define DP_VBLEND_REG_ARRAY_SIZE            (0x1DF >> 2)
 #define DP_AUDIO_REG_ARRAY_SIZE             (0x50 >> 2)
```

## Contact

Let me know if I need to provide more information.
