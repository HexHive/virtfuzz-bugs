# OOBR in xlnx_dp_read

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


## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 6.1.50, c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50, Ubuntu 18.04

### VM architecture, device, device type
aarch64, xlnx_dp, display

### Bug Type: Out-of-bounds Read

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
xlnx_dp_read allows an out-of-bounds read at its default branch because
of an improper index.

According to
https://www.xilinx.com/html_docs/registers/ug1087/ug1087-zynq-ultrascale-registers.html
(DP Module), registers 0x3A4/0x3A4/0x3AC are allowed.

DP_INT_MASK 0x03A4  32  mixed   0xF03F  Interrupt Mask 
Register for intrN.
DP_INT_EN   0x03A8  32  mixed   0x  Interrupt 
Enable Register.
DP_INT_DS   0x03AC  32  mixed   0x  Interrupt 
Disable Register.

In xlnx_dp_write, when the offset is 0x3A8 and 0x3AC, the virtual device
will write s->core_registers[0x3A4

2]. That is to say, the maxize of s->core_registers could be ((0x3A4
2) + 1). However, the current size of s->core_registers is (0x3AF >>
2), that is ((0x3A4 >> 2) + 2), which is out of the range.

In xlxn_dp_read, the access to offset 0x3A8 or 0x3AC will be directed to
the offset 0x3A8 (incorrect functionality) or 0x3AC (out-of-bounds read)
rather than 0x3A4.

This patch enforces the read access to offset 0x3A8 and 0x3AC to 0x3A4,
but does not adjust the size of s->core_registers to avoid breaking
migration.

Fixes: 58ac482a66de ("introduce xlnx-dp")
Signed-off-by: Qiang Liu 
---
v2:
   - not change DP_CORE_REG_ARRAY_SIZE
   - add a qtest reproducer
   - update the code style

I have a question about the QTest reproducer. Before patching xlnx-dp,
(0x3ac >> 2) will exceed the right bound of s->core_registers.  However,
this is allowed by the assertion. There is no warning and this
reproducer will pass. Is the reprodocer OK?

  hw/display/xlnx_dp.c|  6 +-
  tests/qtest/fuzz-xlnx-dp-test.c | 33 +
  tests/qtest/meson.build |  1 +
  3 files changed, 39 insertions(+), 1 deletion(-)
  create mode 100644 tests/qtest/fuzz-xlnx-dp-test.c

diff --git a/hw/display/xlnx_dp.c b/hw/display/xlnx_dp.c
index 7bcbb13..747df6e 100644
--- a/hw/display/xlnx_dp.c
+++ b/hw/display/xlnx_dp.c
@@ -714,7 +714,11 @@ static uint64_t xlnx_dp_read(void *opaque, hwaddr offset, 
unsigned size)
  break;
  default:
  assert(offset <= (0x3AC >> 2));
-ret = s->core_registers[offset];
+if (offset == (0x3A8 >> 2) || offset == (0x3AC >> 2)) {
+ret = s->core_registers[DP_INT_MASK];
+} else {
+ret = s->core_registers[offset];
+}
  break;
  }
  
diff --git a/tests/qtest/fuzz-xlnx-dp-test.c b/tests/qtest/fuzz-xlnx-dp-test.c

new file mode 100644
index 000..69eb6c0
--- /dev/null
+++ b/tests/qtest/fuzz-xlnx-dp-test.c


Would it make sense to call the file xlnx-zcu102.c instead, in case we want 
to add other tests related to this machine later?



@@ -0,0 +1,33 @@
+/*
+ * QTest fuzzer-generated testcase for xlnx-dp display device
+ *
+ * Copyright (c) 2021 Qiang Liu 
+ *
+ * SPDX-License-Identifier: GPL-2.0-or-later
+ */
+
+#include "qemu/osdep.h"
+#include "libqos/libqtest.h"
+
+/*
+ * This used to trigger the out-of-bounds read in xlnx_dp_read
+ */
+static void test_fuzz_xlnx_dp_0x3ac(void)
+{
+QTestState *s = qtest_init("-M xlnx-zcu102 -display none ");


You don't need "-display none", it's added by default in the qtest framework 
(see tests/qtest/libqtest.c).



+qtest_readl(s, 0xfd4a03ac);
+qtest_quit(s);
+}
+
+int main(int argc, char **argv)
+{
+const char *arch = qtest_get_arch();
+
+g_test_init(, , NULL);
+
+   if (strcmp(arch, "aarch64") == 0) {


You likely don't need the architecture check, since it's only added for 
aarch64 in the meson.build file anyway.



+qtest_add_func("fuzz/test_fuzz_xlnx_dp/3ac", test_fuzz_xlnx_dp_0x3ac);
+   }
+
+   return g_test_run();
+}
diff --git a/tests/qtest/meson.build b/tests/qtest/meson.build
index 83ad237..6fd6b0e 100644
--- a/tests/qtest/meson.build
+++ b/tests/qtest/meson.build
@@ -185,6 +185,7 @@ qtests_aarch64 = \
 'numa-test',
 'boot-serial-test',
 'xlnx-can-test',
+   'fuzz-xlnx-dp-test',
 'migration-test']
  
  qtests_s390x = \

```

## Contact

Let us know if I need to provide more information.
