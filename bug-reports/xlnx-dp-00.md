tag: arch: aarch64
tag: type: Abort

# Abort when runs into unsupported AUXCommand in xlnx_dp_aux_set_command.

When we are fuzzing the xlnx-dp, it is easy to reach this abort.
I wonder if we can remove this abort to make the fuzzer surviving from
early crashes.

```
// xlnx_dp_aux_set_command
switch (cmd) {
case READ_AUX:
case READ_I2C:
case READ_I2C_MOT:
    // omit
    break;
case WRITE_AUX:
case WRITE_I2C:
    // omit
    break;
case WRITE_I2C_STATUS:
    qemu_log_mask(LOG_UNIMP, "xlnx_dp: Write i2c status not implemented\n");
    break;
default:
    error_report("%s: invalid command: %u", __func__, cmd);
    abort();
}
```

## More technique details

### QEMU version, upstream commit/tag
c52d69e7dbaaed0ffdef8125e79218672c30161d/6.1.50

### Host and Guest
Ubuntu 18.04 docker/QTest Fuzzer

### Stack traces, crash details

```
aarch64: xlnx_dp_aux_set_command: invalid command: 14
==21== ERROR: libFuzzer: deadly signal
    #0 0x55dc6cc90178 in __sanitizer_print_stack_trace /root/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:86
    #1 0x55dc6cbeab32 in fuzzer::PrintStackTrace() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210
    #2 0x55dc6cb9ccd0 in fuzzer::Fuzzer::CrashCallback() (.part.284) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:233
    #3 0x55dc6cbc28ac in fuzzer::Fuzzer::CrashCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:205
    #4 0x55dc6cbc28ac in fuzzer::Fuzzer::StaticCrashSignalCallback() /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:204
    #5 0x7ffb5966697f  (/root/qemu/build-oss-fuzz/DEST_DIR/lib/libpthread.so.0+0x1297f)
    #6 0x7ffb58c7dfb6 in raise (/root/qemu/build-oss-fuzz/DEST_DIR/lib/libc.so.6+0x3efb6)
    #7 0x7ffb58c7f920 in abort (/root/qemu/build-oss-fuzz/DEST_DIR/lib/libc.so.6+0x40920)
    #8 0x55dc6d3fb47c in xlnx_dp_aux_set_command /root/qemu/build-oss-fuzz/../hw/display/xlnx_dp.c:530:9
    #9 0x55dc6d3fa91a in xlnx_dp_write /root/qemu/build-oss-fuzz/../hw/display/xlnx_dp.c:783:9
    #10 0x55dc6e0676a7 in memory_region_write_accessor /root/qemu/build-oss-fuzz/../softmmu/memory.c:491:5
    #11 0x55dc6e06708d in access_with_adjusted_size /root/qemu/build-oss-fuzz/../softmmu/memory.c:552:18
    #12 0x55dc6e06708d in memory_region_dispatch_write /root/qemu/build-oss-fuzz/../softmmu/memory.c:1502:16
    #13 0x55dc6df15ed1 in flatview_write_continue /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2746:23
    #14 0x55dc6df08a67 in flatview_write /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2786:14
    #15 0x55dc6df0820c in address_space_write /root/qemu/build-oss-fuzz/../softmmu/physmem.c:2878:18
    #16 0x55dc6ccd7dfc in __wrap_qtest_writel /root/qemu/build-oss-fuzz/../tests/qtest/fuzz/qtest_wrappers.c:177:9
    #17 0x55dc6ccd2cfa in stateful_fuzz /root/qemu/build-oss-fuzz/../tests/qtest/fuzz/stateful_fuzz.c:402:13
    #18 0x55dc6ccd4470 in LLVMFuzzerTestOneInput /root/qemu/build-oss-fuzz/../tests/qtest/fuzz/fuzz.c:151:5
    #19 0x55dc6cbc3213 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:603
    #20 0x55dc6cba665a in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:323
    #21 0x55dc6cbb1431 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:858
    #22 0x55dc6cb9cfa2 in main /root/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20
    #23 0x7ffb58c60bf6 in __libc_start_main (/root/qemu/build-oss-fuzz/DEST_DIR/lib/libc.so.6+0x21bf6)
    #24 0x55dc6cb9cff9 in _start (/root/qemu/build-oss-fuzz/DEST_DIR/qemu-fuzz-aarch64-target-stateful-fuzz-xlnx-dp+0x123cff9)
```

### Reproducer steps

```
#!/bin/bash -x
export QEMU=/root/qemu/build-oss-fuzz/qemu-system-aarch64
export BUILDROOT=./
cat << EOF | $QEMU \
-machine xlnx-zcu102,accel=qtest -qtest stdio -monitor none -serial none \
-display none -nodefaults -qtest stdio
writel 0xfd4a0100 0x7e04
EOF
```
## Suggested fix

```
diff --git a/hw/display/xlnx_dp.c b/hw/display/xlnx_dp.c
index 4fd6aeb..0db5e1a 100644
--- a/hw/display/xlnx_dp.c
+++ b/hw/display/xlnx_dp.c
@@ -467,7 +467,7 @@ static uint8_t xlnx_dp_aux_pop_tx_fifo(XlnxDPState *s)

     if (fifo8_is_empty(&s->tx_fifo)) {
         error_report("%s: TX_FIFO underflow", __func__);
-        abort();
+        return 0;
     }
     ret = fifo8_pop(&s->tx_fifo);
     DPRINTF("pop 0x%2.2X from tx_fifo.\n", ret);
@@ -527,7 +527,6 @@ static void xlnx_dp_aux_set_command(XlnxDPState *s, uint32_t value)
         break;
     default:
         error_report("%s: invalid command: %u", __func__, cmd);
-        abort();
     }

     s->core_registers[DP_INTERRUPT_SIGNAL_STATE] |= 0x04;
@@ -614,7 +613,7 @@ static void xlnx_dp_recreate_surface(XlnxDPState *s)
 /*
  * Change the graphic format of the surface.
  */
-static void xlnx_dp_change_graphic_fmt(XlnxDPState *s)
+static int xlnx_dp_change_graphic_fmt(XlnxDPState *s)
 {
     switch (s->avbufm_registers[AV_BUF_FORMAT] & DP_GRAPHIC_MASK) {
     case DP_GRAPHIC_RGBA8888:
@@ -635,7 +634,7 @@ static void xlnx_dp_change_graphic_fmt(XlnxDPState *s)
     default:
         error_report("%s: unsupported graphic format %u", __func__,
                      s->avbufm_registers[AV_BUF_FORMAT] & DP_GRAPHIC_MASK);
-        abort();
+        return EDP_GRAPHIC;
     }

     switch (s->avbufm_registers[AV_BUF_FORMAT] & DP_NL_VID_FMT_MASK) {
@@ -651,10 +650,11 @@ static void xlnx_dp_change_graphic_fmt(XlnxDPState *s)
     default:
         error_report("%s: unsupported video format %u", __func__,
                      s->avbufm_registers[AV_BUF_FORMAT] & DP_NL_VID_FMT_MASK);
-        abort();
+        return EDP_NL_VID_FMT;
     }

     xlnx_dp_recreate_surface(s);
+    return 0;
 }

 static void xlnx_dp_update_irq(XlnxDPState *s)
@@ -1025,8 +1025,10 @@ static void xlnx_dp_avbufm_write(void *opaque, hwaddr offset, uint64_t value,

     switch (offset) {
     case AV_BUF_FORMAT:
+        uint32_t old_av_buf_format = s->avbufm_registers[offset];
         s->avbufm_registers[offset] = value & 0x00000FFF;
-        xlnx_dp_change_graphic_fmt(s);
+        if (xlnx_dp_change_graphic_fmt(s))
+            s->avbufm_registers[offset] = old_av_buf_format;
         break;
     case AV_CHBUF0:
     case AV_CHBUF1:
diff --git a/include/hw/display/xlnx_dp.h b/include/hw/display/xlnx_dp.h
index 8ab4733..e85e428 100644
--- a/include/hw/display/xlnx_dp.h
+++ b/include/hw/display/xlnx_dp.h
@@ -107,4 +107,7 @@ struct XlnxDPState {
 #define TYPE_XLNX_DP "xlnx.v-dp"
 OBJECT_DECLARE_SIMPLE_TYPE(XlnxDPState, XLNX_DP)

+#define EDP_GRAPHIC -1
+#define EDP_NL_VID_FMT -2
+
 #endif
```

## Contact

Let me know if I need to provide more information.
