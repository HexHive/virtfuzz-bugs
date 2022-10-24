# Heap buffer overflow in sdhci_read_dataport()

I re-trigger the off-by-one heap-buffer-overflow read [3] in
sdhci_read_dataport() (previously reported at
https://gitlab.com/qemu-project/qemu/-/issues/451) and write [4] in
sdhci_write_dataport() (previously reported at
https://bugs.launchpad.net/qemu/+bug/1913919) to s->fifo_buffer since
s->data_count [2] is possibly equal to the size of the heap buffer
s->fifo_buffer [1]. As s->data_count is immediately reset [5], we can only read
and write one byte after a heap buffer.

``` c
static uint32_t sdhci_read_dataport(SDHCIState *s, unsigned size)
{
    // ...
    for (i = 0; i < size; i++) {
        // sizeof(s->fifo_buffer) = 0x200 // <--------------------------- [1]
        // s->data_count = 0x200 // <------------------------------------ [2]
        value |= s->fifo_buffer[s->data_count] << i * 8; // <------------ [3]
        // ...
        if (s->data_count >= (s->blksize & BLOCK_SIZE_MASK)) {
            s->data_count = 0; // <-------------------------------------- [5]

static void sdhci_write_dataport(SDHCIState *s, uint32_t value, unsigned size)
{
    // ...
    for (i = 0; i < size; i++) {
        // sizeof(s->fifo_buffer) = 0x200 // <--------------------------- [1]
        // s->data_count = 0x200 // <------------------------------------ [2]
        s->fifo_buffer[s->data_count] = value & 0xFF; // <--------------- [4]
        // ...
        if (s->data_count >= (s->blksize & BLOCK_SIZE_MASK)) {
            s->data_count = 0; // <-------------------------------------- [5]
```

The key to trigger this off-by-one read/write is producing a dma access error.

Here is how the off-by-one read works. The write works similarly.

sdhci_do_adma() will load a DMA descriptor [6] and set s->data_count to
s->blksize (0x200) [7]. Usually, s->data_count will be clear at [10]. However,
if dma_memory_write() at [8] returns an error, the value of s->data_count will
be kept since nothing has been done at [9]. One possible way to let
dma_memory_write() returns error is to set dscr.addr to an invalid address.
For example, a guest requires 2G physical memory, but dscr.addr is set to 3G.

``` c
static void sdhci_do_adma(SDHCIState *s)
{
        // ...
        get_adma_description(s, &dscr); // <---------------------------- [6]

        // ...
        length = dscr.length ? dscr.length : 64 * KiB;

        switch (dscr.attr & SDHC_ADMA_ATTR_ACT_MASK) {
        case SDHC_ADMA_ATTR_ACT_TRAN:  /* data transfer */
                    // ...
                    begin = s->data_count;
                    if ((length + begin) < block_size) {
                        // ...
                     } else {
                        s->data_count = block_size; // <---------------- [7]
                        length -= block_size - begin;
                    }
                    res = dma_memory_write(s->dma_as, dscr.addr, // <--- [8]
                    // ...
                    if (res != MEMTX_OK) {
                        break; // <------------------------------------- [9]
                    }
                    dscr.addr += s->data_count - begin;
                    if (s->data_count == block_size) {
                        s->data_count = 0; // <------------------------ [10]
                        // ...
```

## Security impact

1 This bug is trigger when a dma error is issued. For example, we require a
machine with 1G physical memory while we want the sd controller to read and
write something to above 1G.

2 We can control one byte after s->fifo_buffer (0x200). The byte will be the
prev_size of the next chunk causing overlapped chunks. This is prevented after
glibc 2.29. On Ubuntu 20.04, it's glibc 2.31.

3 The chunk after what after s->fifo_buffer is a 30 bytes buffer allocated in
g_hash_table_new_full(), which idk how to free.


## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 7.1.50, e93ded1bf6c94ab95015b33e188bc8b0b0c32670, Ubuntu 20.04

### VM architecture, device, device type
i386, sdhci, storage

### Bug Type: Heap-Buffer-Overflow

### Existing bug reports
https://gitlab.com/qemu-project/qemu/-/issues/451
https://bugs.launchpad.net/qemu/+bug/1913919

## Suggested fix

```
From 9688c852b8a767f63e7cfa710ca2b3c68c78d531 Mon Sep 17 00:00:00 2001
From: Qiang Liu <cyruscyliu@gmail.com>
Date: Wed, 7 Sep 2022 13:53:56 +0800
Subject: [PATCH] sdhci: Fix off-by-one heap-buffer-flow read and write in
 sdhci

Signed-off-by: Qiang Liu <cyruscyliu@gmail.com>
---
 hw/sd/sdhci.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/hw/sd/sdhci.c b/hw/sd/sdhci.c
index 0e5e988927..374217ca70 100644
--- a/hw/sd/sdhci.c
+++ b/hw/sd/sdhci.c
@@ -797,6 +797,7 @@ static void sdhci_do_adma(SDHCIState *s)
                                            s->data_count - begin,
                                            attrs);
                     if (res != MEMTX_OK) {
+                        s->data_count = 0;
                         break;
                     }
                     dscr.addr += s->data_count - begin;
@@ -826,6 +827,7 @@ static void sdhci_do_adma(SDHCIState *s)
                                           s->data_count - begin,
                                           attrs);
                     if (res != MEMTX_OK) {
+                        s->data_count = 0;
                         break;
                     }
                     dscr.addr += s->data_count - begin;
-- 
2.25.1

```

## Contact

Let us know if I need to provide more information.
