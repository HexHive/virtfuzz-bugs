# Infinite loop in virtio_blk_handle_vq()

An infinite loop is in virtio_blk_handle_vq(). Via crafted vring buffers,
vq->inuse is full even it's not. As a sequence, in virtio_blk_handle_vq(),
vq->shadow_avail_idx is kept 0 while vq->last_avail_idx (>0) will unchange
anymore. Then, virtio_queue_empty() will always return 0 and the do {}
while(!virtio_queue_empy()) will be infinite.

## How to trigger this bug?

1. Set up the vring and invoke virtio_blk_handle_output().

```
vring->desc
           |--------addr----------|----len----|flags|next|
0x10002000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

vring->avail 
           |flgs|-len|
0x10002000 00 00 8e 0c // <---------------------------------------------- [1]
           |--ring---|
0x10003002 00 00 00 00 

           001, EVENT_TYPE_MEM_WRITE, 0x10003002, 0x2, 8e0c

vring->used
           |flgs|-len|
0x100ef000 00 00 00 00
           |---------ring--------|
0x100ef002 00 00 00 00 00 00 00 00 
```

After this, vq->shadow_avail_idx and vq->last_avail_idx will be equal to 0xc83[1].

2. Repeat.

```
vring->desc
           |--------addr----------|----len----|flags|next|
0x100ed000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

           001, EVENT_TYPE_MEM_WRITE, 0x100ed240, 0x8, 0040120000000000
           001, EVENT_TYPE_MEM_WRITE, 0x100ed248, 0x4, 20000000
           001, EVENT_TYPE_MEM_WRITE, 0x100ed24c, 0x2, 11e6
           001, EVENT_TYPE_MEM_WRITE, 0x100ed24e, 0x2, 9300 // next: 0x93

           001, EVENT_TYPE_MEM_WRITE, 0x100ed938, 0x4, 10020000 // <----- [5]
           001, EVENT_TYPE_MEM_WRITE, 0x100ed93c, 0x2, c354
           001, EVENT_TYPE_MEM_WRITE, 0x100ed93e, 0x2, da00 // next: 0xda

           001, EVENT_TYPE_MEM_WRITE, 0x100edda8, 0x4, 01020000 // <----- [6]
           001, EVENT_TYPE_MEM_WRITE, 0x100eddac, 0x2, 4623

vring->avail 
           |flgs|-len|
0x100ee000 00 00 00 00  // <--------------------------------------------- [2]
           |--ring---|
0x100ee002 00 00 00 00 

           001, EVENT_TYPE_MEM_WRITE, 0x100ee0aa, 0x2, 2400 // <--------- [7] 
           001, EVENT_TYPE_MEM_WRITE, 0x100ee1ac, 0x2, 2400 // <--------- [8]

vring->used
           |flgs|-len|
0x100ef000 00 00 00 00
           |---------ring--------|
0x100ef002 00 00 00 00 00 00 00 00 
```

This will clear vq->shadow_avail_idx[2], load three buffers[4-6] 2 * N
times[7,8], where N is 0x80 if vq->vring.num is 0x100. This makes vq->inuse full
even only three descriptors are used[9]. Then, vq->last_avail_idx never gets
update.

```
static void *virtqueue_split_pop(VirtQueue *vq, size_t sz)
{
    if (vq->inuse >= vq->vring.num) { goto done; } // <----------------- [9]

    if (!virtqueue_get_head(vq, vq->last_avail_idx++, &head)) { goto done; }
```


## More details

### Hypervisor, hypervisor version, upstream commit/tag, host
qemu, 7.0.94, 9a99f964b152f8095949bbddca7841744ad418da, Ubuntu 20.04

### VM architecture, device, device type
i386, virtio-blk, storage

### Bug Type: Infinite Loop

## Contact

Let us know if I need to provide more information.
