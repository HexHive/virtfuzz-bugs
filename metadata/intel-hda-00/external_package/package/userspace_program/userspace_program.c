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

void mmio_write(uint32_t addr, uint32_t value) {
    *((uint32_t *)(mmio_mem + addr)) = value;
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
    void *ptr_virt = mmap(0, size + 256, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ptr_virt == MAP_FAILED)
        die("[-] Mmap 256aligned buffer failed.\n");
    mlock(ptr_virt, size + 256);
    uint64_t ptr_phys = gva_to_gpa(ptr_virt);
    uint64_t __ptr_phys = (ptr_phys + 0xff) & (~(uint64_t)0xff);
    return (void *)((uint64_t)ptr_virt + (__ptr_phys - ptr_phys));
}

int main(int argc, char **argv) {
    printf("[+]\n[+] Reproduce hda-00: start\n[+]\n");

    // lspci -v
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:05.0/resource0", O_RDWR | O_SYNC);
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

    iopl(3);

    //  009, EVENT_TYPE_MMIO_WRITE, 0xf0406146, 0x1, 0x5bd062c2
    mmio_writeb(0x2146, 0xc2);

    printf("[+]\n[+] Reproduce hda-00: fail\n[+]\n");

    return 0;
}
