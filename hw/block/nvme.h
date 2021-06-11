#ifndef HW_NVME_H
#define HW_NVME_H

#include "block/nvme.h"
#include "nvme-ns.h"
#include "hw/virtio/vhost.h"
#include "sysemu/hostmem.h"
#include "chardev/char-fe.h"
#include "hw/pci/pci.h"

#define NVME_MAX_NAMESPACES 256
#define NVME_MAX_IOQPAIRS 0xffff
#define NVME_DB_SIZE  4
#define NVME_SPEC_VER 0x00010300
#define NVME_CMB_BIR 2
#define NVME_PMR_BIR 2
#define NVME_TEMPERATURE 0x143
#define NVME_TEMPERATURE_WARNING 0x157
#define NVME_TEMPERATURE_CRITICAL 0x175
#define NVME_NUM_FW_SLOTS 1
#define VHOST_NVME_BAR_READ 0
#define VHOST_NVME_BAR_WRITE 1

#define NVME_GUEST_ERR(trace, fmt, ...) \
    do { \
        (trace_##trace)(__VA_ARGS__); \
        qemu_log_mask(LOG_GUEST_ERROR, #trace \
            " in %s: " fmt "\n", __func__, ## __VA_ARGS__); \
    } while (0)


static const bool nvme_feature_support[NVME_FID_MAX] = {
    [NVME_ARBITRATION]              = true,
    [NVME_POWER_MANAGEMENT]         = true,
    [NVME_TEMPERATURE_THRESHOLD]    = true,
    [NVME_ERROR_RECOVERY]           = true,
    [NVME_VOLATILE_WRITE_CACHE]     = true,
    [NVME_NUMBER_OF_QUEUES]         = true,
    [NVME_INTERRUPT_COALESCING]     = true,
    [NVME_INTERRUPT_VECTOR_CONF]    = true,
    [NVME_WRITE_ATOMICITY]          = true,
    [NVME_ASYNCHRONOUS_EVENT_CONF]  = true,
    [NVME_TIMESTAMP]                = true,
};

static const uint32_t nvme_feature_cap[NVME_FID_MAX] = {
    [NVME_TEMPERATURE_THRESHOLD]    = NVME_FEAT_CAP_CHANGE,
    [NVME_VOLATILE_WRITE_CACHE]     = NVME_FEAT_CAP_CHANGE,
    [NVME_NUMBER_OF_QUEUES]         = NVME_FEAT_CAP_CHANGE,
    [NVME_ASYNCHRONOUS_EVENT_CONF]  = NVME_FEAT_CAP_CHANGE,
    [NVME_TIMESTAMP]                = NVME_FEAT_CAP_CHANGE,
};
typedef struct NvmeParams {
    char     *serial;
    char     *vhostfd;
    uint32_t num_queues; /* deprecated since 5.1 */
    uint32_t max_ioqpairs;
    uint16_t msix_qsize;
    uint32_t cmb_size_mb;
    uint8_t  aerl;
    uint32_t aer_max_queued;
    uint8_t  mdts;
    bool     use_intel_id;
} NvmeParams;

typedef struct NvmeAsyncEvent {
    QTAILQ_ENTRY(NvmeAsyncEvent) entry;
    NvmeAerResult result;
} NvmeAsyncEvent;

typedef struct NvmeRequest {
    struct NvmeSQueue       *sq;
    struct NvmeNamespace    *ns;
    BlockAIOCB              *aiocb;
    uint16_t                status;
    NvmeCqe                 cqe;
    NvmeCmd                 cmd;
    BlockAcctCookie         acct;
    QEMUSGList              qsg;
    QEMUIOVector            iov;
    QTAILQ_ENTRY(NvmeRequest)entry;
} NvmeRequest;

static inline const char *nvme_adm_opc_str(uint8_t opc)
{
    switch (opc) {
    case NVME_ADM_CMD_DELETE_SQ:        return "NVME_ADM_CMD_DELETE_SQ";
    case NVME_ADM_CMD_CREATE_SQ:        return "NVME_ADM_CMD_CREATE_SQ";
    case NVME_ADM_CMD_GET_LOG_PAGE:     return "NVME_ADM_CMD_GET_LOG_PAGE";
    case NVME_ADM_CMD_DELETE_CQ:        return "NVME_ADM_CMD_DELETE_CQ";
    case NVME_ADM_CMD_CREATE_CQ:        return "NVME_ADM_CMD_CREATE_CQ";
    case NVME_ADM_CMD_IDENTIFY:         return "NVME_ADM_CMD_IDENTIFY";
    case NVME_ADM_CMD_ABORT:            return "NVME_ADM_CMD_ABORT";
    case NVME_ADM_CMD_SET_FEATURES:     return "NVME_ADM_CMD_SET_FEATURES";
    case NVME_ADM_CMD_GET_FEATURES:     return "NVME_ADM_CMD_GET_FEATURES";
    case NVME_ADM_CMD_ASYNC_EV_REQ:     return "NVME_ADM_CMD_ASYNC_EV_REQ";
    default:                            return "NVME_ADM_CMD_UNKNOWN";
    }
}

static inline const char *nvme_io_opc_str(uint8_t opc)
{
    switch (opc) {
    case NVME_CMD_FLUSH:            return "NVME_NVM_CMD_FLUSH";
    case NVME_CMD_WRITE:            return "NVME_NVM_CMD_WRITE";
    case NVME_CMD_READ:             return "NVME_NVM_CMD_READ";
    case NVME_CMD_WRITE_ZEROES:     return "NVME_NVM_CMD_WRITE_ZEROES";
    default:                        return "NVME_NVM_CMD_UNKNOWN";
    }
}

typedef struct NvmeSQueue {
    struct NvmeCtrl *ctrl;
    uint16_t    sqid;
    uint16_t    cqid;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    size;
    uint64_t    dma_addr;
    QEMUTimer   *timer;
    NvmeRequest *io_req;
    QTAILQ_HEAD(, NvmeRequest) req_list;
    QTAILQ_HEAD(, NvmeRequest) out_req_list;
    QTAILQ_ENTRY(NvmeSQueue) entry;
} NvmeSQueue;

typedef struct NvmeCQueue {
    struct NvmeCtrl *ctrl;
    uint8_t     phase;
    uint16_t    cqid;
    uint16_t    irq_enabled;
    uint32_t    head;
    uint32_t    tail;
    uint32_t    vector;
    uint32_t    size;
    uint64_t    dma_addr;
    int32_t     virq;
    EventNotifier guest_notifier;
    QEMUTimer   *timer;
    QTAILQ_HEAD(, NvmeSQueue) sq_list;
    QTAILQ_HEAD(, NvmeRequest) req_list;
} NvmeCQueue;

#define TYPE_NVME_BUS "nvme-bus"
#define NVME_BUS(obj) OBJECT_CHECK(NvmeBus, (obj), TYPE_NVME_BUS)

typedef struct NvmeBus {
    BusState parent_bus;
} NvmeBus;

#define TYPE_NVME "nvme"
#define NVME(obj) \
        OBJECT_CHECK(NvmeCtrl, (obj), TYPE_NVME)

#define TYPE_VHOST_NVME "vhost-kernel-nvme"
#define NVME_VHOST(obj) \
        OBJECT_CHECK(NvmeCtrl, (obj), TYPE_VHOST_NVME)

typedef struct NvmeFeatureVal {
    struct {
        uint16_t temp_thresh_hi;
        uint16_t temp_thresh_low;
    };
    uint32_t    async_config;
    uint32_t    vwc;
} NvmeFeatureVal;

typedef struct NvmeCtrl {
    PCIDevice    parent_obj;
    MemoryRegion iomem;
    MemoryRegion ctrl_mem;
    NvmeBar      bar;
    NvmeParams   params;
    NvmeBus      bus;
    BlockConf    conf;

    int32_t      bootindex;
    struct vhost_dev dev;
    uint32_t     num_io_queues;
    bool         dataplane_started;
    bool         vector_poll_started;

    bool        qs_created;
    uint32_t    page_size;
    uint16_t    page_bits;
    uint16_t    max_prp_ents;
    uint16_t    cqe_size;
    uint16_t    sqe_size;
    uint32_t    reg_size;
    uint32_t    num_namespaces;
    uint32_t    max_q_ents;
    uint8_t     outstanding_aers;
    uint8_t     *cmbuf;
    uint32_t    irq_status;
    uint64_t    host_timestamp;                 /* Timestamp sent by the host */
    uint64_t    timestamp_set_qemu_clock_ms;    /* QEMU clock time */
    uint64_t    starttime_ms;
    uint16_t    temperature;

    HostMemoryBackend *pmrdev;

    uint8_t     aer_mask;
    NvmeRequest **aer_reqs;
    QTAILQ_HEAD(, NvmeAsyncEvent) aer_queue;
    int         aer_queued;

    NvmeNamespace   namespace;
    NvmeNamespace   *namespaces[NVME_MAX_NAMESPACES];
    NvmeSQueue      **sq;
    NvmeCQueue      **cq;
    NvmeSQueue      admin_sq;
    NvmeCQueue      admin_cq;
    NvmeIdCtrl      id_ctrl;
    NvmeFeatureVal  features;
} NvmeCtrl;

struct nvme_stats {
    uint64_t units_read;
    uint64_t units_written;
    uint64_t read_commands;
    uint64_t write_commands;
};

static inline NvmeNamespace *nvme_ns(NvmeCtrl *n, uint32_t nsid)
{
    if (!nsid || nsid > n->num_namespaces) {
        return NULL;
    }

    return n->namespaces[nsid - 1];
}

static inline NvmeCQueue *nvme_cq(NvmeRequest *req)
{
    NvmeSQueue *sq = req->sq;
    NvmeCtrl *n = sq->ctrl;

    return n->cq[sq->cqid];
}

static inline NvmeCtrl *nvme_ctrl(NvmeRequest *req)
{
    NvmeSQueue *sq = req->sq;
    return sq->ctrl;
}

int nvme_register_namespace(NvmeCtrl *n, NvmeNamespace *ns, Error **errp);
uint16_t nvme_cid(NvmeRequest *req);
uint16_t nvme_sqid(NvmeRequest *req);
bool nvme_addr_is_cmb(NvmeCtrl *n, hwaddr addr);
int nvme_addr_read(NvmeCtrl *n, hwaddr addr, void *buf, int size);
bool nvme_nsid_valid(NvmeCtrl *n, uint32_t nsid);
int nvme_check_sqid(NvmeCtrl *n, uint16_t sqid);
int nvme_check_cqid(NvmeCtrl *n, uint16_t cqid);
void nvme_inc_cq_tail(NvmeCQueue *cq);
void nvme_inc_sq_head(NvmeSQueue *sq);
uint8_t nvme_cq_full(NvmeCQueue *cq);
uint8_t nvme_sq_empty(NvmeSQueue *sq);
void nvme_irq_check(NvmeCtrl *n);
void nvme_irq_assert(NvmeCtrl *n, NvmeCQueue *cq);
void nvme_irq_deassert(NvmeCtrl *n, NvmeCQueue *cq);
void nvme_req_clear(NvmeRequest *req);
void nvme_req_exit(NvmeRequest *req);
uint16_t nvme_map_addr_cmb(NvmeCtrl *n, QEMUIOVector *iov, hwaddr addr, size_t len);
uint16_t nvme_map_addr(NvmeCtrl *n, QEMUSGList *qsg, QEMUIOVector *iov,
                                                    hwaddr addr, size_t len);
uint16_t nvme_map_prp(NvmeCtrl *n, uint64_t prp1, uint64_t prp2,
                             uint32_t len, NvmeRequest *req);
uint16_t nvme_map_sgl_data(NvmeCtrl *n, QEMUSGList *qsg, QEMUIOVector *iov,
                                  NvmeSglDescriptor *segment, uint64_t nsgld,
                                  size_t *len, NvmeRequest *req);
uint16_t nvme_map_sgl(NvmeCtrl *n, QEMUSGList *qsg, QEMUIOVector *iov,
                             NvmeSglDescriptor sgl, size_t len,
                             NvmeRequest *req);
uint16_t nvme_map_dptr(NvmeCtrl *n, size_t len, NvmeRequest *req);
uint16_t nvme_dma(NvmeCtrl *n, uint8_t *ptr, uint32_t len,
                         DMADirection dir, NvmeRequest *req);
void nvme_post_cqes(void *opaque);
void nvme_enqueue_req_completion(NvmeCQueue *cq, NvmeRequest *req);
void nvme_process_aers(void *opaque);
void nvme_enqueue_event(NvmeCtrl *n, uint8_t event_type,
                               uint8_t event_info, uint8_t log_page);
void nvme_clear_events(NvmeCtrl *n, uint8_t event_type);
void nvme_rw_cb(void *opaque, int ret);
uint16_t nvme_flush(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_write_zeroes(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_rw(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_io_cmd(NvmeCtrl *n, NvmeRequest *req);
void nvme_free_sq(NvmeSQueue *sq, NvmeCtrl *n);
uint16_t nvme_del_sq(NvmeCtrl *n, NvmeRequest *req);
void nvme_set_blk_stats(NvmeNamespace *ns, struct nvme_stats *stats);
uint16_t nvme_smart_info(NvmeCtrl *n, uint8_t rae, uint32_t buf_len,
                                uint64_t off, NvmeRequest *req);
uint16_t nvme_fw_log_info(NvmeCtrl *n, uint32_t buf_len, uint64_t off,
                                 NvmeRequest *req);
uint16_t nvme_error_info(NvmeCtrl *n, uint8_t rae, uint32_t buf_len,
                                uint64_t off, NvmeRequest *req);
uint16_t nvme_get_log(NvmeCtrl *n, NvmeRequest *req);
void nvme_free_cq(NvmeCQueue *cq, NvmeCtrl *n);
uint16_t nvme_del_cq(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_identify_ctrl(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_identify_ns(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_identify_nslist(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_identify_ns_descr_list(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_identify(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_abort(NvmeCtrl *n, NvmeRequest *req);
void nvme_set_timestamp(NvmeCtrl *n, uint64_t ts);
uint64_t nvme_get_timestamp(const NvmeCtrl *n);
uint16_t nvme_get_feature_timestamp(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_get_feature(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_set_feature_timestamp(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_set_feature(NvmeCtrl *n, NvmeRequest *req);
uint16_t nvme_aer(NvmeCtrl *n, NvmeRequest *req);
void nvme_clear_ctrl(NvmeCtrl *n);
void nvme_process_db(NvmeCtrl *n, hwaddr addr, int val);
void nvme_cmb_write(void *opaque, hwaddr addr, uint64_t data, unsigned size);
uint64_t nvme_cmb_read(void *opaque, hwaddr addr, unsigned size);
void nvme_check_constraints(NvmeCtrl *n, Error **errp);
void nvme_init_state(NvmeCtrl *n);
void nvme_init_cmb(NvmeCtrl *n, PCIDevice *pci_dev);
void nvme_init_pmr(NvmeCtrl *n, PCIDevice *pci_dev);
void nvme_init_ctrl(NvmeCtrl *n, PCIDevice *pci_dev);

#endif /* HW_NVME_H */
