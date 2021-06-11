#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "hw/block/block.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "migration/vmstate.h"
#include "sysemu/sysemu.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qapi/visitor.h"
#include "sysemu/hostmem.h"
#include "sysemu/block-backend.h"
#include "exec/memory.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/cutils.h"
#include "trace.h"
#include "nvme.h"
#include "nvme-ns.h"
#include "sysemu/kvm.h"
#include "hw/virtio/vhost.h"
#include "standard-headers/linux/vhost_types.h"
#include "monitor/monitor.h"


#ifdef _VHOST_DEBUG
#define VHOST_OPS_DEBUG(fmt, ...) \
    do { error_report(fmt ": %s (%d)", ## __VA_ARGS__, \
                      strerror(errno), errno); } while (0)
#else
#define VHOST_OPS_DEBUG(fmt, ...) \
    do { } while (0)
#endif

static void nvme_process_sq(void *opaque);

static int vhost_dev_has_iommu(struct vhost_dev *dev)
{
    return false;
    VirtIODevice *vdev = dev->vdev;

    /*
     * For vhost, VIRTIO_F_IOMMU_PLATFORM means the backend support
     * incremental memory mapping API via IOTLB API. For platform that
     * does not have IOMMU, there's no need to enable this feature
     * which may cause unnecessary IOTLB miss/update trnasactions.
     */
    return vdev->dma_as != &address_space_memory &&
           virtio_host_has_feature(vdev, VIRTIO_F_IOMMU_PLATFORM);
}

static int vhost_kernel_nvme_add_kvm_msi_virq(NvmeCtrl *n, NvmeCQueue *cq)
{
    int virq;
    int vector_n;

    if (!msix_enabled(&(n->parent_obj))) {
        error_report("MSIX is mandatory for the device");
        return -1;
    }

    if (event_notifier_init(&cq->guest_notifier, 0)) {
        error_report("Initiated guest notifier failed");
        return -1;
    }
    event_notifier_set_handler(&cq->guest_notifier, NULL);

    vector_n = cq->vector;

    virq = kvm_irqchip_add_msi_route(kvm_state, vector_n, &n->parent_obj);
    if (virq < 0) {
        error_report("Route MSIX vector to KVM failed");
        event_notifier_cleanup(&cq->guest_notifier);
        return -1;
    }
    cq->virq = virq;

    return 0;
}

static void vhost_kernel_nvme_remove_kvm_msi_virq(NvmeCQueue *cq)
{
    kvm_irqchip_release_virq(kvm_state, cq->virq);
    event_notifier_cleanup(&cq->guest_notifier);
    cq->virq = -1;
}

static void nvme_clear_guest_notifier(NvmeCtrl *n)
{
    NvmeCQueue *cq;
    uint32_t qid;

    for (qid = 1; qid <= n->num_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            break;
        }

        if (cq->irq_enabled) {
            vhost_kernel_nvme_remove_kvm_msi_virq(cq);
        }
    }

    if (n->vector_poll_started) {
        msix_unset_vector_notifiers(&n->parent_obj);
        n->vector_poll_started = false;
    }
}

static void vhost_nvme_vector_mask(PCIDevice *dev, unsigned vector)
{
    NvmeCtrl *n = container_of(dev, NvmeCtrl, parent_obj);
    NvmeCQueue *cq;
    EventNotifier *e;
    uint32_t qid;
    int ret;
    for (qid = 1; qid <= n->num_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            continue;
        }
        if (cq->vector == vector) {
            e = &cq->guest_notifier;
            ret = kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state, e, cq->virq);
            if (ret != 0) {
                error_report("remove_irqfd_notifier_gsi failed");
            }
            return;
        }
    }
    return;
}

static int vhost_dev_set_features(struct vhost_dev *dev,
                                  bool enable_log)
{
    uint64_t features = dev->acked_features;
    int r;
    if (enable_log) {
        features |= 0x1ULL << VHOST_F_LOG_ALL;
    }
    if (!vhost_dev_has_iommu(dev)) {
        features &= ~(0x1ULL << VIRTIO_F_IOMMU_PLATFORM);
    }
    if (dev->vhost_ops->vhost_force_iommu) {
        if (dev->vhost_ops->vhost_force_iommu(dev) == true) {
            features |= 0x1ULL << VIRTIO_F_IOMMU_PLATFORM;
       }
    }
    r = dev->vhost_ops->vhost_set_features(dev, features);
    if (r < 0) {
        VHOST_OPS_DEBUG("vhost_set_features failed");
        goto out;
    }
    if (dev->vhost_ops->vhost_set_backend_cap) {
        r = dev->vhost_ops->vhost_set_backend_cap(dev);
        if (r < 0) {
            VHOST_OPS_DEBUG("vhost_set_backend_cap failed");
            goto out;
        }
    }

out:
    return r < 0 ? -errno : 0;
}

static int vhost_dev_nvme_start(struct vhost_dev *hdev, VirtIODevice *vdev)
{
    int ret;

    /* should only be called after backend is connected */
    assert(hdev->vhost_ops);
    hdev->started = true;
    hdev->vdev = vdev;

    ret = vhost_dev_set_features(hdev, hdev->log_enabled);
    if (ret < 0) {
        return ret;
    }

    if (vdev != NULL) {
        return -1;
    }
    ret = hdev->vhost_ops->vhost_set_mem_table(hdev, hdev->mem);
    if (ret < 0) {
        error_report("SET MEMTABLE Failed");
        return ret;
    }

    //vhost_user_set_u64(dev, VHOST_USER_NVME_START_STOP, 1);
    if (hdev->vhost_ops->vhost_dev_start) {
        ret = hdev->vhost_ops->vhost_dev_start(hdev, vdev);
        if (ret) {
        return ret;
        }
    }

    return 0;
}

static int vhost_dev_nvme_stop(struct vhost_dev *hdev)
{
    /* should only be called after backend is connected */
    assert(hdev->vhost_ops);

    if (hdev->vhost_ops->vhost_dev_start) {
        hdev->vhost_ops->vhost_dev_start(hdev, false);
    }

    hdev->started = false;
    hdev->vdev = NULL;
    return 0;
}

static int vhost_nvme_set_endpoint(NvmeCtrl *n)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct vhost_nvme_target backend;
    int ret;

    info_report("QEMU Start NVMe Controller ...");
    if (vhost_dev_nvme_start(&n->dev, NULL) < 0) {
        error_report("vhost_nvme_set_endpoint: vhost device start failed");
        return -1;
    }

    //NVME not have wwpn, but have serial number. See nvme_props for more info
    memset(&backend, 0, sizeof(backend));
    pstrcpy(backend.vhost_wwpn, sizeof(backend.vhost_wwpn), n->params.serial);
    ret = vhost_ops->vhost_nvme_set_endpoint(&n->dev, &backend);
    if (ret < 0) {
        return -errno;
    }

    return 0;
}

static int vhost_nvme_clear_endpoint(NvmeCtrl *n, bool shutdown)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct vhost_nvme_target backend;
    int ret;

    if (shutdown) {
        info_report("QEMU Shutdown NVMe Controller ...");
    } else {
        info_report("QEMU Disable NVMe Controller ...");
    }

    if (vhost_dev_nvme_stop(&n->dev) < 0) {
        error_report("vhost_nvme_clear_endpoint: vhost device stop failed");
        return -1;
    }

    if (shutdown) {
        nvme_clear_guest_notifier(n);
    }

    memset(&backend, 0, sizeof(backend));
    pstrcpy(backend.vhost_wwpn, sizeof(backend.vhost_wwpn), n->params.serial);
    ret = vhost_ops->vhost_nvme_clear_endpoint(&n->dev, &backend);
    if (ret < 0) {
        return -errno;
    }

    n->bar.cc = 0;
    n->dataplane_started = false;
    return 0;
}

static int vhost_nvme_vector_unmask(PCIDevice *dev, unsigned vector,
                                          MSIMessage msg)
{
    NvmeCtrl *n = container_of(dev, NvmeCtrl, parent_obj);
    NvmeCQueue *cq;
    EventNotifier *e;
    uint32_t qid;
    int ret;
    for (qid = 1; qid <= n->num_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            continue;
        }
        if (cq->vector == vector) {
            e = &cq->guest_notifier;
            ret = kvm_irqchip_update_msi_route(kvm_state, cq->virq, msg, dev);
            if (ret < 0) {
                error_report("msi irq update vector %u failed", vector);
                return ret;
            }
            kvm_irqchip_commit_routes(kvm_state);
            ret = kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, e,
                                                     NULL, cq->virq);
            if (ret < 0) {
                error_report("msi add irqfd gsi vector %u failed, ret %d",
                             vector, ret);
                return ret;
            }
            return 0;
        }
    }
    return 0;
}

static void vhost_nvme_vector_poll(PCIDevice *dev,
                                        unsigned int vector_start,
                                        unsigned int vector_end)
{
    NvmeCtrl *n = container_of(dev, NvmeCtrl, parent_obj);
    NvmeCQueue *cq;
    EventNotifier *e;
    uint32_t qid, vector;
    for (qid = 1; qid <= n->num_io_queues; qid++) {
        cq = n->cq[qid];
        if (!cq) {
            continue;
        }
        vector = cq->vector;
        if (vector < vector_end && vector >= vector_start) {
            e = &cq->guest_notifier;
            if (!msix_is_masked(dev, vector)) {
                continue;
            }
            if (event_notifier_test_and_clear(e)) {
                msix_set_pending(dev, vector);
            }
        }
    }
}

static int nvme_set_eventfd(NvmeCtrl *n, EventNotifier *notifier, uint16_t cqid, uint32_t *vector, uint16_t *irq_enabled)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    int fd = event_notifier_get_fd(notifier);
    struct nvmet_vhost_eventfd eventfd;
    int ret;

    memset(&eventfd, 0, sizeof(eventfd));
    eventfd.num = cqid;
    eventfd.fd = fd;
    eventfd.irq_enabled = (int*)irq_enabled;
    eventfd.vector = (int*)vector;
    ret = vhost_ops->vhost_nvme_set_eventfd(&n->dev, &eventfd);
    if (ret < 0) {
        error_report("vhost_nvme_set_eventfd error = %d", ret);
    }

    return 0;
}

static void nvme_init_sq(NvmeSQueue *sq, NvmeCtrl *n, uint64_t dma_addr,
                         uint16_t sqid, uint16_t cqid, uint16_t size)
{
    int i;
    NvmeCQueue *cq;

    sq->ctrl = n;
    sq->dma_addr = dma_addr;
    sq->sqid = sqid;
    sq->size = size;
    sq->cqid = cqid;
    sq->head = sq->tail = 0;
    sq->io_req = g_new0(NvmeRequest, sq->size);

    QTAILQ_INIT(&sq->req_list);
    QTAILQ_INIT(&sq->out_req_list);
    for (i = 0; i < sq->size; i++) {
        sq->io_req[i].sq = sq;
        QTAILQ_INSERT_TAIL(&(sq->req_list), &sq->io_req[i], entry);
    }
    sq->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_process_sq, sq);

    assert(n->cq[cqid]);
    cq = n->cq[cqid];
    QTAILQ_INSERT_TAIL(&(cq->sq_list), sq, entry);
    n->sq[sqid] = sq;
}

static void nvme_init_cq(NvmeCQueue *cq, NvmeCtrl *n, uint64_t dma_addr,
                         uint16_t cqid, uint16_t vector, uint16_t size,
                         uint16_t irq_enabled)
{
    int ret;

    ret = msix_vector_use(&n->parent_obj, vector);
    assert(ret == 0);
    cq->ctrl = n;
    cq->cqid = cqid;
    cq->size = size;
    cq->dma_addr = dma_addr;
    cq->phase = 1;
    cq->irq_enabled = irq_enabled;
    cq->vector = vector;
    cq->head = cq->tail = 0;
    QTAILQ_INIT(&cq->req_list);
    QTAILQ_INIT(&cq->sq_list);
    n->cq[cqid] = cq;
    cq->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, nvme_post_cqes, cq);
}

static uint16_t nvme_create_sq(NvmeCtrl *n, NvmeRequest *req)
{
    NvmeSQueue *sq;
    NvmeCreateSq *c = (NvmeCreateSq *)&req->cmd;

    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t sqid = le16_to_cpu(c->sqid);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->sq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);

    trace_pci_nvme_create_sq(prp1, sqid, cqid, qsize, qflags);

    if (unlikely(!cqid || nvme_check_cqid(n, cqid))) {
        trace_pci_nvme_err_invalid_create_sq_cqid(cqid);
        return NVME_INVALID_CQID | NVME_DNR;
    }
    if (unlikely(!sqid || sqid > n->params.max_ioqpairs ||
        n->sq[sqid] != NULL)) {
        trace_pci_nvme_err_invalid_create_sq_sqid(sqid);
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (unlikely(!qsize || qsize > NVME_CAP_MQES(n->bar.cap))) {
        trace_pci_nvme_err_invalid_create_sq_size(qsize);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (unlikely(prp1 & (n->page_size - 1))) {
        trace_pci_nvme_err_invalid_create_sq_addr(prp1);
        return NVME_INVALID_PRP_OFFSET | NVME_DNR;
    }
    if (unlikely(!(NVME_SQ_FLAGS_PC(qflags)))) {
        trace_pci_nvme_err_invalid_create_sq_qflags(NVME_SQ_FLAGS_PC(qflags));
        return NVME_INVALID_FIELD | NVME_DNR;
    }
    sq = g_malloc0(sizeof(*sq));
    nvme_init_sq(sq, n, prp1, sqid, cqid, qsize + 1);
    return NVME_SUCCESS;
}

static uint16_t nvme_create_cq(NvmeCtrl *n, NvmeRequest *req)
{
    NvmeCQueue *cq;
    NvmeCreateCq *c = (NvmeCreateCq *)&req->cmd;
    uint16_t cqid = le16_to_cpu(c->cqid);
    uint16_t vector = le16_to_cpu(c->irq_vector);
    uint16_t qsize = le16_to_cpu(c->qsize);
    uint16_t qflags = le16_to_cpu(c->cq_flags);
    uint64_t prp1 = le64_to_cpu(c->prp1);
    int ret = 0;

    trace_pci_nvme_create_cq(prp1, cqid, vector, qsize, qflags,
                             NVME_CQ_FLAGS_IEN(qflags) != 0);

    if (unlikely(!cqid || cqid > n->params.max_ioqpairs ||
        n->cq[cqid] != NULL)) {
        trace_pci_nvme_err_invalid_create_cq_cqid(cqid);
        return NVME_INVALID_QID | NVME_DNR;
    }
    if (unlikely(!qsize || qsize > NVME_CAP_MQES(n->bar.cap))) {
        trace_pci_nvme_err_invalid_create_cq_size(qsize);
        return NVME_MAX_QSIZE_EXCEEDED | NVME_DNR;
    }
    if (unlikely(prp1 & (n->page_size - 1))) {
        trace_pci_nvme_err_invalid_create_cq_addr(prp1);
        return NVME_INVALID_PRP_OFFSET | NVME_DNR;
    }
    if (unlikely(!msix_enabled(&n->parent_obj) && vector)) {
        trace_pci_nvme_err_invalid_create_cq_vector(vector);
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (unlikely(vector >= n->params.msix_qsize)) {
        trace_pci_nvme_err_invalid_create_cq_vector(vector);
        return NVME_INVALID_IRQ_VECTOR | NVME_DNR;
    }
    if (unlikely(!(NVME_CQ_FLAGS_PC(qflags)))) {
        trace_pci_nvme_err_invalid_create_cq_qflags(NVME_CQ_FLAGS_PC(qflags));
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    cq = g_malloc0(sizeof(*cq));
    nvme_init_cq(cq, n, prp1, cqid, vector, qsize + 1,
                 NVME_CQ_FLAGS_IEN(qflags));

    if (cq->irq_enabled) {
        ret = vhost_kernel_nvme_add_kvm_msi_virq(n, cq);
        if (ret < 0) {
            error_report("vhost-user-nvme: add kvm msix virq failed");
            return -1;
        }
        ret = vhost_dev_nvme_set_guest_notifier(&n->dev,
                                                &cq->guest_notifier,
                                                cq->cqid);
        if (ret < 0) {
            error_report("vhost-user-nvme: set guest notifier failed");
            return -1;
        }
    }
    if (cq->irq_enabled && !n->vector_poll_started) {
        n->vector_poll_started = true;
        if (msix_set_vector_notifiers(&n->parent_obj,
                                      vhost_nvme_vector_unmask,
                                      vhost_nvme_vector_mask,
                                      vhost_nvme_vector_poll)) {
            error_report("vhost-user-nvme: msix_set_vector_notifiers failed");
            return -1;
        }
    }
    nvme_set_eventfd(n, &cq->guest_notifier, cq->cqid, &cq->vector, &cq->irq_enabled);

    /*
     * It is only required to set qs_created when creating a completion queue;
     * creating a submission queue without a matching completion queue will
     * fail.
     */
    n->qs_created = true;
    return NVME_SUCCESS;
}

static uint16_t nvme_admin_cmd(NvmeCtrl *n, NvmeRequest *req)
{
    trace_pci_nvme_admin_cmd(nvme_cid(req), nvme_sqid(req), req->cmd.opcode,
                             nvme_adm_opc_str(req->cmd.opcode));

    switch (req->cmd.opcode) {
    case NVME_ADM_CMD_DELETE_SQ:
        return nvme_del_sq(n, req);
    case NVME_ADM_CMD_CREATE_SQ:
        return nvme_create_sq(n, req);
    case NVME_ADM_CMD_GET_LOG_PAGE:
        return nvme_get_log(n, req);
    case NVME_ADM_CMD_DELETE_CQ:
        return nvme_del_cq(n, req);
    case NVME_ADM_CMD_CREATE_CQ:
        return nvme_create_cq(n, req);
    case NVME_ADM_CMD_IDENTIFY:
        return nvme_identify(n, req);
    case NVME_ADM_CMD_ABORT:
        return nvme_abort(n, req);
    case NVME_ADM_CMD_SET_FEATURES:
        return nvme_set_feature(n, req);
    case NVME_ADM_CMD_GET_FEATURES:
        return nvme_get_feature(n, req);
    case NVME_ADM_CMD_ASYNC_EV_REQ:
        return nvme_aer(n, req);
    default:
        trace_pci_nvme_err_invalid_admin_opc(req->cmd.opcode);
        return NVME_INVALID_OPCODE | NVME_DNR;
    }
}

static void nvme_process_sq(void *opaque)
{
    NvmeSQueue *sq = opaque;
    NvmeCtrl *n = sq->ctrl;
    NvmeCQueue *cq = n->cq[sq->cqid];

    uint16_t status;
    hwaddr addr;
    NvmeCmd cmd;
    NvmeRequest *req;

    while (!(nvme_sq_empty(sq) || QTAILQ_EMPTY(&sq->req_list))) {
        addr = sq->dma_addr + sq->head * n->sqe_size;
        if (nvme_addr_read(n, addr, (void *)&cmd, sizeof(cmd))) {
            trace_pci_nvme_err_addr_read(addr);
            trace_pci_nvme_err_cfs();
            n->bar.csts = NVME_CSTS_FAILED;
            break;
        }
        nvme_inc_sq_head(sq);

        req = QTAILQ_FIRST(&sq->req_list);
        QTAILQ_REMOVE(&sq->req_list, req, entry);
        QTAILQ_INSERT_TAIL(&sq->out_req_list, req, entry);
        nvme_req_clear(req);
        req->cqe.cid = cmd.cid;
        memcpy(&req->cmd, &cmd, sizeof(NvmeCmd));

        status = sq->sqid ? nvme_io_cmd(n, req) :
            nvme_admin_cmd(n, req);
        if (status != NVME_NO_COMPLETE) {
            req->status = status;
            nvme_enqueue_req_completion(cq, req);
        }
    }
}

/* static int nvme_start_ctrl(NvmeCtrl *n)  //kernel side?!
{
    uint32_t page_bits = NVME_CC_MPS(n->bar.cc) + 12;
    uint32_t page_size = 1 << page_bits;

    if (unlikely(n->cq[0])) {
        trace_pci_nvme_err_startfail_cq();
        return -1;
    }
    if (unlikely(n->sq[0])) {
        trace_pci_nvme_err_startfail_sq();
        return -1;
    }
    if (unlikely(!n->bar.asq)) {
        trace_pci_nvme_err_startfail_nbarasq();
        return -1;
    }
    if (unlikely(!n->bar.acq)) {
        trace_pci_nvme_err_startfail_nbaracq();
        return -1;
    }
    if (unlikely(n->bar.asq & (page_size - 1))) {
        trace_pci_nvme_err_startfail_asq_misaligned(n->bar.asq);
        return -1;
    }
    if (unlikely(n->bar.acq & (page_size - 1))) {
        trace_pci_nvme_err_startfail_acq_misaligned(n->bar.acq);
        return -1;
    }
    if (unlikely(!(NVME_CAP_CSS(n->bar.cap) & (1 << NVME_CC_CSS(n->bar.cc))))) {
        trace_pci_nvme_err_startfail_css(NVME_CC_CSS(n->bar.cc));
        return -1;
    }
    if (unlikely(NVME_CC_MPS(n->bar.cc) <
                 NVME_CAP_MPSMIN(n->bar.cap))) {
        trace_pci_nvme_err_startfail_page_too_small(
                    NVME_CC_MPS(n->bar.cc),
                    NVME_CAP_MPSMIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_MPS(n->bar.cc) >
                 NVME_CAP_MPSMAX(n->bar.cap))) {
        trace_pci_nvme_err_startfail_page_too_large(
                    NVME_CC_MPS(n->bar.cc),
                    NVME_CAP_MPSMAX(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOCQES(n->bar.cc) <
                 NVME_CTRL_CQES_MIN(n->id_ctrl.cqes))) {
        trace_pci_nvme_err_startfail_cqent_too_small(
                    NVME_CC_IOCQES(n->bar.cc),
                    NVME_CTRL_CQES_MIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOCQES(n->bar.cc) >
                 NVME_CTRL_CQES_MAX(n->id_ctrl.cqes))) {
        trace_pci_nvme_err_startfail_cqent_too_large(
                    NVME_CC_IOCQES(n->bar.cc),
                    NVME_CTRL_CQES_MAX(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOSQES(n->bar.cc) <
                 NVME_CTRL_SQES_MIN(n->id_ctrl.sqes))) {
        trace_pci_nvme_err_startfail_sqent_too_small(
                    NVME_CC_IOSQES(n->bar.cc),
                    NVME_CTRL_SQES_MIN(n->bar.cap));
        return -1;
    }
    if (unlikely(NVME_CC_IOSQES(n->bar.cc) >
                 NVME_CTRL_SQES_MAX(n->id_ctrl.sqes))) {
        trace_pci_nvme_err_startfail_sqent_too_large(
                    NVME_CC_IOSQES(n->bar.cc),
                    NVME_CTRL_SQES_MAX(n->bar.cap));
        return -1;
    }
    if (unlikely(!NVME_AQA_ASQS(n->bar.aqa))) {
        trace_pci_nvme_err_startfail_asqent_sz_zero();
        return -1;
    }
    if (unlikely(!NVME_AQA_ACQS(n->bar.aqa))) {
        trace_pci_nvme_err_startfail_acqent_sz_zero();
        return -1;
    }

    n->page_bits = page_bits;
    n->page_size = page_size;
    n->max_prp_ents = n->page_size / sizeof(uint64_t);
    n->cqe_size = 1 << NVME_CC_IOCQES(n->bar.cc);
    n->sqe_size = 1 << NVME_CC_IOSQES(n->bar.cc);
    nvme_init_cq(&n->admin_cq, n, n->bar.acq, 0, 0,
                 NVME_AQA_ACQS(n->bar.aqa) + 1, 1);
    nvme_init_sq(&n->admin_sq, n, n->bar.asq, 0, 0,
                 NVME_AQA_ASQS(n->bar.aqa) + 1);

    nvme_set_timestamp(n, 0ULL);

    QTAILQ_INIT(&n->aer_queue);

    return 0;
} */

static void nvme_write_bar(NvmeCtrl *n, hwaddr offset, uint64_t data,
                           unsigned size)
{
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct nvmet_vhost_bar nvmet_bar;
    int ret;

    memset(&nvmet_bar, 0, sizeof(nvmet_bar));
    nvmet_bar.type = VHOST_NVME_BAR_WRITE;
    nvmet_bar.offset = offset;
    nvmet_bar.size = size;
    nvmet_bar.val = data;
    ret = vhost_ops->vhost_nvme_bar(&n->dev, &nvmet_bar);
    if (ret < 0) {
        error_report("nvme_write_bar error = %d", ret);
    }
}

static uint64_t nvme_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;
    uint64_t val = 0;
    const VhostOps *vhost_ops = n->dev.vhost_ops;
    struct nvmet_vhost_bar nvmet_bar;

    if (unlikely(addr & (sizeof(uint32_t) - 1))) {
        error_report("MMIO read not 32-bit aligned, offset=0x%"PRIx64"", addr);
        // should RAZ, fall through for now
    } else if (unlikely(size < sizeof(uint32_t))) {
        error_report("MMIO read smaller than 32-bits,"
                     " offset=0x%"PRIx64"", addr);
        // should RAZ, fall through for now
    }
    memset(&nvmet_bar, 0, sizeof(nvmet_bar));
    nvmet_bar.type = VHOST_NVME_BAR_READ;
    nvmet_bar.offset = addr;
    nvmet_bar.size = size;
    val = vhost_ops->vhost_nvme_bar(&n->dev, &nvmet_bar);

    return val;
}

static void nvme_mmio_write(void *opaque, hwaddr addr, uint64_t data,
                            unsigned size)
{
    NvmeCtrl *n = (NvmeCtrl *)opaque;

    trace_pci_nvme_mmio_write(addr, data);

    nvme_write_bar(n, addr, data, size);
    if (addr > sizeof(n->bar)) {
        nvme_process_db(n, addr, data);
    }
}

static const MemoryRegionOps nvme_mmio_ops = {
    .read = nvme_mmio_read,
    .write = nvme_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 2,
        .max_access_size = 8,
    },
};

static void nvme_init_pci(NvmeCtrl *n, PCIDevice *pci_dev, Error **errp)
{
    uint8_t *pci_conf = pci_dev->config;

    pci_conf[PCI_INTERRUPT_PIN] = 1;
    pci_config_set_prog_interface(pci_conf, 0x2);

    if (n->params.use_intel_id) {
        pci_config_set_vendor_id(pci_conf, PCI_VENDOR_ID_INTEL);
        pci_config_set_device_id(pci_conf, 0x5845);
    } else {
        pci_config_set_vendor_id(pci_conf, PCI_VENDOR_ID_REDHAT);
        pci_config_set_device_id(pci_conf, PCI_DEVICE_ID_REDHAT_NVME);
    }

    pci_config_set_class(pci_conf, PCI_CLASS_STORAGE_EXPRESS);
    pcie_endpoint_cap_init(pci_dev, 0x80);

    memory_region_init_io(&n->iomem, OBJECT(n), &nvme_mmio_ops, n, "nvme",
                          n->reg_size);
    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64, &n->iomem);
    if (msix_init_exclusive_bar(pci_dev, n->params.msix_qsize, 4, errp)) {
        return;
    }

    if (n->params.cmb_size_mb) {
        nvme_init_cmb(n, pci_dev);
    } else if (n->pmrdev) {
        nvme_init_pmr(n, pci_dev);
    }
}

static void nvme_realize(PCIDevice *pci_dev, Error **errp)
{
    NvmeCtrl *n = NVME_VHOST(pci_dev);
    NvmeNamespace *ns;
    Error *local_err = NULL;
    int vhostfd = -1;
    int ret;

    nvme_check_constraints(n, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    if (n->params.vhostfd) {
        vhostfd = monitor_fd_param(monitor_cur(), n->params.vhostfd, errp);
        if (vhostfd == -1) {
            error_prepend(errp, "vhost-kernel-nvme: unable to parse vhostfd: ");
            return;
        }
    } else {
        vhostfd = open("/dev/vhost-nvme", O_RDWR);
        if (vhostfd < 0) {
            error_setg(errp, "vhost-kernel-nvme: open vhost char device failed: %s",
                       strerror(errno));
            return;
        }
    }

    if (vhost_dev_nvme_init(&n->dev, (void *)(uintptr_t)vhostfd,
                            VHOST_BACKEND_TYPE_KERNEL, 0) < 0) {
        error_setg(errp, "vhost-kernel-nvme: vhost_dev_init failed");
        return;
    }


    nvme_init_state(n);
    nvme_init_pci(n, pci_dev, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    nvme_init_ctrl(n, pci_dev);

    ret = vhost_nvme_set_endpoint(n);
    if (ret < 0) {
        error_setg(errp, "vhost-kernel-nvme: set endpoint ioctl failed");
        return;
    }

    /* setup a namespace if the controller drive property was given */
    if (n->namespace.blkconf.blk) {
        ns = &n->namespace;
        ns->params.nsid = 1;

        if (nvme_ns_setup(n, ns, errp)) {
            return;
        }
    }
}

static void nvme_exit(PCIDevice *pci_dev)
{
    NvmeCtrl *n = NVME_VHOST(pci_dev);

    vhost_nvme_clear_endpoint(n, 1);
    nvme_clear_ctrl(n);
    g_free(n->cq);
    g_free(n->sq);
    g_free(n->aer_reqs);

    if (n->params.cmb_size_mb) {
        g_free(n->cmbuf);
    }

    if (n->pmrdev) {
        host_memory_backend_set_mapped(n->pmrdev, false);
    }
    msix_uninit_exclusive_bar(pci_dev);
}

static Property nvme_props[] = {
    DEFINE_PROP_STRING("vhostfd", NvmeCtrl, params.vhostfd),
    DEFINE_BLOCK_PROPERTIES(NvmeCtrl, namespace.blkconf),
    DEFINE_PROP_LINK("pmrdev", NvmeCtrl, pmrdev, TYPE_MEMORY_BACKEND,
                     HostMemoryBackend *),
    DEFINE_PROP_STRING("serial", NvmeCtrl, params.serial),
    DEFINE_PROP_UINT32("cmb_size_mb", NvmeCtrl, params.cmb_size_mb, 0),
    DEFINE_PROP_UINT32("num_queues", NvmeCtrl, params.num_queues, 0),
    DEFINE_PROP_UINT32("max_ioqpairs", NvmeCtrl, params.max_ioqpairs, 64),
    DEFINE_PROP_UINT16("msix_qsize", NvmeCtrl, params.msix_qsize, 65),
    DEFINE_PROP_UINT8("aerl", NvmeCtrl, params.aerl, 3),
    DEFINE_PROP_UINT32("aer_max_queued", NvmeCtrl, params.aer_max_queued, 64),
    DEFINE_PROP_UINT8("mdts", NvmeCtrl, params.mdts, 7),
    DEFINE_PROP_BOOL("use-intel-id", NvmeCtrl, params.use_intel_id, false),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription nvme_vmstate = {
    .name = "nvme",
    .unmigratable = 1,
};

static void nvme_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    PCIDeviceClass *pc = PCI_DEVICE_CLASS(oc);

    pc->realize = nvme_realize;
    pc->exit = nvme_exit;
    pc->class_id = PCI_CLASS_STORAGE_EXPRESS;
    pc->vendor_id = PCI_VENDOR_ID_INTEL;
    pc->device_id = 0x5845;
    pc->revision = 2;

    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    dc->desc = "Non-Volatile Memory Express";
    device_class_set_props(dc, nvme_props);
    dc->vmsd = &nvme_vmstate;
}

static void nvme_instance_init(Object *obj)
{
    NvmeCtrl *s = NVME_VHOST(obj);

    if (s->namespace.blkconf.blk) {
        device_add_bootindex_property(obj, &s->namespace.blkconf.bootindex,
                                      "bootindex", "/namespace@1,0",
                                      DEVICE(obj));
    }
}

static const TypeInfo nvme_info = {
    .name          = TYPE_VHOST_NVME,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(NvmeCtrl),
    .instance_init = nvme_instance_init,
    .class_init    = nvme_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { }
    },
};

static void nvme_register_types(void)
{
    type_register_static(&nvme_info);
}

type_init(nvme_register_types)
