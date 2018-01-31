#ifndef QEMU_MC_RDMA_H
#define QEMU_MC_RDMA_H

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "qemu/cutils.h"
#include "migration/migration.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/sockets.h"
#include "qemu/bitmap.h"

int mc_start_incoming_migration(void);
int mc_start_outgoing_migration(const char *mc_host_port);

int mc_rdma_put_colo_ctrl_buffer(uint32_t size);
ssize_t mc_rdma_get_colo_ctrl_buffer(size_t size);
uint8_t *mc_rdma_get_colo_ctrl_buffer_ptr(void);

int mc_rdma_load_hook(QEMUFile *f, void *opaque, uint64_t flags, void *data);
int mc_rdma_registration_start(QEMUFile *f, void *opaque, uint64_t flags, void *data);
int mc_rdma_registration_stop(QEMUFile *f, void *opaque, uint64_t flags, void *data);
size_t mc_rdma_save_page(QEMUFile *f, void *opaque, ram_addr_t block_offset, ram_addr_t offset, size_t size, uint64_t *bytes_sent);

#endif /* QEMU_MC_RDMA_H */
