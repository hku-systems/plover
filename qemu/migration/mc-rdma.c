#include <infiniband/verbs.h>

#include "mc-rdma.h"

#define MC_ERROR(errp, fmt, ...) \
    do { \
        fprintf(stderr, "RDMA ERROR: " fmt "\n", ## __VA_ARGS__); \
        if (errp && (*(errp) == NULL)) { \
            error_setg(errp, "RDMA ERROR: " fmt, ## __VA_ARGS__); \
        } \
    } while (0)

#define MC_RDMA_MERGE_MAX (2 * 1024 * 1024)
#define MC_RDMA_SIGNALED_SEND_MAX (MC_RDMA_MERGE_MAX / 4096)

#define MC_RDMA_REG_CHUNK_SHIFT 20

#define MC_RDMA_SEND_INCREMENT 32768

#define MC_RDMA_CONTROL_MAX_BUFFER (512 * 1024 * 516)
#define MC_RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE 4096
#define MC_RDMA_CONTROL_RESERVED_RECV_BUFFER (MC_RDMA_CONTROL_MAX_BUFFER / 2)

#define MC_RDMA_CAPABILITY_PIN_ALL 0x01

#define MC_RDMA_WRID_TYPE_SHIFT  0UL
#define MC_RDMA_WRID_BLOCK_SHIFT 16UL
#define MC_RDMA_WRID_CHUNK_SHIFT 30UL

#define MC_RDMA_WRID_TYPE_MASK \
    ((1UL << MC_RDMA_WRID_BLOCK_SHIFT) - 1UL)

#define MC_RDMA_WRID_BLOCK_MASK \
    (~MC_RDMA_WRID_TYPE_MASK & ((1UL << MC_RDMA_WRID_CHUNK_SHIFT) - 1UL))

#define MC_RDMA_WRID_CHUNK_MASK (~MC_RDMA_WRID_BLOCK_MASK & ~MC_RDMA_WRID_TYPE_MASK)

#define MC_MIGRATION_CAPABILITY_RDMA_PIN_ALL 1

enum {
    MC_RDMA_WRID_NONE = 0,
    MC_RDMA_WRID_RDMA_WRITE = 1,
    MC_RDMA_WRID_SEND_CONTROL = 2000,
    MC_RDMA_WRID_RECV_CONTROL = 4000,
};

static const char *wrid_desc[] = {
    [MC_RDMA_WRID_NONE] = "NONE",
    [MC_RDMA_WRID_RDMA_WRITE] = "WRITE RDMA",
    [MC_RDMA_WRID_SEND_CONTROL] = "CONTROL SEND",
    [MC_RDMA_WRID_RECV_CONTROL] = "CONTROL RECV",
};

enum {
    MC_RDMA_WRID_READY = 0,
    MC_RDMA_WRID_DATA,
    MC_RDMA_WRID_CONTROL,
    MC_RDMA_WRID_MAX,
};

enum {
    MC_RDMA_CONTROL_NONE = 0,
    MC_RDMA_CONTROL_ERROR,
    MC_RDMA_CONTROL_READY,       
    MC_RDMA_CONTROL_QEMU_FILE,      
    MC_RDMA_CONTROL_RAM_BLOCKS_REQUEST, 
    MC_RDMA_CONTROL_RAM_BLOCKS_RESULT, 
    MC_RDMA_CONTROL_COMPRESS,     
    MC_RDMA_CONTROL_REGISTER_REQUEST,  
    MC_RDMA_CONTROL_REGISTER_RESULT,  
    MC_RDMA_CONTROL_REGISTER_FINISHED, 
    MC_RDMA_CONTROL_UNREGISTER_REQUEST, 
    MC_RDMA_CONTROL_UNREGISTER_FINISHED, 
};

static const char *control_desc[] = {
    [MC_RDMA_CONTROL_NONE] = "NONE",
    [MC_RDMA_CONTROL_ERROR] = "MC_ERROR",
    [MC_RDMA_CONTROL_READY] = "READY",
    [MC_RDMA_CONTROL_QEMU_FILE] = "QEMU FILE",
    [MC_RDMA_CONTROL_RAM_BLOCKS_REQUEST] = "RAM BLOCKS REQUEST",
    [MC_RDMA_CONTROL_RAM_BLOCKS_RESULT] = "RAM BLOCKS RESULT",
    [MC_RDMA_CONTROL_COMPRESS] = "COMPRESS",
    [MC_RDMA_CONTROL_REGISTER_REQUEST] = "REGISTER REQUEST",
    [MC_RDMA_CONTROL_REGISTER_RESULT] = "REGISTER RESULT",
    [MC_RDMA_CONTROL_REGISTER_FINISHED] = "REGISTER FINISHED",
    [MC_RDMA_CONTROL_UNREGISTER_REQUEST] = "UNREGISTER REQUEST",
    [MC_RDMA_CONTROL_UNREGISTER_FINISHED] = "UNREGISTER FINISHED",
};

typedef struct {
    uint8_t  control[MC_RDMA_CONTROL_MAX_BUFFER];
    struct   ibv_mr *control_mr;
    size_t   control_len;
    uint8_t *control_curr;
} MC_RDMAWorkRequestData;

typedef struct MC_RDMALocalBlock {
    char          *block_name;
    uint8_t       *local_host_addr; 
    uint64_t       remote_host_addr; 
    uint64_t       offset;
    uint64_t       length;
    struct         ibv_mr **pmr;   
    struct         ibv_mr *mr;   
    uint32_t      *remote_keys; 
    uint32_t       remote_rkey;  
    int            index;  
    unsigned int   src_index; 
    bool           is_ram_block;
    int            nb_chunks;
    unsigned long *transit_bitmap;
    unsigned long *unregister_bitmap;
} MC_RDMALocalBlock;

typedef struct QEMU_PACKED MC_RDMADestBlock {
    uint64_t remote_host_addr;
    uint64_t offset;
    uint64_t length;
    uint32_t remote_rkey;
    uint32_t padding;
} MC_RDMADestBlock;

static uint64_t mc_htonll(uint64_t v)
{
    union { uint32_t lv[2]; uint64_t llv; } u;
    u.lv[0] = htonl(v >> 32);
    u.lv[1] = htonl(v & 0xFFFFFFFFULL);
    return u.llv;
}

static uint64_t mc_ntohll(uint64_t v) {
    union { uint32_t lv[2]; uint64_t llv; } u;
    u.llv = v;
    return ((uint64_t)ntohl(u.lv[0]) << 32) | (uint64_t) ntohl(u.lv[1]);
}

static void mc_dest_block_to_network(MC_RDMADestBlock *db)
{
    db->remote_host_addr = mc_htonll(db->remote_host_addr);
    db->offset = mc_htonll(db->offset);
    db->length = mc_htonll(db->length);
    db->remote_rkey = htonl(db->remote_rkey);
}

static void mc_network_to_dest_block(MC_RDMADestBlock *db)
{
    db->remote_host_addr = mc_ntohll(db->remote_host_addr);
    db->offset = mc_ntohll(db->offset);
    db->length = mc_ntohll(db->length);
    db->remote_rkey = ntohl(db->remote_rkey);
}

typedef struct MC_RDMALocalBlocks {
    int nb_blocks;
    bool     init;             /* main memory init complete */
    MC_RDMALocalBlock *block;
} MC_RDMALocalBlocks;

struct cm_con_data_t
{
    uint32_t qp_num;
    uint16_t lid;
    uint8_t gid[16];
    uint32_t capability_flags;
} __attribute__ ((packed));

typedef struct MC_RDMAContext {
    struct ibv_context *ib_ctx;
    struct ibv_port_attr port_attr;
    struct ibv_device_attr device_attr;
    struct cm_con_data_t remote_props;
    int sock;

    MC_RDMAWorkRequestData wr_data[MC_RDMA_WRID_MAX];
    MC_RDMAWorkRequestData colo_ctrl_wr_data;

    int control_ready_expected;

    int nb_sent;

    uint64_t current_addr;
    uint64_t current_length;

    int current_index;

    int current_chunk;

    bool pin_all;

    bool connected;

    struct ibv_qp *qp;
    struct ibv_pd *pd;
    struct ibv_cq *cq;

    struct ibv_qp *colo_ctrl_qp;
    struct ibv_cq *colo_ctrl_cq;

    int error_state;
    int error_reported;

    MC_RDMALocalBlocks local_ram_blocks;
    MC_RDMADestBlock  *dest_blocks;

    unsigned int    next_src_index;

    int migration_started_on_destination;

    int total_registrations;
    int total_writes;

    int unregister_current, unregister_next;
    uint64_t unregistrations[MC_RDMA_SIGNALED_SEND_MAX];

    GHashTable *blockmap;
} MC_RDMAContext;

static MC_RDMAContext *rdma;

typedef struct QEMU_PACKED {
    uint32_t len;     /* Total length of data portion */
    uint32_t type;    /* which control command to perform */
    uint32_t repeat;  /* number of commands in data portion of same type */
    uint32_t padding;
} MC_RDMAControlHeader;

static void mc_control_to_network(MC_RDMAControlHeader *control)
{
    control->type = htonl(control->type);
    control->len = htonl(control->len);
    control->repeat = htonl(control->repeat);
}

static void mc_network_to_control(MC_RDMAControlHeader *control)
{
    control->type = ntohl(control->type);
    control->len = ntohl(control->len);
    control->repeat = ntohl(control->repeat);
}

typedef struct QEMU_PACKED {
    union QEMU_PACKED {
        uint64_t current_addr;
        uint64_t chunk;  
    } key;
    uint32_t current_index; 
    uint32_t padding;
    uint64_t chunks; 
} MC_RDMARegister;

static void mc_register_to_network(MC_RDMAContext *rdma, MC_RDMARegister *reg)
{
    MC_RDMALocalBlock *local_block;
    local_block  = &rdma->local_ram_blocks.block[reg->current_index];

    if (local_block->is_ram_block) {

        reg->key.current_addr -= local_block->offset;
        reg->key.current_addr += rdma->dest_blocks[reg->current_index].offset;
    }
    reg->key.current_addr = mc_htonll(reg->key.current_addr);
    reg->current_index = htonl(reg->current_index);
    reg->chunks = mc_htonll(reg->chunks);
}

static void mc_network_to_register(MC_RDMARegister *reg)
{
    reg->key.current_addr = mc_ntohll(reg->key.current_addr);
    reg->current_index = ntohl(reg->current_index);
    reg->chunks = mc_ntohll(reg->chunks);
}

typedef struct QEMU_PACKED {
    uint32_t value;     /* if zero, we will madvise() */
    uint32_t block_idx; /* which ram block index */
    uint64_t offset;    /* Address in remote ram_addr_t space */
    uint64_t length;    /* length of the chunk */
} MC_RDMACompress;

static void mc_compress_to_network(MC_RDMAContext *rdma, MC_RDMACompress *comp)
{
    comp->value = htonl(comp->value);

    comp->offset -= rdma->local_ram_blocks.block[comp->block_idx].offset;
    comp->offset += rdma->dest_blocks[comp->block_idx].offset;
    comp->block_idx = htonl(comp->block_idx);
    comp->offset = mc_htonll(comp->offset);
    comp->length = mc_htonll(comp->length);
}

static void mc_network_to_compress(MC_RDMACompress *comp)
{
    comp->value = ntohl(comp->value);
    comp->block_idx = ntohl(comp->block_idx);
    comp->offset = mc_ntohll(comp->offset);
    comp->length = mc_ntohll(comp->length);
}

typedef struct QEMU_PACKED {
    uint32_t rkey;
    uint32_t padding;
    uint64_t host_addr;
} MC_RDMARegisterResult;

static void mc_result_to_network(MC_RDMARegisterResult *result)
{
    result->rkey = htonl(result->rkey);
    result->host_addr = mc_htonll(result->host_addr);
};

static void mc_network_to_result(MC_RDMARegisterResult *result)
{
    result->rkey = ntohl(result->rkey);
    result->host_addr = mc_ntohll(result->host_addr);
};

static int mc_rdma_exchange_send(MC_RDMAContext *rdma, MC_RDMAControlHeader *head,
                                   uint8_t *data, MC_RDMAControlHeader *resp,
                                   int *resp_idx,
                                   int (*callback)(MC_RDMAContext *rdma));


static inline uint64_t mc_ram_chunk_index(const uint8_t *start,
                                       const uint8_t *host)
{
    return ((uintptr_t) host - (uintptr_t) start) >> MC_RDMA_REG_CHUNK_SHIFT;
}

static inline uint8_t *mc_ram_chunk_start(const MC_RDMALocalBlock *rdma_ram_block,
                                       uint64_t i)
{
    return (uint8_t *)(uintptr_t)(rdma_ram_block->local_host_addr +
                                  (i << MC_RDMA_REG_CHUNK_SHIFT));
}

static inline uint8_t *mc_ram_chunk_end(const MC_RDMALocalBlock *rdma_ram_block,
                                     uint64_t i)
{
    uint8_t *result = mc_ram_chunk_start(rdma_ram_block, i) +
                                         (1UL << MC_RDMA_REG_CHUNK_SHIFT);

    if (result > (rdma_ram_block->local_host_addr + rdma_ram_block->length)) {
        result = rdma_ram_block->local_host_addr + rdma_ram_block->length;
    }

    return result;
}

static int mc_rdma_add_block(MC_RDMAContext *rdma, const char *block_name,
                         void *host_addr,
                         ram_addr_t block_offset, uint64_t length)
{
    MC_RDMALocalBlocks *local = &rdma->local_ram_blocks;
    MC_RDMALocalBlock *block;
    MC_RDMALocalBlock *old = local->block;

    local->block = g_new0(MC_RDMALocalBlock, local->nb_blocks + 1);

    if (local->nb_blocks) {
        int x;

        if (rdma->blockmap) {
            for (x = 0; x < local->nb_blocks; x++) {
                g_hash_table_remove(rdma->blockmap,
                                    (void *)(uintptr_t)old[x].offset);
                g_hash_table_insert(rdma->blockmap,
                                    (void *)(uintptr_t)old[x].offset,
                                    &local->block[x]);
            }
        }
        memcpy(local->block, old, sizeof(MC_RDMALocalBlock) * local->nb_blocks);
        g_free(old);
    }

    block = &local->block[local->nb_blocks];

    block->block_name = g_strdup(block_name);
    block->local_host_addr = host_addr;
    block->offset = block_offset;
    block->length = length;
    block->index = local->nb_blocks;
    block->src_index = ~0U; /* Filled in by the receipt of the block list */
    block->nb_chunks = mc_ram_chunk_index(host_addr, host_addr + length) + 1UL;
    block->transit_bitmap = bitmap_new(block->nb_chunks);
    bitmap_clear(block->transit_bitmap, 0, block->nb_chunks);
    block->unregister_bitmap = bitmap_new(block->nb_chunks);
    bitmap_clear(block->unregister_bitmap, 0, block->nb_chunks);
    block->remote_keys = g_new0(uint32_t, block->nb_chunks);

    block->is_ram_block = local->init ? false : true;

    if (rdma->blockmap) {
        g_hash_table_insert(rdma->blockmap, (void *)(uintptr_t)block_offset, block);
    }

    local->nb_blocks++;

    return 0;
}

static int mc_rdma_init_one_block(const char *block_name, void *host_addr,
    ram_addr_t block_offset, ram_addr_t length, void *opaque)
{
    return mc_rdma_add_block(opaque, block_name, host_addr, block_offset, length);
}

static int mc_rdma_init_ram_blocks(MC_RDMAContext *rdma)
{
    MC_RDMALocalBlocks *local = &rdma->local_ram_blocks;

    assert(rdma->blockmap == NULL);
    memset(local, 0, sizeof *local);
    qemu_ram_foreach_block(mc_rdma_init_one_block, rdma);

    rdma->dest_blocks = g_new0(MC_RDMADestBlock,
                               rdma->local_ram_blocks.nb_blocks);
    local->init = true;
    return 0;
}

static int mc_rdma_reg_whole_ram_blocks(MC_RDMAContext *rdma)
{
    int i;
    MC_RDMALocalBlocks *local = &rdma->local_ram_blocks;

    for (i = 0; i < local->nb_blocks; i++) {
        local->block[i].mr =
            ibv_reg_mr(rdma->pd,
                    local->block[i].local_host_addr,
                    local->block[i].length,
                    IBV_ACCESS_LOCAL_WRITE |
                    IBV_ACCESS_REMOTE_WRITE
                    );
        if (!local->block[i].mr) {
            perror("Failed to register local dest ram block!\n");
            break;
        }
        rdma->total_registrations++;
    }

    if (i >= local->nb_blocks) {
        return 0;
    }

    for (i--; i >= 0; i--) {
        ibv_dereg_mr(local->block[i].mr);
        rdma->total_registrations--;
    }

    return -1;

}

static int mc_rdma_search_ram_block(MC_RDMAContext *rdma,
                                      uintptr_t block_offset,
                                      uint64_t offset,
                                      uint64_t length,
                                      uint64_t *block_index,
                                      uint64_t *chunk_index)
{
    uint64_t current_addr = block_offset + offset;
    MC_RDMALocalBlock *block = g_hash_table_lookup(rdma->blockmap,
                                                (void *) block_offset);
    assert(block);
    assert(current_addr >= block->offset);
    assert((current_addr + length) <= (block->offset + block->length));

    *block_index = block->index;
    *chunk_index = mc_ram_chunk_index(block->local_host_addr,
                block->local_host_addr + (current_addr - block->offset));

    return 0;
}

/*
 * Register a chunk with IB. If the chunk was already registered
 * previously, then skip.
 *
 * Also return the keys associated with the registration needed
 * to perform the actual RDMA operation.
 */
static int mc_rdma_register_and_get_keys(MC_RDMAContext *rdma,
        MC_RDMALocalBlock *block, uintptr_t host_addr,
        uint32_t *lkey, uint32_t *rkey, int chunk,
        uint8_t *chunk_start, uint8_t *chunk_end)
{
    if (block->mr) {
        if (lkey) {
            *lkey = block->mr->lkey;
        }
        if (rkey) {
            *rkey = block->mr->rkey;
        }
        return 0;
    }

    if (!block->pmr) {
        block->pmr = g_new0(struct ibv_mr *, block->nb_chunks);
    }

    if (!block->pmr[chunk]) {
        uint64_t len = chunk_end - chunk_start;

        block->pmr[chunk] = ibv_reg_mr(rdma->pd,
                chunk_start, len,
                (rkey ? (IBV_ACCESS_LOCAL_WRITE |
                        IBV_ACCESS_REMOTE_WRITE) : 0));

        if (!block->pmr[chunk]) {
            perror("Failed to register chunk!");
            fprintf(stderr, "Chunk details: block: %d chunk index %d"
                            " start %" PRIuPTR " end %" PRIuPTR
                            " host %" PRIuPTR
                            " local %" PRIuPTR " registrations: %d\n",
                            block->index, chunk, (uintptr_t)chunk_start,
                            (uintptr_t)chunk_end, host_addr,
                            (uintptr_t)block->local_host_addr,
                            rdma->total_registrations);
            return -1;
        }
        rdma->total_registrations++;
    }

    if (lkey) {
        *lkey = block->pmr[chunk]->lkey;
    }
    if (rkey) {
        *rkey = block->pmr[chunk]->rkey;
    }
    return 0;
}

static int mc_rdma_reg_control(MC_RDMAContext *rdma, int idx)
{
    rdma->wr_data[idx].control_mr = ibv_reg_mr(rdma->pd,
            rdma->wr_data[idx].control, MC_RDMA_CONTROL_MAX_BUFFER,
            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
    if (rdma->wr_data[idx].control_mr) {
        rdma->total_registrations++;
        return 0;
    }

    error_report("mc_rdma_reg_control failed");
    return -1;
}

//#define RDMA_UNREGISTRATION_EXAMPLE

static int mc_rdma_unregister_waiting(MC_RDMAContext *rdma)
{
    while (rdma->unregistrations[rdma->unregister_current]) {
        int ret;
        uint64_t wr_id = rdma->unregistrations[rdma->unregister_current];
        uint64_t chunk =
            (wr_id & MC_RDMA_WRID_CHUNK_MASK) >> MC_RDMA_WRID_CHUNK_SHIFT;
        uint64_t index =
            (wr_id & MC_RDMA_WRID_BLOCK_MASK) >> MC_RDMA_WRID_BLOCK_SHIFT;
        MC_RDMALocalBlock *block =
            &(rdma->local_ram_blocks.block[index]);
        MC_RDMARegister reg = { .current_index = index };
        MC_RDMAControlHeader resp = { .type = MC_RDMA_CONTROL_UNREGISTER_FINISHED,
                                 };
        MC_RDMAControlHeader head = { .len = sizeof(MC_RDMARegister),
                                   .type = MC_RDMA_CONTROL_UNREGISTER_REQUEST,
                                   .repeat = 1,
                                 };

        rdma->unregistrations[rdma->unregister_current] = 0;
        rdma->unregister_current++;

        if (rdma->unregister_current == MC_RDMA_SIGNALED_SEND_MAX) {
            rdma->unregister_current = 0;
        }


        /*
         * Unregistration is speculative (because migration is single-threaded
         * and we cannot break the protocol's inifinband message ordering).
         * Thus, if the memory is currently being used for transmission,
         * then abort the attempt to unregister and try again
         * later the next time a completion is received for this memory.
         */
        clear_bit(chunk, block->unregister_bitmap);

        if (test_bit(chunk, block->transit_bitmap)) {
            continue;
        }

        ret = ibv_dereg_mr(block->pmr[chunk]);
        block->pmr[chunk] = NULL;
        block->remote_keys[chunk] = 0;

        if (ret != 0) {
            perror("unregistration chunk failed");
            return -ret;
        }
        rdma->total_registrations--;

        reg.key.chunk = chunk;
        mc_register_to_network(rdma, &reg);
        ret = mc_rdma_exchange_send(rdma, &head, (uint8_t *) &reg,
                                &resp, NULL, NULL);
        if (ret < 0) {
            return ret;
        }

    }

    return 0;
}

static uint64_t mc_rdma_make_wrid(uint64_t wr_id, uint64_t index,
                                         uint64_t chunk)
{
    uint64_t result = wr_id & MC_RDMA_WRID_TYPE_MASK;

    result |= (index << MC_RDMA_WRID_BLOCK_SHIFT);
    result |= (chunk << MC_RDMA_WRID_CHUNK_SHIFT);

    return result;
}

static void mc_rdma_signal_unregister(MC_RDMAContext *rdma, uint64_t index,
                                        uint64_t chunk, uint64_t wr_id)
{
    if (rdma->unregistrations[rdma->unregister_next] != 0) {
        error_report("rdma migration: queue is full");
    } else {
        MC_RDMALocalBlock *block = &(rdma->local_ram_blocks.block[index]);

        if (!test_and_set_bit(chunk, block->unregister_bitmap)) {

            rdma->unregistrations[rdma->unregister_next++] =
                    mc_rdma_make_wrid(wr_id, index, chunk);

            if (rdma->unregister_next == MC_RDMA_SIGNALED_SEND_MAX) {
                rdma->unregister_next = 0;
            }
        } else {
        }
    }
}

static uint64_t mc_rdma_poll(MC_RDMAContext *rdma, uint64_t *wr_id_out,
                               uint32_t *byte_len)
{
    int ret;
    struct ibv_wc wc;
    uint64_t wr_id;

    ret = ibv_poll_cq(rdma->cq, 1, &wc);

    if (!ret) {
        *wr_id_out = MC_RDMA_WRID_NONE;
        return 0;
    }

    if (ret < 0) {
        error_report("ibv_poll_cq return %d", ret);
        return ret;
    }

    wr_id = wc.wr_id & MC_RDMA_WRID_TYPE_MASK;

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "ibv_poll_cq wc.status=%d %s!\n",
                        wc.status, ibv_wc_status_str(wc.status));
        fprintf(stderr, "ibv_poll_cq wrid=%s!\n", wrid_desc[wr_id]);

        return -1;
    }

    if (rdma->control_ready_expected &&
        (wr_id >= MC_RDMA_WRID_RECV_CONTROL)) {

        rdma->control_ready_expected = 0;
    }

    if (wr_id == MC_RDMA_WRID_RDMA_WRITE) {
        uint64_t chunk =
            (wc.wr_id & MC_RDMA_WRID_CHUNK_MASK) >> MC_RDMA_WRID_CHUNK_SHIFT;
        uint64_t index =
            (wc.wr_id & MC_RDMA_WRID_BLOCK_MASK) >> MC_RDMA_WRID_BLOCK_SHIFT;
        MC_RDMALocalBlock *block = &(rdma->local_ram_blocks.block[index]);

        clear_bit(chunk, block->transit_bitmap);

        if (rdma->nb_sent > 0) {
            rdma->nb_sent--;
        }

        if (!rdma->pin_all) {
#ifdef RDMA_UNREGISTRATION_EXAMPLE
            mc_rdma_signal_unregister(rdma, index, chunk, wc.wr_id);
#endif
        }
    } else {
    }

    *wr_id_out = wc.wr_id;
    if (byte_len) {
        *byte_len = wc.byte_len;
    }

    return  0;
}

/*
 * Block until the next work request has completed.
 *
 * First poll to see if a work request has already completed,
 * otherwise block.
 *
 * If we encounter completed work requests for IDs other than
 * the one we're interested in, then that's generally an MC_ERROR.
 *
 * The only exception is actual RDMA Write completions. These
 * completions only need to be recorded, but do not actually
 * need further processing.
 */
static int mc_rdma_block_for_wrid(MC_RDMAContext *rdma, int wrid_requested,
                                    uint32_t *byte_len)
{
    int ret = 0;
    uint64_t wr_id = MC_RDMA_WRID_NONE, wr_id_in;

    /* poll cq first */
    while (wr_id != wrid_requested) {
        ret = mc_rdma_poll(rdma, &wr_id_in, byte_len);
        if (ret < 0) {
            return ret;
        }

        wr_id = wr_id_in & MC_RDMA_WRID_TYPE_MASK;

        if (wr_id == MC_RDMA_WRID_NONE) {
            break;
        }
        if (wr_id != wrid_requested) {
        }
    }

    if (wr_id == wrid_requested) {
        return 0;
    }

    while (1) {
        // ibv_get_cq_event() - blocks until gets "event"

        while (wr_id != wrid_requested) {
            ret = mc_rdma_poll(rdma, &wr_id_in, byte_len);
            if (ret < 0) {
                goto err_block_for_wrid;
            }

            wr_id = wr_id_in & MC_RDMA_WRID_TYPE_MASK;

            if (wr_id == MC_RDMA_WRID_NONE) {
                break;
            }
            if (wr_id != wrid_requested) {
            }
        }

        if (wr_id == wrid_requested) {
            goto success_block_for_wrid;
        }
    }

success_block_for_wrid:
    return 0;

err_block_for_wrid:
    return ret;
}

/*
 * Post a SEND message work request for the control channel
 * containing some data and block until the post completes.
 */
static int mc_rdma_post_send_control(MC_RDMAContext *rdma, uint8_t *buf,
                                       MC_RDMAControlHeader *head)
{
    int ret = 0;
    MC_RDMAWorkRequestData *wr = &rdma->wr_data[MC_RDMA_WRID_CONTROL];
    struct ibv_send_wr *bad_wr;
    struct ibv_sge sge = {
                           .addr = (uintptr_t)(wr->control),
                           .length = head->len + sizeof(MC_RDMAControlHeader),
                           .lkey = wr->control_mr->lkey,
                         };
    struct ibv_send_wr send_wr = {
                                   .wr_id = MC_RDMA_WRID_SEND_CONTROL,
                                   .opcode = IBV_WR_SEND,
                                   .send_flags = IBV_SEND_SIGNALED,
                                   .sg_list = &sge,
                                   .num_sge = 1,
                                };

    /*
     * We don't actually need to do a memcpy() in here if we used
     * the "sge" properly, but since we're only sending control messages
     * (not RAM in a performance-critical path), then its OK for now.
     *
     * The copy makes the MC_RDMAControlHeader simpler to manipulate
     * for the time being.
     */
    assert(head->len <= MC_RDMA_CONTROL_MAX_BUFFER - sizeof(*head));
    memcpy(wr->control, head, sizeof(MC_RDMAControlHeader));
    mc_control_to_network((void *) wr->control);

    if (buf) {
        memcpy(wr->control + sizeof(MC_RDMAControlHeader), buf, head->len);
    }


    ret = ibv_post_send(rdma->qp, &send_wr, &bad_wr);

    if (ret > 0) {
        error_report("Failed to use post IB SEND for control");
        return -ret;
    }

    ret = mc_rdma_block_for_wrid(rdma, MC_RDMA_WRID_SEND_CONTROL, NULL);
    if (ret < 0) {
        error_report("rdma migration: send polling control MC_ERROR");
    }

    return ret;
}

/*
 * Post a RECV work request in anticipation of some future receipt
 * of data on the control channel.
 */
static int mc_rdma_post_recv_control(MC_RDMAContext *rdma, int idx)
{
    struct ibv_recv_wr *bad_wr;
    struct ibv_sge sge = {
                            .addr = (uintptr_t)(rdma->wr_data[idx].control),
                            .length = MC_RDMA_CONTROL_MAX_BUFFER,
                            .lkey = rdma->wr_data[idx].control_mr->lkey,
                         };

    struct ibv_recv_wr recv_wr = {
                                    .wr_id = MC_RDMA_WRID_RECV_CONTROL + idx,
                                    .sg_list = &sge,
                                    .num_sge = 1,
                                 };


    if (ibv_post_recv(rdma->qp, &recv_wr, &bad_wr)) {
        return -1;
    }

    return 0;
}



/*
 * Block and wait for a RECV control channel message to arrive.
 */
static int mc_rdma_exchange_get_response(MC_RDMAContext *rdma,
                MC_RDMAControlHeader *head, int expecting, int idx)
{
    uint32_t byte_len;
    int ret = mc_rdma_block_for_wrid(rdma, MC_RDMA_WRID_RECV_CONTROL + idx,
                                       &byte_len);

    if (ret < 0) {
        error_report("rdma migration: recv polling control MC_ERROR!");
        return ret;
    }

    mc_network_to_control((void *) rdma->wr_data[idx].control);
    memcpy(head, rdma->wr_data[idx].control, sizeof(MC_RDMAControlHeader));

    if (expecting == MC_RDMA_CONTROL_NONE) {
    } else if (head->type != expecting || head->type == MC_RDMA_CONTROL_ERROR) {
        error_report("Was expecting a %s (%d) control message"
                ", but got: %s (%d), length: %d",
                control_desc[expecting], expecting,
                control_desc[head->type], head->type, head->len);
        return -EIO;
    }
    if (head->len > MC_RDMA_CONTROL_MAX_BUFFER - sizeof(*head)) {
        error_report("too long length: %d", head->len);
        return -EINVAL;
    }
    if (sizeof(*head) + head->len != byte_len) {
        error_report("Malformed length: %d byte_len %d", head->len, byte_len);
        return -EINVAL;
    }

    return 0;
}

static void mc_rdma_move_header(MC_RDMAContext *rdma, int idx,
                                  MC_RDMAControlHeader *head)
{
    rdma->wr_data[idx].control_len = head->len;
    rdma->wr_data[idx].control_curr =
        rdma->wr_data[idx].control + sizeof(MC_RDMAControlHeader);
}


static int mc_rdma_exchange_send(MC_RDMAContext *rdma, MC_RDMAControlHeader *head,
                                   uint8_t *data, MC_RDMAControlHeader *resp,
                                   int *resp_idx,
                                   int (*callback)(MC_RDMAContext *rdma))
{
    int ret = 0;

    /*
     * Wait until the dest is ready before attempting to deliver the message
     * by waiting for a READY message.
     */
    if (rdma->control_ready_expected) {
        MC_RDMAControlHeader resp;
        ret = mc_rdma_exchange_get_response(rdma,
                                    &resp, MC_RDMA_CONTROL_READY, MC_RDMA_WRID_READY);
        if (ret < 0) {
            return ret;
        }
    }

    /*
     * If the user is expecting a response, post a WR in anticipation of it.
     */
    if (resp) {
        ret = mc_rdma_post_recv_control(rdma, MC_RDMA_WRID_DATA);
        if (ret) {
            error_report("rdma migration: MC_ERROR posting"
                    " extra control recv for anticipated result!");
            return ret;
        }
    }

    /*
     * Post a WR to replace the one we just consumed for the READY message.
     */
    ret = mc_rdma_post_recv_control(rdma, MC_RDMA_WRID_READY);
    if (ret) {
        error_report("rdma migration: MC_ERROR posting first control recv!");
        return ret;
    }

    /*
     * Deliver the control message that was requested.
     */
    ret = mc_rdma_post_send_control(rdma, data, head);

    if (ret < 0) {
        error_report("Failed to send control buffer!");
        return ret;
    }

    /*
     * If we're expecting a response, block and wait for it.
     */
    if (resp) {
        if (callback) {
            ret = callback(rdma);
            if (ret < 0) {
                return ret;
            }
        }

        ret = mc_rdma_exchange_get_response(rdma, resp,
                                              resp->type, MC_RDMA_WRID_DATA);

        if (ret < 0) {
            return ret;
        }

        mc_rdma_move_header(rdma, MC_RDMA_WRID_DATA, resp);
        if (resp_idx) {
            *resp_idx = MC_RDMA_WRID_DATA;
        }
    }

    rdma->control_ready_expected = 1;

    return 0;
}

static int mc_rdma_exchange_recv(MC_RDMAContext *rdma, MC_RDMAControlHeader *head,
                                int expecting)
{
    MC_RDMAControlHeader ready = {
                                .len = 0,
                                .type = MC_RDMA_CONTROL_READY,
                                .repeat = 1,
                              };
    int ret;

    /*
     * Inform the source that we're ready to receive a message.
     */
    ret = mc_rdma_post_send_control(rdma, NULL, &ready);

    if (ret < 0) {
        error_report("Failed to send control buffer!");
        return ret;
    }

    /*
     * Block and wait for the message.
     */
    ret = mc_rdma_exchange_get_response(rdma, head,
                                          expecting, MC_RDMA_WRID_READY);

    if (ret < 0) {
        return ret;
    }

    mc_rdma_move_header(rdma, MC_RDMA_WRID_READY, head);

    /*
     * Post a new RECV work request to replace the one we just consumed.
     */
    ret = mc_rdma_post_recv_control(rdma, MC_RDMA_WRID_READY);
    if (ret) {
        error_report("rdma migration: MC_ERROR posting second control recv!");
        return ret;
    }

    return 0;
}

static int mc_rdma_write_one(QEMUFile *f, MC_RDMAContext *rdma,
                               int current_index, uint64_t current_addr,
                               uint64_t length)
{
    struct ibv_sge sge;
    struct ibv_send_wr send_wr = { 0 };
    struct ibv_send_wr *bad_wr;
    int reg_result_idx, ret, count = 0;
    uint64_t chunk, chunks;
    uint8_t *chunk_start, *chunk_end;
    MC_RDMALocalBlock *block = &(rdma->local_ram_blocks.block[current_index]);
    MC_RDMARegister reg;
    MC_RDMARegisterResult *reg_result;
    MC_RDMAControlHeader resp = { .type = MC_RDMA_CONTROL_REGISTER_RESULT };
    MC_RDMAControlHeader head = { .len = sizeof(MC_RDMARegister),
                               .type = MC_RDMA_CONTROL_REGISTER_REQUEST,
                               .repeat = 1,
                             };

retry:
    sge.addr = (uintptr_t)(block->local_host_addr +
                            (current_addr - block->offset));
    sge.length = length;

    chunk = mc_ram_chunk_index(block->local_host_addr,
                            (uint8_t *)(uintptr_t)sge.addr);
    chunk_start = mc_ram_chunk_start(block, chunk);

    if (block->is_ram_block) {
        chunks = length / (1UL << MC_RDMA_REG_CHUNK_SHIFT);

        if (chunks && ((length % (1UL << MC_RDMA_REG_CHUNK_SHIFT)) == 0)) {
            chunks--;
        }
    } else {
        chunks = block->length / (1UL << MC_RDMA_REG_CHUNK_SHIFT);

        if (chunks && ((block->length % (1UL << MC_RDMA_REG_CHUNK_SHIFT)) == 0)) {
            chunks--;
        }
    }

    chunk_end = mc_ram_chunk_end(block, chunk + chunks);

    if (!rdma->pin_all) {
#ifdef RDMA_UNREGISTRATION_EXAMPLE
        mc_rdma_unregister_waiting(rdma);
#endif
    }

    while (test_bit(chunk, block->transit_bitmap)) {
        (void)count;

        ret = mc_rdma_block_for_wrid(rdma, MC_RDMA_WRID_RDMA_WRITE, NULL);

        if (ret < 0) {
            error_report("Failed to Wait for previous write to complete "
                    "block %d chunk %" PRIu64
                    " current %" PRIu64 " len %" PRIu64 " %d",
                    current_index, chunk, sge.addr, length, rdma->nb_sent);
            return ret;
        }
    }

    if (!rdma->pin_all || !block->is_ram_block) {
        if (!block->remote_keys[chunk]) {
            /*
             * This chunk has not yet been registered, so first check to see
             * if the entire chunk is zero. If so, tell the other size to
             * memset() + madvise() the entire chunk without RDMA.
             */

            if (can_use_buffer_find_nonzero_offset((void *)(uintptr_t)sge.addr,
                                                   length)
                   && buffer_find_nonzero_offset((void *)(uintptr_t)sge.addr,
                                                    length) == length) {
                MC_RDMACompress comp = {
                                        .offset = current_addr,
                                        .value = 0,
                                        .block_idx = current_index,
                                        .length = length,
                                    };

                head.len = sizeof(comp);
                head.type = MC_RDMA_CONTROL_COMPRESS;

                mc_compress_to_network(rdma, &comp);
                ret = mc_rdma_exchange_send(rdma, &head,
                                (uint8_t *) &comp, NULL, NULL, NULL);

                if (ret < 0) {
                    return -EIO;
                }

                acct_update_position(f, sge.length, true);

                return 1;
            }

            /*
             * Otherwise, tell other side to register.
             */
            reg.current_index = current_index;
            if (block->is_ram_block) {
                reg.key.current_addr = current_addr;
            } else {
                reg.key.chunk = chunk;
            }
            reg.chunks = chunks;

            mc_register_to_network(rdma, &reg);
            ret = mc_rdma_exchange_send(rdma, &head, (uint8_t *) &reg,
                                    &resp, &reg_result_idx, NULL);
            if (ret < 0) {
                return ret;
            }

            /* try to overlap this single registration with the one we sent. */
            if (mc_rdma_register_and_get_keys(rdma, block, sge.addr,
                                                &sge.lkey, NULL, chunk,
                                                chunk_start, chunk_end)) {
                error_report("cannot get lkey");
                return -EINVAL;
            }

            reg_result = (MC_RDMARegisterResult *)
                    rdma->wr_data[reg_result_idx].control_curr;

            mc_network_to_result(reg_result);

            block->remote_keys[chunk] = reg_result->rkey;
            block->remote_host_addr = reg_result->host_addr;
        } else {
            /* already registered before */
            if (mc_rdma_register_and_get_keys(rdma, block, sge.addr,
                                                &sge.lkey, NULL, chunk,
                                                chunk_start, chunk_end)) {
                error_report("cannot get lkey!");
                return -EINVAL;
            }
        }

        send_wr.wr.rdma.rkey = block->remote_keys[chunk];
    } else {
        send_wr.wr.rdma.rkey = block->remote_rkey;

        if (mc_rdma_register_and_get_keys(rdma, block, sge.addr,
                                                     &sge.lkey, NULL, chunk,
                                                     chunk_start, chunk_end)) {
            error_report("cannot get lkey!");
            return -EINVAL;
        }
    }

    /*
     * Encode the ram block index and chunk within this wrid.
     * We will use this information at the time of completion
     * to figure out which bitmap to check against and then which
     * chunk in the bitmap to look for.
     */
    send_wr.wr_id = mc_rdma_make_wrid(MC_RDMA_WRID_RDMA_WRITE,
                                        current_index, chunk);

    send_wr.opcode = IBV_WR_RDMA_WRITE;
    send_wr.send_flags = IBV_SEND_SIGNALED;
    send_wr.sg_list = &sge;
    send_wr.num_sge = 1;
    send_wr.wr.rdma.remote_addr = block->remote_host_addr +
                                (current_addr - block->offset);

    /*
     * ibv_post_send() does not return negative MC_ERROR numbers,
     * per the specification they are positive - no idea why.
     */
    ret = ibv_post_send(rdma->qp, &send_wr, &bad_wr);

    if (ret == ENOMEM) {
        ret = mc_rdma_block_for_wrid(rdma, MC_RDMA_WRID_RDMA_WRITE, NULL);
        if (ret < 0) {
            error_report("rdma migration: failed to make "
                         "room in full send queue! %d", ret);
            return ret;
        }

        goto retry;

    } else if (ret > 0) {
        perror("rdma migration: post rdma write failed");
        return -ret;
    }

    set_bit(chunk, block->transit_bitmap);
    acct_update_position(f, sge.length, false);
    rdma->total_writes++;

    return 0;
}


static int mc_rdma_write_flush(QEMUFile *f, MC_RDMAContext *rdma)
{
    int ret;

    if (!rdma->current_length) {
        return 0;
    }

    ret = mc_rdma_write_one(f, rdma,
            rdma->current_index, rdma->current_addr, rdma->current_length);

    if (ret < 0) {
        return ret;
    }

    if (ret == 0) {
        rdma->nb_sent++;
    }

    rdma->current_length = 0;
    rdma->current_addr = 0;

    return 0;
}


static inline int mc_rdma_buffer_mergable(MC_RDMAContext *rdma,
                    uint64_t offset, uint64_t len)
{
    MC_RDMALocalBlock *block;
    uint8_t *host_addr;
    uint8_t *chunk_end;

    if (rdma->current_index < 0) {
        return 0;
    }

    if (rdma->current_chunk < 0) {
        return 0;
    }

    block = &(rdma->local_ram_blocks.block[rdma->current_index]);
    host_addr = block->local_host_addr + (offset - block->offset);
    chunk_end = mc_ram_chunk_end(block, rdma->current_chunk);

    if (rdma->current_length == 0) {
        return 0;
    }

    /*
     * Only merge into chunk sequentially.
     */
    if (offset != (rdma->current_addr + rdma->current_length)) {
        return 0;
    }

    if (offset < block->offset) {
        return 0;
    }

    if ((offset + len) > (block->offset + block->length)) {
        return 0;
    }

    if ((host_addr + len) > chunk_end) {
        return 0;
    }

    return 1;
}

static int mc_rdma_write(QEMUFile *f, MC_RDMAContext *rdma,
                           uint64_t block_offset, uint64_t offset,
                           uint64_t len)
{
    uint64_t current_addr = block_offset + offset;
    uint64_t index = rdma->current_index;
    uint64_t chunk = rdma->current_chunk;
    int ret;

    /* If we cannot merge it, we flush the current buffer first. */
    if (!mc_rdma_buffer_mergable(rdma, current_addr, len)) {
        ret = mc_rdma_write_flush(f, rdma);
        if (ret) {
            return ret;
        }
        rdma->current_length = 0;
        rdma->current_addr = current_addr;

        ret = mc_rdma_search_ram_block(rdma, block_offset,
                                         offset, len, &index, &chunk);
        if (ret) {
            error_report("ram block search failed");
            return ret;
        }
        rdma->current_index = index;
        rdma->current_chunk = chunk;
    }

    /* merge it */
    rdma->current_length += len;

    /* flush it if buffer is too large */
    if (rdma->current_length >= MC_RDMA_MERGE_MAX) {
        return mc_rdma_write_flush(f, rdma);
    }

    return 0;
}

static int mc_rdma_dest_init(MC_RDMAContext *rdma)
{
    int idx;

    for (idx = 0; idx < MC_RDMA_WRID_MAX; idx++) {
        rdma->wr_data[idx].control_len = 0;
        rdma->wr_data[idx].control_curr = NULL;
    }

    return 0;
}

static void *mc_rdma_data_init(void)
{
    MC_RDMAContext *rdma = NULL;

    rdma = g_new0(MC_RDMAContext, 1);
    rdma->current_index = -1;
    rdma->current_chunk = -1;

    return rdma;
}

static int mc_rdma_drain_cq(QEMUFile *f, MC_RDMAContext *rdma)
{
    int ret;

    if (mc_rdma_write_flush(f, rdma) < 0) {
        return -EIO;
    }

    while (rdma->nb_sent) {
        ret = mc_rdma_block_for_wrid(rdma, MC_RDMA_WRID_RDMA_WRITE, NULL);
        if (ret < 0) {
            error_report("rdma migration: complete polling MC_ERROR!");
            return -EIO;
        }
    }

    mc_rdma_unregister_waiting(rdma);

    return 0;
}

size_t mc_rdma_save_page(QEMUFile *f, void *opaque,
                                  ram_addr_t block_offset, ram_addr_t offset,
                                  size_t size, uint64_t *bytes_sent)
{
    int ret;

    qemu_fflush(f);

    if (size > 0) {
        /*
         * Add this page to the current 'chunk'. If the chunk
         * is full, or the page doen't belong to the current chunk,
         * an actual RDMA write will occur and a new chunk will be formed.
         */
        ret = mc_rdma_write(f, rdma, block_offset, offset, size);
        if (ret < 0) {
            error_report("rdma migration: write MC_ERROR! %d", ret);
            goto err;
        }

        /*
         * We always return 1 bytes because the RDMA
         * protocol is completely asynchronous. We do not yet know
         * whether an  identified chunk is zero or not because we're
         * waiting for other pages to potentially be merged with
         * the current chunk. So, we have to call qemu_update_position()
         * later on when the actual write occurs.
         */
        if (bytes_sent) {
            *bytes_sent = 1;
        }
    } else {
        uint64_t index, chunk;

        /* TODO: Change QEMUFileOps prototype to be signed: size_t => long
        if (size < 0) {
            ret = mc_rdma_drain_cq(f, rdma);
            if (ret < 0) {
                fprintf(stderr, "rdma: failed to synchronously drain"
                                " completion queue before unregistration.\n");
                goto err;
            }
        }
        */

        ret = mc_rdma_search_ram_block(rdma, block_offset,
                                         offset, size, &index, &chunk);

        if (ret) {
            error_report("ram block search failed");
            goto err;
        }

        mc_rdma_signal_unregister(rdma, index, chunk, 0);

        /*
         * TODO: Synchronous, guaranteed unregistration (should not occur during
         * fast-path). Otherwise, unregisters will process on the next call to
         * mc_rdma_drain_cq()
        if (size < 0) {
            mc_rdma_unregister_waiting(rdma);
        }
        */
    }

    while (1) {
        uint64_t wr_id, wr_id_in;
        int ret = mc_rdma_poll(rdma, &wr_id_in, NULL);
        if (ret < 0) {
            error_report("rdma migration: polling MC_ERROR! %d", ret);
            goto err;
        }

        wr_id = wr_id_in & MC_RDMA_WRID_TYPE_MASK;

        if (wr_id == MC_RDMA_WRID_NONE) {
            break;
        }
    }

    return RAM_SAVE_CONTROL_DELAYED;
err:
    rdma->error_state = ret;
    return ret;
}

static int mc_dest_ram_sort_func(const void *a, const void *b)
{
    unsigned int a_index = ((const MC_RDMALocalBlock *)a)->src_index;
    unsigned int b_index = ((const MC_RDMALocalBlock *)b)->src_index;

    return (a_index < b_index) ? -1 : (a_index != b_index);
}

static int mc_rdma_registration_handle(QEMUFile *f)
{
    MC_RDMAControlHeader reg_resp = { .len = sizeof(MC_RDMARegisterResult),
                               .type = MC_RDMA_CONTROL_REGISTER_RESULT,
                               .repeat = 0,
                             };
    MC_RDMAControlHeader unreg_resp = { .len = 0,
                               .type = MC_RDMA_CONTROL_UNREGISTER_FINISHED,
                               .repeat = 0,
                             };
    MC_RDMAControlHeader blocks = { .type = MC_RDMA_CONTROL_RAM_BLOCKS_RESULT,
                                 .repeat = 1 };

    MC_RDMALocalBlocks *local = &rdma->local_ram_blocks;
    MC_RDMAControlHeader head;
    MC_RDMARegister *reg, *registers;
    MC_RDMACompress *comp;
    MC_RDMARegisterResult *reg_result;
    static MC_RDMARegisterResult results[MC_RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE];
    MC_RDMALocalBlock *block;
    void *host_addr;
    int ret = 0;
    int idx = 0;
    int count = 0;
    int i = 0;

    do {

        ret = mc_rdma_exchange_recv(rdma, &head, MC_RDMA_CONTROL_NONE);

        if (ret < 0) {
            break;
        }

        if (head.repeat > MC_RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE) {
            error_report("rdma: Too many requests in this message (%d)."
                            "Bailing.", head.repeat);
            ret = -EIO;
            break;
        }

        switch (head.type) {
        case MC_RDMA_CONTROL_COMPRESS:
            comp = (MC_RDMACompress *) rdma->wr_data[idx].control_curr;
            mc_network_to_compress(comp);

            if (comp->block_idx >= rdma->local_ram_blocks.nb_blocks) {
                error_report("rdma: 'compress' bad block index %u (vs %d)",
                             (unsigned int)comp->block_idx,
                             rdma->local_ram_blocks.nb_blocks);
                ret = -EIO;
                goto out;
            }
            block = &(rdma->local_ram_blocks.block[comp->block_idx]);

            host_addr = block->local_host_addr +
                            (comp->offset - block->offset);

            ram_handle_compressed(host_addr, comp->value, comp->length);
            break;

        case MC_RDMA_CONTROL_REGISTER_FINISHED:
            goto out;

        case MC_RDMA_CONTROL_RAM_BLOCKS_REQUEST:

            /* Sort our local RAM Block list so it's the same as the source,
             * we can do this since we've filled in a src_index in the list
             * as we received the RAMBlock list earlier.
             */
            qsort(rdma->local_ram_blocks.block,
                  rdma->local_ram_blocks.nb_blocks,
                  sizeof(MC_RDMALocalBlock), mc_dest_ram_sort_func);
            if (rdma->pin_all) {
                ret = mc_rdma_reg_whole_ram_blocks(rdma);
                if (ret) {
                    error_report("rdma migration: MC_ERROR dest "
                                    "registering ram blocks");
                    goto out;
                }
            }

            /*
             * Dest uses this to prepare to transmit the RAMBlock descriptions
             * to the source VM after connection setup.
             * Both sides use the "remote" structure to communicate and update
             * their "local" descriptions with what was sent.
             */
            for (i = 0; i < local->nb_blocks; i++) {
                rdma->dest_blocks[i].remote_host_addr =
                    (uintptr_t)(local->block[i].local_host_addr);

                if (rdma->pin_all) {
                    rdma->dest_blocks[i].remote_rkey = local->block[i].mr->rkey;
                }

                rdma->dest_blocks[i].offset = local->block[i].offset;
                rdma->dest_blocks[i].length = local->block[i].length;

                mc_dest_block_to_network(&rdma->dest_blocks[i]);
            }

            blocks.len = rdma->local_ram_blocks.nb_blocks
                                                * sizeof(MC_RDMADestBlock);


            ret = mc_rdma_post_send_control(rdma,
                                        (uint8_t *) rdma->dest_blocks, &blocks);

            if (ret < 0) {
                error_report("rdma migration: MC_ERROR sending remote info");
                goto out;
            }

            break;
        case MC_RDMA_CONTROL_REGISTER_REQUEST:

            reg_resp.repeat = head.repeat;
            registers = (MC_RDMARegister *) rdma->wr_data[idx].control_curr;

            for (count = 0; count < head.repeat; count++) {
                uint64_t chunk;
                uint8_t *chunk_start, *chunk_end;

                reg = &registers[count];
                mc_network_to_register(reg);

                reg_result = &results[count];

                if (reg->current_index >= rdma->local_ram_blocks.nb_blocks) {
                    error_report("rdma: 'register' bad block index %u (vs %d)",
                                 (unsigned int)reg->current_index,
                                 rdma->local_ram_blocks.nb_blocks);
                    ret = -ENOENT;
                    goto out;
                }
                block = &(rdma->local_ram_blocks.block[reg->current_index]);
                if (block->is_ram_block) {
                    if (block->offset > reg->key.current_addr) {
                        error_report("rdma: bad register address for block %s"
                            " offset: %" PRIx64 " current_addr: %" PRIx64,
                            block->block_name, block->offset,
                            reg->key.current_addr);
                        ret = -ERANGE;
                        goto out;
                    }
                    host_addr = (block->local_host_addr +
                                (reg->key.current_addr - block->offset));
                    chunk = mc_ram_chunk_index(block->local_host_addr,
                                            (uint8_t *) host_addr);
                } else {
                    chunk = reg->key.chunk;
                    host_addr = block->local_host_addr +
                        (reg->key.chunk * (1UL << MC_RDMA_REG_CHUNK_SHIFT));
                    /* Check for particularly bad chunk value */
                    if (host_addr < (void *)block->local_host_addr) {
                        error_report("rdma: bad chunk for block %s"
                            " chunk: %" PRIx64,
                            block->block_name, reg->key.chunk);
                        ret = -ERANGE;
                        goto out;
                    }
                }
                chunk_start = mc_ram_chunk_start(block, chunk);
                chunk_end = mc_ram_chunk_end(block, chunk + reg->chunks);
                if (mc_rdma_register_and_get_keys(rdma, block,
                            (uintptr_t)host_addr, NULL, &reg_result->rkey,
                            chunk, chunk_start, chunk_end)) {
                    error_report("cannot get rkey");
                    ret = -EINVAL;
                    goto out;
                }

                reg_result->host_addr = (uintptr_t)block->local_host_addr;

                mc_result_to_network(reg_result);
            }

            ret = mc_rdma_post_send_control(rdma,
                            (uint8_t *) results, &reg_resp);

            if (ret < 0) {
                error_report("Failed to send control buffer");
                goto out;
            }
            break;
        case MC_RDMA_CONTROL_UNREGISTER_REQUEST:

            unreg_resp.repeat = head.repeat;
            registers = (MC_RDMARegister *) rdma->wr_data[idx].control_curr;

            for (count = 0; count < head.repeat; count++) {
                reg = &registers[count];
                mc_network_to_register(reg);

                block = &(rdma->local_ram_blocks.block[reg->current_index]);

                ret = ibv_dereg_mr(block->pmr[reg->key.chunk]);
                block->pmr[reg->key.chunk] = NULL;

                if (ret != 0) {
                    perror("rdma unregistration chunk failed");
                    ret = -ret;
                    goto out;
                }

                rdma->total_registrations--;

            }

            ret = mc_rdma_post_send_control(rdma, NULL, &unreg_resp);

            if (ret < 0) {
                error_report("Failed to send control buffer");
                goto out;
            }
            break;
        case MC_RDMA_CONTROL_REGISTER_RESULT:
            error_report("Invalid RESULT message at dest.");
            ret = -EIO;
            goto out;
        default:
            error_report("Unknown control message %s", control_desc[head.type]);
            ret = -EIO;
            goto out;
        }
    } while (1);
out:
    if (ret < 0) {
        rdma->error_state = ret;
    }
    return ret;
}

static int mc_block_notification_handle(const char *name)
{
    int curr;
    int found = -1;

    /* Find the matching RAMBlock in our local list */
    for (curr = 0; curr < rdma->local_ram_blocks.nb_blocks; curr++) {
        if (!strcmp(rdma->local_ram_blocks.block[curr].block_name, name)) {
            found = curr;
            break;
        }
    }

    if (found == -1) {
        error_report("RAMBlock '%s' not found on destination", name);
        return -ENOENT;
    }

    rdma->local_ram_blocks.block[curr].src_index = rdma->next_src_index;
    rdma->next_src_index++;

    return 0;
}

int mc_rdma_load_hook(QEMUFile *f, void *opaque, uint64_t flags, void *data)
{
    switch (flags) {
    case RAM_CONTROL_BLOCK_REG:
        return mc_block_notification_handle(data);

    case RAM_CONTROL_HOOK:
        return mc_rdma_registration_handle(f);

    default:
        /* Shouldn't be called with any other values */
        abort();
    }
}

int mc_rdma_registration_start(QEMUFile *f, void *opaque, uint64_t flags, void *data)
{
    qemu_put_be64(f, RAM_SAVE_FLAG_HOOK);
    qemu_fflush(f);

    return 0;
}

// qemu_fflush -> put_buffer
int mc_rdma_registration_stop(QEMUFile *f, void *opaque, uint64_t flags, void *data)
{
    Error *local_err = NULL, **errp = &local_err;

    MC_RDMAControlHeader head = { .len = 0, .repeat = 1 };
    int ret = 0;

    qemu_fflush(f);
    ret = mc_rdma_drain_cq(f, rdma);

    if (ret < 0) {
        goto err;
    }

    if (flags == RAM_CONTROL_SETUP) {
        MC_RDMAControlHeader resp = {.type = MC_RDMA_CONTROL_RAM_BLOCKS_RESULT };
        MC_RDMALocalBlocks *local = &rdma->local_ram_blocks;
        int reg_result_idx, i, nb_dest_blocks;

        head.type = MC_RDMA_CONTROL_RAM_BLOCKS_REQUEST;

        /*
         * Make sure that we parallelize the pinning on both sides.
         * For very large guests, doing this serially takes a really
         * long time, so we have to 'interleave' the pinning locally
         * with the control messages by performing the pinning on this
         * side before we receive the control response from the other
         * side that the pinning has completed.
         */
        ret = mc_rdma_exchange_send(rdma, &head, NULL, &resp,
                    &reg_result_idx, rdma->pin_all ?
                    mc_rdma_reg_whole_ram_blocks : NULL);
        if (ret < 0) {
            MC_ERROR(errp, "receiving remote info!");
            return ret;
        }

        nb_dest_blocks = resp.len / sizeof(MC_RDMADestBlock);

        /*
         * The protocol uses two different sets of rkeys (mutually exclusive):
         * 1. One key to represent the virtual address of the entire ram block.
         *    (dynamic chunk registration disabled - pin everything with one rkey.)
         * 2. One to represent individual chunks within a ram block.
         *    (dynamic chunk registration enabled - pin individual chunks.)
         *
         * Once the capability is successfully negotiated, the destination transmits
         * the keys to use (or sends them later) including the virtual addresses
         * and then propagates the remote ram block descriptions to his local copy.
         */

        if (local->nb_blocks != nb_dest_blocks) {
            MC_ERROR(errp, "ram blocks mismatch (Number of blocks %d vs %d) "
                        "Your QEMU command line parameters are probably "
                        "not identical on both the source and destination.",
                        local->nb_blocks, nb_dest_blocks);
            rdma->error_state = -EINVAL;
            return -EINVAL;
        }

        mc_rdma_move_header(rdma, reg_result_idx, &resp);
        memcpy(rdma->dest_blocks,
            rdma->wr_data[reg_result_idx].control_curr, resp.len);
        for (i = 0; i < nb_dest_blocks; i++) {
            mc_network_to_dest_block(&rdma->dest_blocks[i]);

            /* We require that the blocks are in the same order */
            if (rdma->dest_blocks[i].length != local->block[i].length) {
                MC_ERROR(errp, "Block %s/%d has a different length %" PRIu64
                            "vs %" PRIu64, local->block[i].block_name, i,
                            local->block[i].length,
                            rdma->dest_blocks[i].length);
                rdma->error_state = -EINVAL;
                return -EINVAL;
            }
            local->block[i].remote_host_addr =
                    rdma->dest_blocks[i].remote_host_addr;
            local->block[i].remote_rkey = rdma->dest_blocks[i].remote_rkey;
        }
    }

    head.type = MC_RDMA_CONTROL_REGISTER_FINISHED;
    ret = mc_rdma_exchange_send(rdma, &head, NULL, NULL, NULL, NULL);

    if (ret < 0) {
        goto err;
    }

    return 0;
err:
    rdma->error_state = ret;
    return ret;
}

/* ================================================================== */

struct config_t
{
    const char *dev_name;
    char *server_name; 
    u_int32_t tcp_port;
    int ib_port;
    int gid_idx;
};

static struct config_t config = {
    NULL,
    NULL,
    19875,
    1,
    -1
};

static int sock_connect(const char *servername, int port)
{
    struct addrinfo *resolved_addr = NULL;
    struct addrinfo *iterator;
    char service[6];
    int sockfd = -1;
    int listenfd = 0;
    int tmp;

    struct addrinfo hints =
    {
        .ai_flags = AI_PASSIVE,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };

    if (sprintf(service, "%d", port) < 0)
        goto sock_connect_exit;

    sockfd = getaddrinfo(servername, service, &hints, &resolved_addr);

    if (sockfd < 0)
    {
        fprintf(stderr, "%s for %s:%d\n", gai_strerror (sockfd), servername, port);
        goto sock_connect_exit;
    }


    /* Search through results and find the one we want */
    for (iterator = resolved_addr; iterator; iterator = iterator->ai_next)
    {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);
        if (sockfd >= 0)
        {
            if (servername)
            {
                if ((tmp = connect (sockfd, iterator->ai_addr, iterator->ai_addrlen)))
                {
                    fprintf (stdout, "failed connect \n");
                    close (sockfd);
                    sockfd = -1;
                }
            }
            else
            {
                listenfd = sockfd;
                
                int optval = 1;
                setsockopt(listenfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
                setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
                
                if (bind(listenfd, iterator->ai_addr, iterator->ai_addrlen))
                    goto sock_connect_exit;
                listen(listenfd, 1);
            }
        }
    }

sock_connect_exit:

    if (resolved_addr)
        freeaddrinfo(resolved_addr);

    if (sockfd < 0)
    {
        if (servername)
            fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
        else
        {
            perror("server listen");
            fprintf(stderr, "listen() failed\n");
        }
    }
    return sockfd;
}

static int sock_sync_data(int sock, int xfer_size, char *local_data, char *remote_data)
{
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;
    rc = write(sock, local_data, xfer_size);
    if (rc < xfer_size)
        fprintf (stderr, "Failed writing data during sock_sync_data\n");
    else
        rc = 0;
    while(!rc && total_read_bytes < xfer_size)
    {
        read_bytes = read(sock, remote_data, xfer_size);
        if (read_bytes > 0)
            total_read_bytes += read_bytes;
        else
            rc = read_bytes;
    }
    return rc;
}

static void resources_init(void)
{
    rdma->sock = -1;
}

static int resources_create(void)
{
    struct ibv_device **dev_list = NULL;
    struct ibv_qp_init_attr qp_init_attr;
    struct ibv_device *ib_dev = NULL;
    int i;
    int num_devices;
    int rc = 0;

    fprintf(stdout, "searching for IB devices in host\n");

    dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list)
    {
        fprintf(stderr, "failed to get IB devices list\n");
        rc = 1;
        goto resources_create_exit;
    }

    if (!num_devices)
    {
        fprintf(stderr, "found %d device(s)\n", num_devices);
        rc = 1;
        goto resources_create_exit;
    }
    fprintf (stdout, "found %d device(s)\n", num_devices);

    for (i = 0; i < num_devices; i++)
    {
        if (!config.dev_name)
        {
            config.dev_name = strdup(ibv_get_device_name(dev_list[i]));
            fprintf(stdout, "device not specified, using first one found: %s\n", config.dev_name);
        }
        if (!strcmp(ibv_get_device_name(dev_list[i]), config.dev_name))
        {
            ib_dev = dev_list[i];
            break;
        }
    }

    if (!ib_dev)
    {
        fprintf(stderr, "IB device %s wasn't found\n", config.dev_name);
        rc = 1;
        goto resources_create_exit;
    }

    rdma->ib_ctx = ibv_open_device(ib_dev);
    if (!rdma->ib_ctx)
    {
        fprintf(stderr, "failed to open device %s\n", config.dev_name);
        rc = 1;
        goto resources_create_exit;
    }

    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ib_dev = NULL;

    if (ibv_query_port(rdma->ib_ctx, config.ib_port, &rdma->port_attr))
    {
        fprintf (stderr, "ibv_query_port on port %u failed\n", config.ib_port);
        rc = 1;
        goto resources_create_exit;
    }

    rdma->pd = ibv_alloc_pd(rdma->ib_ctx);
    if (!rdma->pd)
    {
        fprintf (stderr, "ibv_alloc_pd failed\n");
        rc = 1;
        goto resources_create_exit;
    }

    rdma->cq = ibv_create_cq(rdma->ib_ctx, (MC_RDMA_SIGNALED_SEND_MAX * 3), NULL, NULL, 0);
    if (!rdma->cq)
    {
        fprintf (stderr, "failed to create CQ with %u entries\n", (MC_RDMA_SIGNALED_SEND_MAX * 3));
        rc = 1;
        goto resources_create_exit;
    }

    /* create the Queue Pair */
    memset(&qp_init_attr, 0, sizeof (qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.send_cq = rdma->cq;
    qp_init_attr.recv_cq = rdma->cq;
    qp_init_attr.cap.max_send_wr = MC_RDMA_SIGNALED_SEND_MAX;
    qp_init_attr.cap.max_recv_wr = 3;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
    rdma->qp = ibv_create_qp(rdma->pd, &qp_init_attr);
    if (!rdma->qp)
    {
        fprintf(stderr, "failed to create QP\n");
        rc = 1;
        goto resources_create_exit;
    }
    fprintf(stdout, "QP was created, QP number=0x%x\n", rdma->qp->qp_num);

    rdma->colo_ctrl_cq = ibv_create_cq(rdma->ib_ctx, 1, NULL, NULL, 0);
    if (!rdma->colo_ctrl_cq)
    {
        fprintf (stderr, "failed to create COLO CTRL CQ with %u entries\n", 1);
        rc = 1;
        goto resources_create_exit;
    }

    /* create the COLO CTRL Queue Pair */
    memset(&qp_init_attr, 0, sizeof (qp_init_attr));
    qp_init_attr.qp_type = IBV_QPT_RC;
    qp_init_attr.send_cq = rdma->colo_ctrl_cq;
    qp_init_attr.recv_cq = rdma->colo_ctrl_cq;
    qp_init_attr.cap.max_send_wr = 1;
    qp_init_attr.cap.max_recv_wr = 1;
    qp_init_attr.cap.max_send_sge = 1;
    qp_init_attr.cap.max_recv_sge = 1;
    rdma->colo_ctrl_qp = ibv_create_qp(rdma->pd, &qp_init_attr);
    if (!rdma->colo_ctrl_qp)
    {
        fprintf(stderr, "failed to create COLO CTRL QP\n");
        rc = 1;
        goto resources_create_exit;
    }
    fprintf(stdout, "COLO CTRL QP was created, QP number=0x%x\n", rdma->colo_ctrl_qp->qp_num);

resources_create_exit:
    if (rc)
    {
        /* MC_ERROR encountered, cleanup */
        if (rdma->qp)
        {
            ibv_destroy_qp(rdma->qp);
            rdma->qp = NULL;
        }
        if (rdma->cq)
        {
            ibv_destroy_cq(rdma->cq);
            rdma->cq = NULL;
        }
        if (rdma->colo_ctrl_qp)
        {
            ibv_destroy_qp(rdma->colo_ctrl_qp);
            rdma->colo_ctrl_qp = NULL;
        }
        if (rdma->colo_ctrl_cq)
        {
            ibv_destroy_cq(rdma->colo_ctrl_cq);
            rdma->colo_ctrl_cq = NULL;
        }
        if (rdma->pd)
        {
            ibv_dealloc_pd(rdma->pd);
            rdma->pd = NULL;
        }
        if (rdma->ib_ctx)
        {
            ibv_close_device(rdma->ib_ctx);
            rdma->ib_ctx = NULL;
        }
        if (dev_list)
        {
            ibv_free_device_list(dev_list);
            dev_list = NULL;
        }
        if (rdma->sock >= 0)
        {
            if (close(rdma->sock))
                fprintf(stderr, "failed to close socket\n");
            rdma->sock = -1;
        }
    }
    return rc;
}

static int modify_qp_to_init(struct ibv_qp *qp)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset(&attr, 0, sizeof (attr));
    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = config.ib_port;
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
        IBV_ACCESS_REMOTE_WRITE;
    flags =
        IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    rc = ibv_modify_qp(qp, &attr, flags);
    if (rc)
        fprintf(stderr, "failed to modify QP state to INIT\n");
    return rc;
}

static int modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn, uint16_t dlid, uint8_t * dgid)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset (&attr, 0, sizeof (attr));
    attr.qp_state = IBV_QPS_RTR;
    //attr.path_mtu = IBV_MTU_256;
    attr.path_mtu = rdma->port_attr.active_mtu;
    attr.dest_qp_num = remote_qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 1;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = config.ib_port;
    if (config.gid_idx >= 0)
    {
        attr.ah_attr.is_global = 1;
        attr.ah_attr.port_num = 1;
        memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
        attr.ah_attr.grh.flow_label = 0;
        attr.ah_attr.grh.hop_limit = 0xFF;
        attr.ah_attr.grh.sgid_index = config.gid_idx;
        attr.ah_attr.grh.traffic_class = 0;
    }
    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
        IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    rc = ibv_modify_qp(qp, &attr, flags);
    if (rc)
        fprintf(stderr, "failed to modify QP state to RTR\n");
    return rc;
}

static int modify_qp_to_rts(struct ibv_qp *qp)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;
    memset(&attr, 0, sizeof (attr));
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 1;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
        IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    rc = ibv_modify_qp(qp, &attr, flags);
    if (rc)
        fprintf (stderr, "failed to modify QP state to RTS\n");
    return rc;
}

static int connect_qp(void)
{
    struct cm_con_data_t local_con_data;
    struct cm_con_data_t remote_con_data;
    struct cm_con_data_t tmp_con_data;
    int rc = 0;

    union ibv_gid my_gid;
    if (config.gid_idx >= 0)
    {
        rc = ibv_query_gid(rdma->ib_ctx, config.ib_port, config.gid_idx, &my_gid);
        if (rc)
        {
            fprintf (stderr, "could not get gid for port %d, index %d\n", config.ib_port, config.gid_idx);
            return rc;
        }
    }
    else
        memset(&my_gid, 0, sizeof my_gid);

    local_con_data.qp_num = htonl(rdma->qp->qp_num);
    local_con_data.lid = htons(rdma->port_attr.lid);
    memcpy(local_con_data.gid, &my_gid, 16);
    fprintf(stdout, "\nLocal LID = 0x%x\n", rdma->port_attr.lid);

    uint32_t rdma_capability = 0;
    if (config.server_name && rdma->pin_all) {
        rdma_capability |= MC_RDMA_CAPABILITY_PIN_ALL;
    }
    local_con_data.capability_flags = htonl(rdma_capability);

    if (sock_sync_data(rdma->sock, sizeof (struct cm_con_data_t), (char*)&local_con_data, (char*)&tmp_con_data) < 0)
    {
        fprintf(stderr, "failed to exchange connection data between sides\n");
        rc = 1;
        goto connect_qp_exit;
    }
    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
    remote_con_data.lid = ntohs(tmp_con_data.lid);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);
    if (!config.server_name) {
        remote_con_data.capability_flags = ntohl(tmp_con_data.capability_flags);
        if (remote_con_data.capability_flags & MC_RDMA_CAPABILITY_PIN_ALL) {
            rdma->pin_all = true;
        }
    }

    rdma->remote_props = remote_con_data;
    fprintf(stdout, "Remote QP number = 0x%x\n", remote_con_data.qp_num);
    fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data.lid);
    if (config.gid_idx >= 0)
    {
        uint8_t *p = remote_con_data.gid;
        fprintf (stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],
                p[10], p[11], p[12], p[13], p[14], p[15]);
    }
    /* modify the QP to init */
    rc = modify_qp_to_init(rdma->qp);
    if (rc)
    {
        fprintf(stderr, "change QP state to INIT failed\n");
        goto connect_qp_exit;
    }

    rc = modify_qp_to_rtr(rdma->qp, remote_con_data.qp_num, remote_con_data.lid, remote_con_data.gid);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to RTR\n");
        goto connect_qp_exit;
    }
    fprintf(stderr, "Modified QP state to RTR\n");
    rc = modify_qp_to_rts(rdma->qp);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to RTR\n");
        goto connect_qp_exit;
    }
    fprintf(stdout, "QP state was change to RTS\n");

    local_con_data.qp_num = htonl(rdma->colo_ctrl_qp->qp_num);
    local_con_data.lid = htons(rdma->port_attr.lid);
    memcpy(local_con_data.gid, &my_gid, 16);
    fprintf(stdout, "\nLocal LID = 0x%x\n", rdma->port_attr.lid);
    if (sock_sync_data(rdma->sock, sizeof (struct cm_con_data_t), (char*)&local_con_data, (char*)&tmp_con_data) < 0)
    {
        fprintf(stderr, "failed to exchange connection data between sides\n");
        rc = 1;
        goto connect_qp_exit;
    }
    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
    remote_con_data.lid = ntohs(tmp_con_data.lid);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);

    rdma->remote_props = remote_con_data;
    fprintf(stdout, "Remote COLO CTRL QP number = 0x%x\n", remote_con_data.qp_num);
    fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data.lid);
    if (config.gid_idx >= 0)
    {
        uint8_t *p = remote_con_data.gid;
        fprintf (stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],
                p[10], p[11], p[12], p[13], p[14], p[15]);
    }
    /* modify the QP to init */
    rc = modify_qp_to_init(rdma->colo_ctrl_qp);
    if (rc)
    {
        fprintf(stderr, "change COLO CTRL QP state to INIT failed\n");
        goto connect_qp_exit;
    }

    rc = modify_qp_to_rtr(rdma->colo_ctrl_qp, remote_con_data.qp_num, remote_con_data.lid, remote_con_data.gid);
    if (rc)
    {
        fprintf(stderr, "failed to modify COLO CTRL QP state to RTR\n");
        goto connect_qp_exit;
    }
    fprintf(stderr, "Modified COLO CTRL QP state to RTR\n");
    rc = modify_qp_to_rts(rdma->colo_ctrl_qp);
    if (rc)
    {
        fprintf(stderr, "failed to modify COLO CTRL QP state to RTR\n");
        goto connect_qp_exit;
    }
    fprintf(stdout, "COLO CTRL QP state was change to RTS\n");

connect_qp_exit:
    return rc;
}

static int mc_rdma_send_ready(void)
{
    // RDMA SEND to inform the source we're ready
    int ret = 0;
    MC_RDMAControlHeader head;
    head.len = 1;
    MC_RDMAWorkRequestData *wr = &rdma->colo_ctrl_wr_data;
    struct ibv_send_wr *bad_wr;
    struct ibv_sge sge = {
                           .addr = (uintptr_t)(wr->control + MC_RDMA_CONTROL_RESERVED_RECV_BUFFER),
                           .length = head.len + sizeof(MC_RDMAControlHeader),
                           .lkey = wr->control_mr->lkey,
                         };
    struct ibv_send_wr send_wr = {
                                   .opcode = IBV_WR_SEND,
                                   .send_flags = IBV_SEND_SIGNALED,
                                   .sg_list = &sge,
                                   .num_sge = 1,
                                };

    assert(sge.length <= MC_RDMA_CONTROL_RESERVED_RECV_BUFFER);
    memcpy(wr->control + MC_RDMA_CONTROL_RESERVED_RECV_BUFFER, &head, sizeof(MC_RDMAControlHeader));
    mc_control_to_network((void *) (wr->control + MC_RDMA_CONTROL_RESERVED_RECV_BUFFER));

    ret = ibv_post_send(rdma->colo_ctrl_qp, &send_wr, &bad_wr);

    if (ret > 0) {
        error_report("Failed to use post IB SEND for colo control");
        return -ret;
    }

    // block until SEND to finish
    int poll_result;
    struct ibv_wc wc;

    do {
        poll_result = ibv_poll_cq(rdma->colo_ctrl_cq, 1, &wc);
    } while (poll_result == 0);

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "ibv_poll_cq wc.status=%d %s!\n",
                        wc.status, ibv_wc_status_str(wc.status));

        return -1;
    }

    return 0;
}

static int mc_rdma_recv_ready(void)
{
    // wait for READY
    int poll_result;
    struct ibv_wc wc;

    do {
        poll_result = ibv_poll_cq(rdma->colo_ctrl_cq, 1, &wc);
    } while (poll_result == 0);

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "ibv_poll_cq wc.status=%d %s!\n",
                        wc.status, ibv_wc_status_str(wc.status));

        return -1;
    }

    // post a WR request for READY
    struct ibv_recv_wr *bad_wr;
    struct ibv_sge sge = {
                            .addr = (uintptr_t)(rdma->colo_ctrl_wr_data.control),
                            .length = MC_RDMA_CONTROL_MAX_BUFFER,
                            .lkey = rdma->colo_ctrl_wr_data.control_mr->lkey,
                         };

    struct ibv_recv_wr recv_wr = {
                                    .sg_list = &sge,
                                    .num_sge = 1,
                                 };


    if (ibv_post_recv(rdma->colo_ctrl_qp, &recv_wr, &bad_wr)) {
        return -1;
    }

    return 0;
}

int mc_rdma_put_colo_ctrl_buffer(uint32_t size)
{
    // mc_rdma_recv_ready();

    int ret = 0;
    MC_RDMAControlHeader head;
    head.len = size;
    MC_RDMAWorkRequestData *wr = &rdma->colo_ctrl_wr_data;
    struct ibv_send_wr *bad_wr;
    struct ibv_sge sge = {
                           .addr = (uintptr_t)(wr->control + MC_RDMA_CONTROL_RESERVED_RECV_BUFFER),
                           .length = head.len + sizeof(MC_RDMAControlHeader),
                           .lkey = wr->control_mr->lkey,
                         };
    struct ibv_send_wr send_wr = {
                                   .opcode = IBV_WR_SEND,
                                   .send_flags = IBV_SEND_SIGNALED,
                                   .sg_list = &sge,
                                   .num_sge = 1,
                                };

    assert(sge.length <= MC_RDMA_CONTROL_RESERVED_RECV_BUFFER);
    memcpy(wr->control + MC_RDMA_CONTROL_RESERVED_RECV_BUFFER, &head, sizeof(MC_RDMAControlHeader));
    mc_control_to_network((void *) (wr->control + MC_RDMA_CONTROL_RESERVED_RECV_BUFFER));

    ret = ibv_post_send(rdma->colo_ctrl_qp, &send_wr, &bad_wr);

    if (ret > 0) {
        error_report("Failed to use post IB SEND for colo control");
        return -ret;
    }

    int poll_result;
    struct ibv_wc wc;

    do {
        poll_result = ibv_poll_cq(rdma->colo_ctrl_cq, 1, &wc);
    } while (poll_result == 0);

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "ibv_poll_cq wc.status=%d %s!\n",
                        wc.status, ibv_wc_status_str(wc.status));

        return -1;
    }

    return 0;
}

uint8_t *mc_rdma_get_colo_ctrl_buffer_ptr(void)
{
    MC_RDMAWorkRequestData *wr = &rdma->colo_ctrl_wr_data;

    uint8_t *ptr = wr->control + MC_RDMA_CONTROL_RESERVED_RECV_BUFFER + sizeof(MC_RDMAControlHeader);

    return ptr;
}

ssize_t mc_rdma_get_colo_ctrl_buffer(size_t size)
{
    // mc_rdma_send_ready();

    int poll_result;
    struct ibv_wc wc;

    do {
        poll_result = ibv_poll_cq(rdma->colo_ctrl_cq, 1, &wc);
    } while (poll_result == 0);

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "ibv_poll_cq wc.status=%d %s!\n",
                        wc.status, ibv_wc_status_str(wc.status));

        return -1;
    }

    MC_RDMAControlHeader head;

    mc_network_to_control((void *) rdma->colo_ctrl_wr_data.control);
    memcpy(&head, rdma->colo_ctrl_wr_data.control, sizeof(MC_RDMAControlHeader));
    memcpy(rdma->colo_ctrl_wr_data.control + MC_RDMA_CONTROL_RESERVED_RECV_BUFFER + sizeof(MC_RDMAControlHeader), rdma->colo_ctrl_wr_data.control + sizeof(MC_RDMAControlHeader), head.len);

    struct ibv_recv_wr *bad_wr;
    struct ibv_sge sge = {
                            .addr = (uintptr_t)(rdma->colo_ctrl_wr_data.control),
                            .length = MC_RDMA_CONTROL_MAX_BUFFER,
                            .lkey = rdma->colo_ctrl_wr_data.control_mr->lkey,
                         };

    struct ibv_recv_wr recv_wr = {
                                    .sg_list = &sge,
                                    .num_sge = 1,
                                 };


    if (ibv_post_recv(rdma->colo_ctrl_qp, &recv_wr, &bad_wr)) {
        return -1;
    }

    return head.len;
}

static void mc_accept_incoming_migration(void *arg)
{
    int ret;

    int listenfd = rdma->sock;
    rdma->sock = accept(listenfd, NULL, NULL);
    qemu_set_fd_handler(listenfd, NULL, NULL, NULL);

    fprintf(stdout, "TCP connection was established\n");

    if (resources_create())
        error_report("failed to create resources\n");

    ret = mc_rdma_init_ram_blocks(rdma);
    int idx;
    for (idx = 0; idx < MC_RDMA_WRID_MAX; idx++) {
        ret = mc_rdma_reg_control(rdma, idx);
        if (ret) {
            error_report("rdma: error registering %d control", idx);
        }
    }

    rdma->colo_ctrl_wr_data.control_mr = ibv_reg_mr(rdma->pd,
            rdma->colo_ctrl_wr_data.control, MC_RDMA_CONTROL_MAX_BUFFER,
            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    if (connect_qp())
        error_report("failed to connect QPs\n");

    rdma->connected = true;

    ret = mc_rdma_post_recv_control(rdma, MC_RDMA_WRID_READY);

    rdma->migration_started_on_destination = 1;


    struct ibv_recv_wr *bad_wr;
    struct ibv_sge sge = {
                            .addr = (uintptr_t)(rdma->colo_ctrl_wr_data.control),
                            .length = MC_RDMA_CONTROL_MAX_BUFFER,
                            .lkey = rdma->colo_ctrl_wr_data.control_mr->lkey,
                         };

    struct ibv_recv_wr recv_wr = {
                                    .sg_list = &sge,
                                    .num_sge = 1,
                                 };


    if (ibv_post_recv(rdma->colo_ctrl_qp, &recv_wr, &bad_wr)) {
    }
}

int mc_start_incoming_migration(void)
{
    rdma = mc_rdma_data_init();

    if (rdma == NULL) {
    }

    mc_rdma_dest_init(rdma);

    config.gid_idx = 0;
    config.ib_port = 2;
    resources_init();

    fprintf(stdout, "waiting on port %d for TCP connection\n", config.tcp_port);
    rdma->sock = sock_connect(NULL, config.tcp_port);
    if (rdma->sock < 0)
        fprintf(stderr, "failed to listen on port %d\n", config.tcp_port);

    qemu_set_fd_handler(rdma->sock, mc_accept_incoming_migration, NULL, NULL);

    return 0;
}

int mc_start_outgoing_migration(const char *mc_host_port)
{
    rdma = mc_rdma_data_init();

    InetSocketAddress *addr;
    addr = inet_parse(mc_host_port, NULL);
    if (addr != NULL) {
        config.server_name = g_strdup(addr->host);
    }

    config.gid_idx = 0;
    config.ib_port = 2;
    resources_init();

    rdma->sock = sock_connect(config.server_name, config.tcp_port);
    if (rdma->sock < 0)
        fprintf(stderr, "failed to establish TCP connection to server %s, port %d\n", config.server_name, config.tcp_port);

    fprintf(stdout, "TCP connection was established\n");

    rdma->pin_all = MC_MIGRATION_CAPABILITY_RDMA_PIN_ALL;

    if (resources_create())
        error_report("failed to create resources\n");

    int ret, idx;
    ret = mc_rdma_init_ram_blocks(rdma);

    /* Build the hash that maps from offset to RAMBlock */
    rdma->blockmap = g_hash_table_new(g_direct_hash, g_direct_equal);
    for (idx = 0; idx < rdma->local_ram_blocks.nb_blocks; idx++) {
        g_hash_table_insert(rdma->blockmap,
                (void *)(uintptr_t)rdma->local_ram_blocks.block[idx].offset,
                &rdma->local_ram_blocks.block[idx]);
    }

    for (idx = 0; idx < MC_RDMA_WRID_MAX; idx++) {
        ret = mc_rdma_reg_control(rdma, idx);
        if (ret) {
        }
    }

    rdma->colo_ctrl_wr_data.control_mr = ibv_reg_mr(rdma->pd,
            rdma->colo_ctrl_wr_data.control, MC_RDMA_CONTROL_MAX_BUFFER,
            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    if (connect_qp())
        error_report("failed to connect QPs\n");

    rdma->connected = true;

    ret = mc_rdma_post_recv_control(rdma, MC_RDMA_WRID_READY);

    rdma->control_ready_expected = 1;
    rdma->nb_sent = 0;

    struct ibv_recv_wr *bad_wr;
    struct ibv_sge sge = {
                            .addr = (uintptr_t)(rdma->colo_ctrl_wr_data.control),
                            .length = MC_RDMA_CONTROL_MAX_BUFFER,
                            .lkey = rdma->colo_ctrl_wr_data.control_mr->lkey,
                         };

    struct ibv_recv_wr recv_wr = {
                                    .sg_list = &sge,
                                    .num_sge = 1,
                                 };


    if (ibv_post_recv(rdma->colo_ctrl_qp, &recv_wr, &bad_wr)) {
        return -1;
    }


    return 0;
}