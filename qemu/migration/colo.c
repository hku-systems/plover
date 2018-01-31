/*
 * COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 * (a.k.a. Fault Tolerance or Continuous Replication)
 *
 * Copyright (c) 2016 HUAWEI TECHNOLOGIES CO., LTD.
 * Copyright (c) 2016 FUJITSU LIMITED
 * Copyright (c) 2016 Intel Corporation
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "migration/colo.h"
#include "trace.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "migration/failover.h"
#include "qapi-event.h"
#include "block/block.h"
#include "replication.h"
#include "net/colo-compare.h"

#include "output-buffer.h"
#include "mc-rdma.h"
#include "rsm-interface.h"

#include "migration/hash.h"
#include "net/net.h"
#include "getdelays.h"
//#include "migration/gettime.h"


static bool vmstate_loading;

bool colo_not_first_sync; 

bool colo_primary_transfer;

bool control_clock;

#define SYNC_OUTPUT_RANGE 0.98

/* colo buffer */
#define COLO_BUFFER_BASE_SIZE (4 * 1024 * 1024)

bool colo_supported(void)
{
    return true;
}

bool migration_in_colo_state(void)
{
    MigrationState *s = migrate_get_current();

    return (s->state == MIGRATION_STATUS_COLO);
}

bool migration_incoming_in_colo_state(void)
{
    MigrationIncomingState *mis = migration_incoming_get_current();

    return mis && (mis->state == MIGRATION_STATUS_COLO);
}

static bool colo_runstate_is_stopped(void)
{
    return runstate_check(RUN_STATE_COLO) || !runstate_is_running();
}

static void secondary_vm_do_failover(void)
{
    int old_state;
    MigrationIncomingState *mis = migration_incoming_get_current();
    Error *local_err = NULL;

    /* Can not do failover during the process of VM's loading VMstate, Or
      * it will break the secondary VM.
      */
    if (vmstate_loading) {
        old_state = failover_set_state(FAILOVER_STATUS_HANDLING,
                                       FAILOVER_STATUS_RELAUNCH);
        if (old_state != FAILOVER_STATUS_HANDLING) {
            error_report("Unknown error while do failover for secondary VM,"
                         "old_state: %d", old_state);
        }
        return;
    }

    migrate_set_state(&mis->state, MIGRATION_STATUS_COLO,
                      MIGRATION_STATUS_COMPLETED);

    replication_stop_all(true, &local_err);
    if (local_err) {
        error_report_err(local_err);
    }

    if (!autostart) {
        error_report("\"-S\" qemu option will be ignored in secondary side");
        /* recover runstate to normal migration finish state */
        autostart = true;
    }
    /*
    * Make sure colo incoming thread not block in recv or send,
    * If mis->from_src_file and mis->to_src_file use the same fd,
    * The second shutdown() will return -1, we ignore this value,
    * it is harmless.
    */
    if (mis->from_src_file) {
        qemu_file_shutdown(mis->from_src_file);
    }
    if (mis->to_src_file) {
        qemu_file_shutdown(mis->to_src_file);
    }

    old_state = failover_set_state(FAILOVER_STATUS_HANDLING,
                                   FAILOVER_STATUS_COMPLETED);
    if (old_state != FAILOVER_STATUS_HANDLING) {
        error_report("Incorrect state (%d) while doing failover for "
                     "secondary VM", old_state);
        return;
    }
    /* Notify COLO incoming thread that failover work is finished */
    qemu_sem_post(&mis->colo_incoming_sem);
    /* For Secondary VM, jump to incoming co */
    if (mis->migration_incoming_co) {
        qemu_coroutine_enter(mis->migration_incoming_co, NULL);
    }
}

static void primary_vm_do_failover(void)
{
    MigrationState *s = migrate_get_current();
    int old_state;
    Error *local_err = NULL;

    migrate_set_state(&s->state, MIGRATION_STATUS_COLO,
                      MIGRATION_STATUS_COMPLETED);

    /*
    * Make sure colo thread no block in recv or send,
    * The s->rp_state.from_dst_file and s->to_dst_file may use the
    * same fd, but we still shutdown the fd for twice, it is harmless.
    */
    if (s->to_dst_file) {
        qemu_file_shutdown(s->to_dst_file);
    }
    if (s->rp_state.from_dst_file) {
        qemu_file_shutdown(s->rp_state.from_dst_file);
    }

    old_state = failover_set_state(FAILOVER_STATUS_HANDLING,
                                   FAILOVER_STATUS_COMPLETED);
    if (old_state != FAILOVER_STATUS_HANDLING) {
        error_report("Incorrect state (%d) while doing failover for Primary VM",
                     old_state);
        return;
    }

    replication_stop_all(true, &local_err);
    if (local_err) {
        error_report_err(local_err);
    }

    /* Notify COLO thread that failover work is finished */
    qemu_sem_post(&s->colo_sem);
}

void colo_do_failover(MigrationState *s)
{
    /* Make sure vm stopped while failover */
    if (!colo_runstate_is_stopped()) {
        vm_stop_force_state(RUN_STATE_COLO);
    }

    if (get_colo_mode() == COLO_MODE_PRIMARY) {
        primary_vm_do_failover();
    } else {
        secondary_vm_do_failover();
    }
}

uint8_t *rdma_buffer;

static void colo_send_message(QEMUFile *f, COLOMessage msg,
                              Error **errp)
{
    int ret;

    if (msg >= COLO_MESSAGE__MAX) {
        error_setg(errp, "%s: Invalid message", __func__);
        return;
    }
    qemu_put_be32(f, msg);
    qemu_fflush(f);

    ret = qemu_file_get_error(f);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "Can't send COLO message");
    }
    trace_colo_send_message(COLOMessage_lookup[msg]);
}

static void mc_send_message(COLOMessage msg, Error **errp)
{
    int ret;

    *(COLOMessage*)rdma_buffer = msg;
    ret = mc_rdma_put_colo_ctrl_buffer(sizeof(msg));
    if (ret != 0) {
        error_setg_errno(errp, -ret, "Can't send COLO CTRL message");
    }
    trace_colo_send_message(COLOMessage_lookup[msg]);
}

static void colo_send_message_value(QEMUFile *f, COLOMessage msg,
                                    uint64_t value, Error **errp)
{
    Error *local_err = NULL;
    int ret;

    colo_send_message(f, msg, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }
    qemu_put_be64(f, value);
    qemu_fflush(f);

    ret = qemu_file_get_error(f);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "Failed to send value for message:%s",
                         COLOMessage_lookup[msg]);
    }
}

static void mc_send_message_value(COLOMessage msg, uint64_t value, Error **errp)
{
    Error *local_err = NULL;
    int ret;

    mc_send_message(msg, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    *(uint64_t*)rdma_buffer = value;
    ret = mc_rdma_put_colo_ctrl_buffer(sizeof(value));
    if (ret < 0) {
        error_setg_errno(errp, -ret, "Failed to send value for message:%s",
                         COLOMessage_lookup[msg]);
    }
}

static COLOMessage colo_receive_message(QEMUFile *f, Error **errp)
{
    COLOMessage msg;
    int ret;

    msg = qemu_get_be32(f);
    ret = qemu_file_get_error(f);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "Can't receive COLO message");
        return msg;
    }
    if (msg >= COLO_MESSAGE__MAX) {
        error_setg(errp, "%s: Invalid message", __func__);
        return msg;
    }
    trace_colo_receive_message(COLOMessage_lookup[msg]);
    return msg;
}

static COLOMessage mc_receive_message(void)
{
    COLOMessage msg;
    mc_rdma_get_colo_ctrl_buffer(sizeof(msg));
    msg = *(COLOMessage*)rdma_buffer;

    trace_colo_receive_message(COLOMessage_lookup[msg]);
    return msg;
}

static void colo_receive_check_message(QEMUFile *f, COLOMessage expect_msg,
                                       Error **errp)
{
    COLOMessage msg;
    Error *local_err = NULL;

    msg = colo_receive_message(f, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }
    if (msg != expect_msg) {
        error_setg(errp, "Unexpected COLO message %d, expected %d",
                          msg, expect_msg);
    }
}

static void mc_receive_check_message(COLOMessage expect_msg, Error **errp)
{
    COLOMessage msg;

    msg = mc_receive_message();

    if (msg != expect_msg) {
        error_setg(errp, "Unexpected COLO CTRL message %d, expected %d",
                          msg, expect_msg);
    }
}

static uint64_t colo_receive_message_value(QEMUFile *f, uint32_t expect_msg,
                                           Error **errp)
{
    Error *local_err = NULL;
    uint64_t value;
    int ret;

    colo_receive_check_message(f, expect_msg, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return 0;
    }

    value = qemu_get_be64(f);
    ret = qemu_file_get_error(f);
    if (ret < 0) {
        error_setg_errno(errp, -ret, "Failed to get value for COLO message: %s",
                         COLOMessage_lookup[expect_msg]);
    }
    return value;
}

static uint64_t mc_receive_message_value(uint32_t expect_msg, Error **errp)
{
    Error *local_err = NULL;
    uint64_t value;

    mc_receive_check_message(expect_msg, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return 0;
    }

    mc_rdma_get_colo_ctrl_buffer(sizeof(value));

    value = *(uint64_t*)rdma_buffer;

    return value;
}

static int idle_clock_rate_min, idle_clock_rate_max, idle_clock_rate_avg;

#define USE_ESTIMATED_IDLE_CLOCK_RATE

static void learn_idle_clock_rate(void)
{
#ifdef USE_ESTIMATED_IDLE_CLOCK_RATE
    idle_clock_rate_avg = 1200;
    return;
#endif

    int learn_cycles = 50000, i;
    clock_t t1, t2;
    uint64_t clock_sum = 0;
    for (i = 0; i < learn_cycles; ++i)
    {
        t1 = clock();
        g_usleep(1000 * 1);
        t2 = clock();
        clock_sum += t2 - t1;
        if (i == 0) {
            idle_clock_rate_max = t2 - t1;
            idle_clock_rate_min = t2 - t1;
        } else {
            if (t2 - t1 > idle_clock_rate_max) {
                idle_clock_rate_max = t2 - t1;
            }
            if (t2 - t1 < idle_clock_rate_min) {
                idle_clock_rate_min = t2 - t1;
            }
        }
    }
    idle_clock_rate_avg = clock_sum / learn_cycles;
    fprintf(stderr, "idle clock rate max %d, idle clock rate min %d, idle clock rate avg %d, 1ms\n", idle_clock_rate_max, idle_clock_rate_min, idle_clock_rate_avg);
}

static int colo_debug;

static int recheck_count;
static uint64_t checkpoint_cnt;

#define CHECK_IDLE_SYNC 1
#define STATIC_TIME_SYNC 2
static int sync_type;



static void wait_guest_finish(MigrationState *s, bool is_primary)
{
    struct timeval t1, t2;
    if (colo_debug) {
        gettimeofday(&t1, NULL);
    }

    int idle_counter = 0;
    do
    {
        if (check_cpu_usage()) { // 1 means working, 0 means idle
            idle_counter = 0;
        } else {
            uint64_t start_counter, end_counter;
            start_counter = get_output_counter();
            if (check_disk_usage()) {
                idle_counter = 0;
            } else {
                end_counter = get_output_counter();
                if (end_counter == start_counter){
                    idle_counter++;
                }
                else {
                    idle_counter = 0;
                } 
            }
        }
    } while (idle_counter < recheck_count);

    checkpoint_cnt++;
    if (colo_debug) {
        gettimeofday(&t2, NULL);
        double elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;
        elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;
        uint64_t output_counter = get_output_counter();
        reset_output_counter();
        fprintf(stderr, "[%s %"PRIu64"] output_counter %"PRIu64", %fms\n", is_primary == true ? "LEADER" : "BACKUP", checkpoint_cnt, output_counter, elapsedTime);
    }

    return;
}

static void static_timing_sync(MigrationState *s)
{
    g_usleep(s->parameters[MIGRATION_PARAMETER_X_CHECKPOINT_DELAY] * 1000);
}

static int colo_gettime;

#define TURN_ON_FT
static int colo_do_checkpoint_transaction(MigrationState *s,
                                          QEMUSizedBuffer *buffer)
{
    
    QEMUFile *trans = NULL;
    size_t size;
    Error *local_err = NULL;
    int ret = -1;

    // colo_send_message(s->to_dst_file, COLO_MESSAGE_CHECKPOINT_REQUEST,
    //                   &local_err);

    if (sync_type == CHECK_IDLE_SYNC) {
        wait_guest_finish(s, true);
    } else if (sync_type == STATIC_TIME_SYNC) {
        static_timing_sync(s);
    }
    
    proxy_on_checkpoint_req();

    if (local_err) {
        goto out;
    }

    /* Reset colo buffer and open it for write */
    qsb_set_length(buffer, 0);
    trans = qemu_bufopen("w", buffer);
    if (!trans) {
        error_report("Open colo buffer for write failed");
        goto out;
    }

    qemu_mutex_lock_iothread();
    if (failover_request_is_active()) {
        qemu_mutex_unlock_iothread();
        goto out;
    }

    vm_stop_force_state(RUN_STATE_COLO);

    qemu_mutex_unlock_iothread();
    //trace_colo_vm_state_change("run", "stop");

#ifdef TURN_ON_FT

    /*
     * failover request bh could be called after
     * vm_stop_force_state so we check failover_request_is_active() again.
     */
    if (failover_request_is_active()) {
        goto out;
    }

    /* we call this api although this may do nothing on primary side */
    qemu_mutex_lock_iothread();
    replication_do_checkpoint_all(&local_err);
    qemu_mutex_unlock_iothread();
    if (local_err) {
        goto out;
    }

    // colo_send_message(s->to_dst_file, COLO_MESSAGE_VMSTATE_SEND, &local_err);
    /*
     * qemu_mutex_lock_iothread() blocks the io thread for reading new network
     * packets
     */

    // mc_send_message(COLO_MESSAGE_VMSTATE_SEND, &local_err);
    // if (local_err) {
    //     goto out;
    // }

    qemu_mutex_lock_iothread();
    /*
    * Only save VM's live state, which not including device state.
    * TODO: We may need a timeout mechanism to prevent COLO process
    * to be blocked here.
    */
    migrate_use_mc_rdma = true;
    colo_not_first_sync = true;


    colo_primary_transfer = true;

    uint64_t savevm_start;
    if (colo_gettime) {
        savevm_start = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    }

    qemu_savevm_live_state(s->to_dst_file);

    if (colo_gettime) {
        int64_t savevm_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - savevm_start;
        fprintf(stderr, "qemu_savevm_live_state: %"PRId64"\n", savevm_time);
    }

    colo_primary_transfer = false;


    colo_not_first_sync = false;
    migrate_use_mc_rdma = false;

    //clock_add(&clock);

    /* flush QEMU_VM_EOF and RAM_SAVE_FLAG_EOS so that
     * colo_process_incoming_thread can step out of qemu_loadvm_state_main
     */
    qemu_fflush(s->to_dst_file);
    /* Note: device state is saved into buffer */
    ret = qemu_save_device_state(trans);

    qemu_mutex_unlock_iothread();
    if (ret < 0) {
        error_report("Save device state error");
        goto out;
    }
    qemu_fflush(trans);

    /* we send the total size of the vmstate first */
    size = qsb_get_length(buffer);
    // colo_send_message_value(s->to_dst_file, COLO_MESSAGE_VMSTATE_SIZE,
    //                          size, &local_err);
    mc_send_message_value(COLO_MESSAGE_VMSTATE_SIZE, size, &local_err);

    if (local_err) {
        goto out;
    }

    mc_qsb_put_buffer(rdma_buffer, buffer, size);
    mc_rdma_put_colo_ctrl_buffer(size);
    // qsb_put_buffer(s->to_dst_file, buffer, size);
    // qemu_fflush(s->to_dst_file);
    ret = qemu_file_get_error(s->to_dst_file);
    if (ret < 0) {
        goto out;
    }

    // colo_receive_check_message(s->rp_state.from_dst_file,
    //                     COLO_MESSAGE_VMSTATE_RECEIVED, &local_err);
    //mc_receive_check_message(COLO_MESSAGE_VMSTATE_RECEIVED, &local_err);

    if (local_err) {
        goto out;
    }

    uint64_t vmstate_loaded_start;
    if (colo_gettime) {
        vmstate_loaded_start = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    }

    // colo_receive_check_message(s->rp_state.from_dst_file,
    //                     COLO_MESSAGE_VMSTATE_LOADED, &local_err);

    mc_receive_check_message(COLO_MESSAGE_VMSTATE_LOADED, &local_err);
    if (local_err) {
        goto out;
    }

    if (colo_gettime) {
        int64_t vmstate_loaded_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - vmstate_loaded_start;
        fprintf(stderr, "vmstate_loaded_time: %"PRId64"\n", vmstate_loaded_time);
    }

    if (colo_shutdown_requested) {
        colo_send_message(s->to_dst_file, COLO_MESSAGE_GUEST_SHUTDOWN,
                          &local_err);
        if (local_err) {
            error_free(local_err);
            /* Go on the shutdown process and throw the error message */
            error_report("Failed to send shutdown message to SVM");
        }
        qemu_fflush(s->to_dst_file);
        colo_shutdown_requested = 0;
        qemu_system_shutdown_request_core();
        /* Fix me: Just let the colo thread exit ? */
        qemu_thread_exit(0);
    }
#endif
    ret = 0;
    //trace_colo_vm_state_change("stop", "run");

    mc_start_buffer();

    /* Resume primary guest */
    qemu_mutex_lock_iothread();
    control_clock = true;
    vm_start();
    control_clock = false;
    qemu_mutex_unlock_iothread();

    mc_flush_oldest_buffer();

    colo_compare_do_checkpoint();

out:
    if (local_err) {
        error_report_err(local_err);
    }
    if (trans) {
        qemu_fclose(trans);
    }
    return ret;
}

static int colo_prepare_before_save(MigrationState *s)
{
    int ret;

    /* Disable block migration */
    s->params.blk = 0;
    s->params.shared = 0;
    qemu_savevm_state_begin(s->to_dst_file, &s->params);
    ret = qemu_file_get_error(s->to_dst_file);
    if (ret < 0) {
        error_report("Save vm state begin error");
    }
    return ret;
}

static void colo_process_checkpoint(MigrationState *s)
{

    hash_init();

    colo_primary_transfer = false;

    QEMUSizedBuffer *buffer = NULL;
    int64_t current_time, checkpoint_time = qemu_clock_get_ms(QEMU_CLOCK_HOST);
    Error *local_err = NULL;
    int ret;

    ret = mc_enable_buffering();
    if (ret > 0) {

    } else {
        if (ret < 0 || mc_start_buffer() < 0) {

        }
    }

    rdma_buffer = mc_rdma_get_colo_ctrl_buffer_ptr();
    
    failover_init_state();

    s->rp_state.from_dst_file = qemu_file_get_return_path(s->to_dst_file);
    if (!s->rp_state.from_dst_file) {
        error_report("Open QEMUFile from_dst_file failed");
        goto out;
    }

    ret = colo_prepare_before_save(s);
    if (ret < 0) {
        goto out;
    }

    /*
     * Wait for Secondary finish loading vm states and enter COLO
     * restore.
     */
    colo_receive_check_message(s->rp_state.from_dst_file,
                        COLO_MESSAGE_CHECKPOINT_READY, &local_err);

    if (local_err) {
        goto out;
    }

    buffer = qsb_create(NULL, COLO_BUFFER_BASE_SIZE);
    if (buffer == NULL) {
        error_report("Failed to allocate colo buffer!");
        goto out;
    }

    qemu_mutex_lock_iothread();
    /* start block replication */
    replication_start_all(REPLICATION_MODE_PRIMARY, &local_err);
    if (local_err) {
        qemu_mutex_unlock_iothread();
        goto out;
    }

    vm_start();
    qemu_mutex_unlock_iothread();
    trace_colo_vm_state_change("stop", "run");

    ret = global_state_store();
    if (ret < 0) {
        goto out;
    }

    sync_type = proxy_get_sync_type();
    *(int*)rdma_buffer = sync_type;
    mc_rdma_put_colo_ctrl_buffer(sizeof(sync_type));

    recheck_count = proxy_get_recheck_num();
    colo_debug = proxy_get_colo_debug();

    sleep(2);

    learn_idle_clock_rate();

    nl_init();

    colo_gettime = proxy_get_colo_gettime();

    while (s->state == MIGRATION_STATUS_COLO) {
        if (failover_request_is_active()) {
            error_report("failover request");
            goto out;
        }

        // if (colo_compare_result()) {
        //     goto checkpoint_begin;
        // }
        current_time = qemu_clock_get_ms(QEMU_CLOCK_HOST);
        // if ((current_time - checkpoint_time <
        //     s->parameters[MIGRATION_PARAMETER_X_CHECKPOINT_DELAY]) &&
        //     !colo_shutdown_requested) {
        //     g_usleep(10 * 1000); /* 10 ms */
        //     continue;
        // }

checkpoint_begin:
        /* start a colo checkpoint */
        ret = colo_do_checkpoint_transaction(s, buffer);
        if (ret < 0) {
            goto out;
        }
        checkpoint_time = qemu_clock_get_ms(QEMU_CLOCK_HOST);
    }

out:
    /* Throw the unreported error message after exited from loop */
    if (local_err) {
        error_report_err(local_err);
    }
    /*
    * There are only two reasons we can go here, something error happened,
    * Or users triggered failover.
    */
    if (!failover_request_is_active()) {
        qapi_event_send_colo_exit(COLO_MODE_PRIMARY,
                                  COLO_EXIT_REASON_ERROR, NULL);
    } else {
        qapi_event_send_colo_exit(COLO_MODE_PRIMARY,
                                  COLO_EXIT_REASON_REQUEST, NULL);
    }

    qsb_free(buffer);
    buffer = NULL;

    /* Hope this not to be too long to wait here */
    qemu_sem_wait(&s->colo_sem);
    qemu_sem_destroy(&s->colo_sem);
    /*
    * Must be called after failover BH is completed,
    * Or the failover BH may shutdown the wrong fd, that
    * re-used by other thread after we release here.
    */
    if (s->rp_state.from_dst_file) {
        qemu_fclose(s->rp_state.from_dst_file);
    }
}

void migrate_start_colo_process(MigrationState *s)
{
    qemu_mutex_unlock_iothread();
    qemu_sem_init(&s->colo_sem, 0);
    migrate_set_state(&s->state, MIGRATION_STATUS_ACTIVE,
                      MIGRATION_STATUS_COLO);
    colo_process_checkpoint(s);
    qemu_mutex_lock_iothread();
}

static void colo_wait_handle_message(QEMUFile *f, int *checkpoint_request,
                                     Error **errp)
{
    COLOMessage msg;
    Error *local_err = NULL;

    msg = colo_receive_message(f, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    switch (msg) {
    case COLO_MESSAGE_CHECKPOINT_REQUEST:
        *checkpoint_request = 1;
        break;
    case COLO_MESSAGE_GUEST_SHUTDOWN:
        qemu_mutex_lock_iothread();
        vm_stop_force_state(RUN_STATE_COLO);
        replication_stop_all(false, NULL);
        qemu_system_shutdown_request_core();
        qemu_mutex_unlock_iothread();
        /* the main thread will exit and terminate the whole
        * process, do we need some cleanup?
        */
        qemu_thread_exit(0);
    default:
        *checkpoint_request = 0;
        error_setg(errp, "Got unknown COLO message: %d", msg);
        break;
    }
}

static void mc_wait_handle_message(int *checkpoint_request, Error **errp)
{
    COLOMessage msg;

    msg = mc_receive_message();

    switch (msg) {
    case COLO_MESSAGE_CHECKPOINT_REQUEST:
        *checkpoint_request = 1;
        break;
    case COLO_MESSAGE_GUEST_SHUTDOWN:
        qemu_mutex_lock_iothread();
        vm_stop_force_state(RUN_STATE_COLO);
        replication_stop_all(false, NULL);
        qemu_system_shutdown_request_core();
        qemu_mutex_unlock_iothread();
        /* the main thread will exit and terminate the whole
        * process, do we need some cleanup?
        */
        qemu_thread_exit(0);
    default:
        *checkpoint_request = 0;
        error_setg(errp, "Got unknown COLO message: %d", msg);
        break;
    }
}

static int colo_prepare_before_load(QEMUFile *f)
{
    int ret;

    ret = qemu_loadvm_state_begin(f);
    if (ret < 0) {
        error_report("load vm state begin error, ret=%d", ret);
    }
    return ret;
}

void *colo_process_incoming_thread(void *opaque)
{
    hash_init();

    MigrationIncomingState *mis = opaque;
    QEMUFile *fb = NULL;
    QEMUSizedBuffer *buffer = NULL; /* Cache incoming device state */
    uint64_t total_size;
    uint64_t value;
    Error *local_err = NULL;
    int ret;

    rdma_buffer = mc_rdma_get_colo_ctrl_buffer_ptr();

    qemu_sem_init(&mis->colo_incoming_sem, 0);

    migrate_set_state(&mis->state, MIGRATION_STATUS_ACTIVE,
                      MIGRATION_STATUS_COLO);

    failover_init_state();

    mis->to_src_file = qemu_file_get_return_path(mis->from_src_file);
    if (!mis->to_src_file) {
        error_report("colo incoming thread: Open QEMUFile to_src_file failed");
        goto out;
    }
    /* Note: We set the fd to unblocked in migration incoming coroutine,
     * But here we are in the colo incoming thread, so it is ok to set the
     * fd back to blocked.
     */
    qemu_file_set_blocking(mis->from_src_file, true);

    //XS: backup init global variables; 
    //rdma_backup_init();


    ret = colo_init_ram_cache();
    // if (ret < 0) {
    //     error_report("Failed to initialize ram cache");
    //     goto out;
    // }

    buffer = qsb_create(NULL, COLO_BUFFER_BASE_SIZE);
    if (buffer == NULL) {
        error_report("Failed to allocate colo buffer!");
        goto out;
    }

    ret = colo_prepare_before_load(mis->from_src_file);
    if (ret < 0) {
        goto out;
    }

    qemu_mutex_lock_iothread();
    bdrv_invalidate_cache_all(&local_err);
    /* start block replication */
    replication_start_all(REPLICATION_MODE_SECONDARY, &local_err);
    qemu_mutex_unlock_iothread();
    if (local_err) {
        goto out;
    }

    colo_send_message(mis->to_src_file, COLO_MESSAGE_CHECKPOINT_READY,
                       &local_err);

    if (local_err) {
        goto out;
    }

    mc_rdma_get_colo_ctrl_buffer(sizeof(sync_type));
    sync_type = *(int*)rdma_buffer;
    recheck_count = proxy_get_recheck_num();
    colo_debug = proxy_get_colo_debug();
    sleep(2);
    learn_idle_clock_rate();

    nl_init();

    colo_gettime = proxy_get_colo_gettime();

    while (mis->state == MIGRATION_STATUS_COLO) {
        int request;
        // colo_wait_handle_message(mis->from_src_file, &request, &local_err);

        proxy_wait_checkpoint_req();
        request = 1;
        disable_apply_committed_entries();

        if (local_err) {
            goto out;
        }
        assert(request);
        if (failover_request_is_active()) {
            error_report("failover request");
            goto out;
        }

        if (sync_type == CHECK_IDLE_SYNC) {
            wait_guest_finish(NULL, false);
        }

        qemu_mutex_lock_iothread();
        vm_stop_force_state(RUN_STATE_COLO);
        //trace_colo_vm_state_change("run", "stop");
        qemu_mutex_unlock_iothread();

        resume_apply_committed_entries();

        // colo_receive_check_message(mis->from_src_file,
        //                    COLO_MESSAGE_VMSTATE_SEND, &local_err);
        // mc_receive_check_message(COLO_MESSAGE_VMSTATE_SEND, &local_err);

        backup_prepare_bitmap();

        if (local_err) {
            goto out;
        }

        migrate_use_mc_rdma = true;
        ret = qemu_loadvm_state_main(mis->from_src_file, mis);
        if (ret < 0) {
            error_report("Load VM's live state (ram) error");
            goto out;
        }

        migrate_use_mc_rdma = false;
        /* read the VM state total size first */
        // value = colo_receive_message_value(mis->from_src_file,
        //                           COLO_MESSAGE_VMSTATE_SIZE, &local_err);
        
        value = mc_receive_message_value(COLO_MESSAGE_VMSTATE_SIZE, &local_err);


        if (local_err) {
            goto out;
        }

        total_size = mc_rdma_get_colo_ctrl_buffer(value);

        if (total_size != value) {
            error_report("Got %lu VMState data, less than expected %lu",
                         total_size, value);
            ret = -EINVAL;
            goto out;
        }
        /* read vm device state into colo buffer */
        total_size = mc_qsb_fill_buffer(buffer, rdma_buffer, value);

        // total_size = qsb_fill_buffer(buffer, mis->from_src_file, value);
        if (total_size != value) {
            error_report("Got %lu VMState data, less than expected %lu",
                         total_size, value);
            ret = -EINVAL;
            goto out;
        }

        // colo_send_message(mis->to_src_file, COLO_MESSAGE_VMSTATE_RECEIVED,
        //               &local_err);
        //mc_send_message(COLO_MESSAGE_VMSTATE_RECEIVED,&local_err);
        if (local_err) {
            goto out;
        }

        /* open colo buffer for read */
        fb = qemu_bufopen("r", buffer);
        if (!fb) {
            error_report("Can't open colo buffer for read");
            goto out;
        }
        
        qemu_mutex_lock_iothread();
        uint64_t system_reset_start;
        if (colo_gettime) {
            system_reset_start = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
        }  

        qemu_system_reset(VMRESET_SILENT);
        
        if (colo_gettime) {
            int64_t system_reset_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - system_reset_start;
            fprintf(stderr, "system_reset_time: %"PRId64"\n", system_reset_time);
        }

        vmstate_loading = true;

        mc_clear_backup_bmap(); //clear the bakcup bitmap to zeros

        uint64_t load_device_start;
        if (colo_gettime) {
            load_device_start = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
        }   
        ret = qemu_load_device_state(fb);

        if (colo_gettime) {
            int64_t load_device_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - load_device_start;
            fprintf(stderr, "qemu_load_device_state: %"PRId64"\n", load_device_time);
        }

        if (ret < 0) {
            error_report("COLO: load device state failed");
            qemu_mutex_unlock_iothread();
            goto out;
        }

        replication_get_error_all(&local_err);
        if (local_err) {
            qemu_mutex_unlock_iothread();
            goto out;
        }

        uint64_t do_checkpoint_all_start;
        if (colo_gettime) {
            do_checkpoint_all_start = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
        }

        /* discard colo disk buffer */
        replication_do_checkpoint_all(&local_err);
        if (local_err) {
            qemu_mutex_unlock_iothread();
            goto out;
        }

        if (colo_gettime) {
            int64_t do_checkpoint_all_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - do_checkpoint_all_start;
            fprintf(stderr, "do_checkpoint_all_time: %"PRId64"\n", do_checkpoint_all_time);
        }

        vmstate_loading = false;

        if (failover_get_state() == FAILOVER_STATUS_RELAUNCH) {
            failover_set_state(FAILOVER_STATUS_RELAUNCH, FAILOVER_STATUS_NONE);
            failover_request_active(NULL);
            goto out;
        }

        // colo_send_message(mis->to_src_file, COLO_MESSAGE_VMSTATE_LOADED,
        //               &local_err);
        mc_send_message(COLO_MESSAGE_VMSTATE_LOADED,&local_err);
        if (local_err) {
            goto out;
        }

        control_clock = true;
        vm_start();
        control_clock = false;
        //trace_colo_vm_state_change("stop", "run");
        qemu_mutex_unlock_iothread();
        qemu_fclose(fb);
        fb = NULL;
    }

out:
     vmstate_loading = false;
    /* Throw the unreported error message after exited from loop */
    if (local_err) {
        error_report_err(local_err);
    }
    if (!failover_request_is_active()) {
        qapi_event_send_colo_exit(COLO_MODE_SECONDARY,
                                  COLO_EXIT_REASON_ERROR, NULL);
    } else {
        qapi_event_send_colo_exit(COLO_MODE_SECONDARY,
                                  COLO_EXIT_REASON_REQUEST, NULL);
    }

    if (fb) {
        qemu_fclose(fb);
    }
    qsb_free(buffer);
    /* Here, we can ensure BH is hold the global lock, and will join colo
    * incoming thread, so here it is not necessary to lock here again,
    * or there will be a deadlock error.
    */
    colo_release_ram_cache();

    /* Hope this not to be too long to loop here */
    qemu_sem_wait(&mis->colo_incoming_sem);
    qemu_sem_destroy(&mis->colo_incoming_sem);
    /* Must be called after failover BH is completed */
    if (mis->to_src_file) {
        qemu_fclose(mis->to_src_file);
    }
    migration_incoming_exit_colo();

    return NULL;
}

bool colo_shutdown(void)
{
    /*
    * if in colo mode, we need do some significant work before respond
    * to the shutdown request.
    */
    if (migration_incoming_in_colo_state()) {
        return true; /* primary's responsibility */
    }
    if (migration_in_colo_state()) {
        colo_shutdown_requested = 1;
        return true;
    }
    return false;
}
