#include "../include/proxy/proxy.h"
#include "../include/config-comp/config-proxy.h"
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include "../include/dare/dare_server.h"
#include "../include/dare/message.h"
#define __STDC_FORMAT_MACROS

static void stablestorage_save_request(void* data,void*arg);
static void stablestorage_dump_records(void*buf,void*arg);
static uint32_t stablestorage_get_records_len(void*arg);
static int stablestorage_load_records(void*buf,uint32_t size,void*arg);
static void update_highest_rec(void*arg);
static void set_filter_mirror_fd(void*arg,int fd);
static void do_action_to_server(uint16_t clt_id,uint8_t type,size_t data_size,void* data,void *arg);
static void do_action_send(size_t data_size,void* data,void* arg);
static int set_blocking(int fd, int blocking);

FILE *log_fp;

proxy_node* proxy;

const char* config_path = "../rdma-paxos/target/nodes.local.cfg";

volatile static int checkpoint_req_status;

int dare_main(proxy_node* proxy, uint8_t role)
{
    int rc; 
    dare_server_input_t *input = (dare_server_input_t*)malloc(sizeof(dare_server_input_t));
    memset(input, 0, sizeof(dare_server_input_t));
    input->log = stdout;
    input->name = "";
    input->output = "dare_servers.out";
    input->srv_type = SRV_TYPE_START;
    input->sm_type = CLT_KVS;

    input->server_idx = role;

    input->group_size = 3;
    char *group_size = getenv("group_size");
    if (group_size != NULL)
        input->group_size = (uint8_t)atoi(group_size);

    input->do_action = do_action_to_server;
    input->store_cmd = stablestorage_save_request;
    input->get_db_size = stablestorage_get_records_len;
    input->create_db_snapshot = stablestorage_dump_records;
    input->apply_db_snapshot = stablestorage_load_records;
    input->update_state = update_highest_rec;
    input->set_qemu_chardev = set_filter_mirror_fd;
    memcpy(input->config_path, config_path, strlen(config_path));
    input->up_para = proxy;
    static int srv_type = SRV_TYPE_START;

    const char *server_type = getenv("server_type");
    if (server_type != NULL) {
        if (strcmp(server_type, "join") == 0) {
            srv_type = SRV_TYPE_JOIN;
        }
    }
    char *dare_log_file = getenv("dare_log_file");
    if (dare_log_file == NULL)
        dare_log_file = "";

    input->srv_type = srv_type;
    
    pthread_mutex_t dare_ready_lock;
    if(pthread_mutex_init(&dare_ready_lock, NULL)){
        err_log("PROXY: Cannot init dare ready lock\n");
    }
    pthread_cond_t dare_ready_cond;
    if(pthread_cond_init(&dare_ready_cond, NULL)){
        err_log("PROXY: Cannot init dare ready cond\n");
    }
    input->dare_ready_lock = &dare_ready_lock;
    input->dare_ready_cond = &dare_ready_cond;
    int dare_init_status = DARE_STARTING;
    input->dare_init_status = &dare_init_status;

    if (strcmp(dare_log_file, "") != 0) {
        input->log = fopen(dare_log_file, "w+");
        if (input->log==NULL) {
            printf("Cannot open log file\n");
            exit(1);
        }
    }
    if (SRV_TYPE_START == input->srv_type) {
        if (0xFF == input->server_idx) {
            printf("A server cannot start without an index\n");
            exit(1);
        }
    }
    pthread_t dare_thread;
    rc = pthread_create(&dare_thread, NULL, &dare_server_init, input);
    if (0 != rc) {
        fprintf(log_fp, "Cannot init dare_thread\n");
        return 1;
    }

    pthread_mutex_lock(&dare_ready_lock);
    while(1) {
        //Wait for a signal
        pthread_cond_wait(&dare_ready_cond, &dare_ready_lock);

        if (dare_init_status == DARE_STARTING) {
            //Not ready yet, keep waiting
            continue;
        } else {
            break;
        }
    }
    pthread_mutex_unlock(&dare_ready_lock);

    list_entry_t *n1 = malloc(sizeof(list_entry_t));
    n1->tid = dare_thread;
    LIST_INSERT_HEAD(&listhead, n1, entries);
    //fclose(log_fp);

    free(input);
    
    return 0;
}

static void leader_handle_submit_req(void* buf, ssize_t data_size, uint8_t type)
{
    assert(data_size <= IO_BUF_SIZE);

    pthread_spin_lock(&tailq_lock);
    uint64_t cur_rec = ++proxy->cur_rec;

    tailq_entry_t* n2 = (tailq_entry_t*)malloc(sizeof(tailq_entry_t));
    n2->req_id = ++proxy->sync_req_id;
    n2->connection_id = type == MIRROR ? MIRROR_CONNECTION : CHECKPOINT_CTRL_CONNECTION;
    n2->type = type;
    n2->cmd.len = data_size;
    if (data_size)
        memcpy(n2->cmd.cmd, buf, data_size);
    TAILQ_INSERT_TAIL(&tailhead, n2, entries);

    pthread_spin_unlock(&tailq_lock);

    while (cur_rec > proxy->highest_rec);
}

static int set_blocking(int fd, int blocking) {
    int flags;

    if ((flags = fcntl(fd, F_GETFL)) == -1) {
        fprintf(stderr, "fcntl(F_GETFL): %s", strerror(errno));
    }

    if (blocking)
        flags &= ~O_NONBLOCK;
    else
        flags |= O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) == -1) {
        fprintf(stderr, "fcntl(F_SETFL,O_NONBLOCK): %s", strerror(errno));
    }
    return 0;
}

void proxy_on_mirror(uint8_t *buf, int len)
{
    leader_handle_submit_req(buf, len, MIRROR);
    return;
}

void proxy_on_checkpoint_req(void)
{
    leader_handle_submit_req(NULL, 0, CHECKPOINT);
    return;
}

void proxy_wait_checkpoint_req(void)
{
    while (checkpoint_req_status != CHECKPOINT_REQ_READY);
    checkpoint_req_status = CHECKPOINT_REQ_WAIT;
    return;
}

static void update_highest_rec(void*arg)
{
    proxy_node* proxy = arg;
    proxy->highest_rec++;   
}

static void set_filter_mirror_fd(void*arg, int fd)
{
    proxy_node* proxy = arg;
    proxy->mirror_clientfd = fd;
}

int control_tsc(void)
{
    return proxy->control_tsc;
}

int proxy_get_sync_type(void)
{
    return proxy->sync_type;
}

int proxy_get_recheck_num(void)
{
    return proxy->recheck_num;
}

int proxy_get_colo_debug(void)
{
    return proxy->colo_debug;
}

int proxy_get_colo_gettime(void)
{
    return proxy->colo_gettime;
}

static void stablestorage_save_request(void* data,void*arg)
{
    proxy_node* proxy = arg;
    proxy_msg_header* header = (proxy_msg_header*)data;
    switch(header->action){
        case MIRROR:
        {
            proxy_send_msg* send_msg = (proxy_send_msg*)data;
            store_record(proxy->db_ptr,PROXY_SEND_MSG_SIZE(send_msg),data);
            break;
        }
        case CHECKPOINT:
        {
            store_record(proxy->db_ptr,PROXY_CHECKPOINT_MSG_SIZE,data);
            break;
        }
    }
}

static uint32_t stablestorage_get_records_len(void*arg)
{
    proxy_node* proxy = arg;
    uint32_t records_len = get_records_len(proxy->db_ptr);
    return records_len;
}

static void stablestorage_dump_records(void*buf,void*arg)
{
    proxy_node* proxy = arg;
    dump_records(proxy->db_ptr,buf);
}

static int stablestorage_load_records(void*buf,uint32_t size,void*arg)
{
    proxy_node* proxy = arg;
    proxy_msg_header* header;
    uint32_t len = 0;
    while(len < size) {
        header = (proxy_msg_header*)((char*)buf + len);
        switch(header->action){
            case MIRROR:
            {
                proxy_send_msg* send_msg = (proxy_send_msg*)header;
                len += PROXY_SEND_MSG_SIZE(send_msg);
                store_record(proxy->db_ptr,PROXY_SEND_MSG_SIZE(send_msg),header);
                do_action_send(send_msg->data.cmd.len, send_msg->data.cmd.cmd, arg);
                break;
            }
            case CHECKPOINT:
            {
                len += PROXY_CHECKPOINT_MSG_SIZE;
                store_record(proxy->db_ptr,PROXY_CHECKPOINT_MSG_SIZE,header);
                break;
            }
        }
    }
    return 0;
}

static void do_action_send(size_t data_size,void* data,void* arg)
{
    proxy_node* proxy = arg;
    uint32_t len = htonl(data_size);

    int n = send(proxy->mirror_clientfd, &len, sizeof(len), 0);
    if (n < 0)
        fprintf(stderr, "ERROR writing to socket!\n");

    n = send(proxy->mirror_clientfd, data, data_size, 0);
    if (n < 0)
        fprintf(stderr, "ERROR writing to socket!\n");

    proxy->sync_req_id++;
}

static void do_action_to_server(uint16_t clt_id,uint8_t type,size_t data_size,void* data,void*arg)
{
    proxy_node* proxy = arg;
    FILE* output = NULL;
    if(proxy->req_log){
        output = proxy->req_log_file;
    }

    switch(type) {
        case MIRROR:
        {
            do_action_send(data_size, data, arg);
            break;
        }
        case CHECKPOINT:
        {
            checkpoint_req_status = CHECKPOINT_REQ_READY;
            break;
        }
    }

    return;
}

proxy_node* proxy_init(const char* proxy_log_path, uint8_t role)
{
    proxy = (proxy_node*)malloc(sizeof(proxy_node));

    if(NULL==proxy){
        err_log("PROXY : Cannot Malloc Memory For The Proxy.\n");
        goto proxy_exit_error;
    }

    memset(proxy,0,sizeof(proxy_node));
    
    if(proxy_read_config(proxy,config_path)){
        err_log("PROXY : Configuration File Reading Error.\n");
        goto proxy_exit_error;
    }

    int build_log_ret = 0;
    if(proxy_log_path==NULL){
        proxy_log_path = ".";
    }else{
        if((build_log_ret=mkdir(proxy_log_path,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))!=0){
            if(errno!=EEXIST){
                err_log("PROXY : Log Directory Creation Failed,No Log Will Be Recorded.\n");
            }else{
                build_log_ret = 0;
            }
        }
    }

    if(!build_log_ret){
        //if(proxy->sys_log || proxy->stat_log){
            char* sys_log_path = (char*)malloc(sizeof(char)*strlen(proxy_log_path)+50);
            memset(sys_log_path,0,sizeof(char)*strlen(proxy_log_path)+50);
            //err_log("%s.\n",proxy_log_path);
            if(NULL!=sys_log_path){
                sprintf(sys_log_path,"%s/node-proxy-sys.log",proxy_log_path);
                //err_log("%s.\n",sys_log_path);
                proxy->sys_log_file = fopen(sys_log_path,"w");
                free(sys_log_path);
            }
            if(NULL==proxy->sys_log_file && (proxy->sys_log || proxy->stat_log)){
                err_log("PROXY : System Log File Cannot Be Created.\n");
            }
        //}
        //if(proxy->req_log){
            char* req_log_path = (char*)malloc(sizeof(char)*strlen(proxy_log_path)+50);
            memset(req_log_path,0,sizeof(char)*strlen(proxy_log_path)+50);
            if(NULL!=req_log_path){
                sprintf(req_log_path,"%s/node-proxy-req.log",proxy_log_path);
                //err_log("%s.\n",req_log_path);
                proxy->req_log_file = fopen(req_log_path,"w");
                free(req_log_path);
            }
            if(NULL==proxy->req_log_file && proxy->req_log){
                err_log("PROXY : Client Request Log File Cannot Be Created.\n");
            }
        //}
    }    

    TAILQ_INIT(&tailhead);
    LIST_INIT(&listhead);

    proxy->db_ptr = initialize_db(proxy->db_name,0);

    proxy->follower_hash_map = NULL;
    proxy->leader_hash_map = NULL;

    if(pthread_spin_init(&tailq_lock, PTHREAD_PROCESS_PRIVATE)){
        err_log("PROXY: Cannot init the lock\n");
    }

    checkpoint_req_status = CHECKPOINT_REQ_WAIT;

    dare_main(proxy, role);

    return proxy;

proxy_exit_error:
    if(NULL!=proxy){
        free(proxy);
    }
    return NULL;

}
