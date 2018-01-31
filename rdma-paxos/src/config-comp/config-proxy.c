#include "../include/util/common-header.h"
#include "../include/proxy/proxy.h"
#include <libconfig.h>


int proxy_read_config(struct proxy_node_t* cur_node,const char* config_path){
    config_t config_file;
    config_init(&config_file);

    if(!config_read_file(&config_file,config_path)){
        goto goto_config_error;
    }

    config_lookup_int(&config_file,"req_log",&cur_node->req_log);
    config_lookup_int(&config_file,"sys_log",&cur_node->sys_log);
    config_lookup_int(&config_file,"stat_log",&cur_node->stat_log);
    config_lookup_int(&config_file,"control_tsc",&cur_node->control_tsc);
    config_lookup_int(&config_file,"colo_debug",&cur_node->colo_debug);
    config_lookup_int(&config_file,"recheck_num",&cur_node->recheck_num);
    config_lookup_int(&config_file,"sync_type",&cur_node->sync_type);
    config_lookup_int(&config_file,"colo_gettime",&cur_node->colo_gettime);

    const char* db_name;
    if(!config_lookup_string(&config_file,"db_name",&db_name)){
        goto goto_config_error;
    }
    size_t db_name_len = strlen(db_name);
    cur_node->db_name = (char*)malloc(sizeof(char)*(db_name_len+1));
    if(cur_node->db_name==NULL){
        goto goto_config_error;
    }
    if(NULL==strncpy(cur_node->db_name,db_name,db_name_len)){
        free(cur_node->db_name);
        goto goto_config_error;
    }
    cur_node->db_name[db_name_len] = '\0';

    config_destroy(&config_file);
    return 0;

goto_config_error:
    err_log("%s:%d - %s\n", config_error_file(&config_file),
            config_error_line(&config_file), config_error_text(&config_file));
    config_destroy(&config_file);
    return -1;
}
