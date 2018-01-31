#ifndef RSM_INTERFACE_H
#define RSM_INTERFACE_H
#include <unistd.h>
#include <stdint.h>

struct proxy_node_t;

#define STANDBY_BACKUP 0
#define MAJOR_BACKUP   1
#define LEADER         2

#ifdef __cplusplus
extern "C" {
#endif

	struct proxy_node_t* proxy_init(const char* proxy_log_path, uint8_t role);
	void proxy_on_mirror(uint8_t *buf, int len);
	int is_leader(void);
	void proxy_wait_checkpoint_req(void);
	void proxy_on_checkpoint_req(void);
	int control_tsc(void);
	void disable_apply_committed_entries(void);
	void resume_apply_committed_entries(void);
	int proxy_get_sync_type(void);
	int proxy_get_recheck_num(void);
	int proxy_get_colo_debug(void);
	int proxy_get_colo_gettime(void);

#ifdef __cplusplus
}
#endif

#endif
