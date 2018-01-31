#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/genetlink.h>
#include <linux/taskstats.h>
#include "rsm-interface.h"

#include "qemu/osdep.h"
#include "sysemu/sysemu.h"

#define GENLMSG_DATA(glh)	((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)	(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)		((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len)	(len - NLA_HDRLEN)

#define err(code, fmt, arg...)			\
	do {					\
		fprintf(stderr, fmt, ##arg);	\
		exit(code);			\
	} while (0)

int done;
int print_delays;
char name[100];
int dbg;

#define PRINTF(fmt, arg...) {			\
	    if (dbg) {				\
		printf(fmt, ##arg);		\
	    }					\
	}

/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE	1024

struct msgtemplate {
	struct nlmsghdr n;
	struct genlmsghdr g;
	char buf[MAX_MSG_SIZE];
};

int rcvbufsz;

static int create_nl_socket(int protocol)
{
	int fd;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0)
		return -1;

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0)
		goto error;

	return fd;
error:
	close(fd);
	return -1;
}

static int send_cmd(int sd, __u16 nlmsg_type, __u32 nlmsg_pid,
	     __u8 genl_cmd, __u16 nla_type,
	     void *nla_data, int nla_len)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen;
	char *buf;

	struct msgtemplate msg;

	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = NLM_F_REQUEST;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = nlmsg_pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = 0x1;
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + 1 + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len ;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr))) < buflen) {
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN)
			return -1;
	}
	return 0;
}

static int get_family_id(int sd)
{
	struct {
		struct nlmsghdr n;
		struct genlmsghdr g;
		char buf[256];
	} ans;

	int id = 0, rc;
	struct nlattr *na;
	int rep_len;

	strcpy(name, TASKSTATS_GENL_NAME);
	rc = send_cmd(sd, GENL_ID_CTRL, getpid(), CTRL_CMD_GETFAMILY,
			CTRL_ATTR_FAMILY_NAME, (void *)name,
			strlen(TASKSTATS_GENL_NAME)+1);
	if (rc < 0)
		return 0;	/* sendto() failure? */

	rep_len = recv(sd, &ans, sizeof(ans), 0);
	if (ans.n.nlmsg_type == NLMSG_ERROR ||
	    (rep_len < 0) || !NLMSG_OK((&ans.n), rep_len))
		return 0;

	na = (struct nlattr *) GENLMSG_DATA(&ans);
	na = (struct nlattr *) ((char *) na + NLA_ALIGN(na->nla_len));
	if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
		id = *(__u16 *) NLA_DATA(na);
	}
	return id;
}

pid_t tid = 0;
int nl_sd = -1;
int cmd_type = TASKSTATS_CMD_ATTR_UNSPEC;
__u32 mypid;
__u16 id;
int nl_init(void)
{
	tid = getpid();

	cmd_type = TASKSTATS_CMD_ATTR_TGID;

	if ((nl_sd = create_nl_socket(NETLINK_GENERIC)) < 0)
		err(1, "error creating Netlink socket\n");

	mypid = getpid();

	id = get_family_id(nl_sd);
	if (!id) {
		fprintf(stderr, "Error getting family id, errno %d\n", errno);
	}
	PRINTF("family id %d\n", id);
}

static unsigned long long nl_blk_delay(void)
{
	struct nlattr *na;
	int rc, rep_len, aggr_len, len2;

	int len = 0;
	int count = 0;
	int fd = 0;
	pid_t rtid = 0;

	int loop = 0;
	loop = 1; /* listen forever */
	print_delays = 1;
	unsigned long long ret;

	struct msgtemplate msg;

	// do {

		rc = send_cmd(nl_sd, id, mypid, TASKSTATS_CMD_GET,
			      cmd_type, &tid, sizeof(__u32));
		PRINTF("Sent pid/tgid, retval %d\n", rc);
		if (rc < 0) {
			fprintf(stderr, "error sending tid/tgid cmd\n");
			goto done;
		}

		rep_len = recv(nl_sd, &msg, sizeof(msg), 0);
		PRINTF("received %d bytes\n", rep_len);

		if (rep_len < 0) {
			fprintf(stderr, "nonfatal reply error: errno %d\n",
				errno);
			//continue;
		}
		if (msg.n.nlmsg_type == NLMSG_ERROR ||
		    !NLMSG_OK((&msg.n), rep_len)) {
			struct nlmsgerr *err = NLMSG_DATA(&msg);
			fprintf(stderr, "fatal reply error,  errno %d\n",
				err->error);
			goto done;
		}

		PRINTF("nlmsghdr size=%zu, nlmsg_len=%d, rep_len=%d\n",
		       sizeof(struct nlmsghdr), msg.n.nlmsg_len, rep_len);


		rep_len = GENLMSG_PAYLOAD(&msg.n);

		na = (struct nlattr *) GENLMSG_DATA(&msg);
		len = 0;

		while (len < rep_len) {
			len += NLA_ALIGN(na->nla_len);
			switch (na->nla_type) {
			case TASKSTATS_TYPE_AGGR_TGID:
				/* Fall through */
			case TASKSTATS_TYPE_AGGR_PID:
				aggr_len = NLA_PAYLOAD(na->nla_len);
				len2 = 0;
				/* For nested attributes, na follows */
				na = (struct nlattr *) NLA_DATA(na);
				done = 0;
				while (len2 < aggr_len) {
					switch (na->nla_type) {
					case TASKSTATS_TYPE_PID:
						rtid = *(int *) NLA_DATA(na);
						//if (print_delays)
							//printf("PID\t%d\n", rtid);
						break;
					case TASKSTATS_TYPE_TGID:
						rtid = *(int *) NLA_DATA(na);
						//if (print_delays)
							//printf("TGID\t%d\n", rtid);
						break;
					case TASKSTATS_TYPE_STATS:
						count++;
						struct taskstats *t = (struct taskstats *) NLA_DATA(na);
						ret = t->blkio_delay_total;

						if (fd) {
							if (write(fd, NLA_DATA(na), na->nla_len) < 0) {
								err(1,"write error\n");
							}
						}
						if (!loop)
							goto done;
						break;
					default:
						fprintf(stderr, "Unknown nested"
							" nla_type %d\n",
							na->nla_type);
						break;
					}
					len2 += NLA_ALIGN(na->nla_len);
					na = (struct nlattr *) ((char *) na + len2);
				}
				break;

			default:
				fprintf(stderr, "Unknown nla_type %d\n",
					na->nla_type);
			case TASKSTATS_TYPE_NULL:
				break;
			}
			na = (struct nlattr *) (GENLMSG_DATA(&msg) + len);
		}
	// } while (loop);
done:
err:
	// close(nl_sd);
	// if (fd)
	// 	close(fd);
	return ret;
}

#define disk_sleep_time 1000
#define disk_threshold 100

int check_disk_usage(void)
{
	int i = 0;
	unsigned long long start, end;

    start = nl_blk_delay();
    g_usleep(disk_sleep_time);
    end = nl_blk_delay();
    static int colo_gettime = -1; 
    if(colo_gettime==-1)
        proxy_get_colo_gettime();

    if (colo_gettime)
        fprintf(stderr, "DISK: %llu\n", end - start);

    if (end - start > disk_threshold) {
    	return 1;
    }

	return 0;
}

#define cpu_sleep_time 100
#define cpu_threshold 150

int check_cpu_usage(void)
{
	clock_t start, end;

    start = clock();
    g_usleep(cpu_sleep_time);
    end = clock();
    static int colo_gettime = -1;
    if(colo_gettime==-1)
	proxy_get_colo_gettime();

    if (colo_gettime)
        fprintf(stderr, "CPU: %d\n", (int)(end-start));
    if ((end - start) > cpu_threshold) {
    	return 1;
    }

    return 0;
}
