#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include "natunnel.h"
#include "ntlproto.h"

#define WAI_EXPIRE 3600
#define MINFREEPOOL 2
//#define MAGICWORD (htonl(0x8a8c1df4))
#define CTLMSG_INIT1 32896
#define CTLMSG_INIT2 32895
#define CTLMSG_FINI  32894
#define CTLMSG_OPEN1 32893
#define CTLMSG_OPEN2 32892
#define CTLMSG_CLOSE 32891
//#define CTLMSG_ALIVE 32890
#define CTLMSG_MAX   32889 // maximal size of message sent

struct tunnel_info {
	pthread_t threadid;
	int isfree; // is it in the free pool, TODO: can we just use prev!=NULL?
	int isactive;
	int control_pipe[2]; // [0] for read by tunnel thread, [1] for write by controling thread.
	int sock_int, sock_ext;
	struct tunnel_info *prev, *next; // double-linked list
};

char *option_serverip;
int option_serverport;
char *option_ntlid;
char *option_outip;
int option_outport;
int option_inport;
char option_role;
unsigned long timeoff_ttl = 100 * 1000000;
long long timeoff_off = 0; /* server time - local time */
struct tunnel_info free_pool_head; // dummy head
int free_pool_count;
pthread_mutex_t free_pool_mutex;

static int decode_msglen (const unsigned char *msg)
{
	return msg[0] * 256 + msg[1];
}
static void encode_msglen (unsigned char *msg, int n)
{
	assert(n >= 0 && n < 256 * 256);
	msg[0] = n >> 8;
	msg[1] = n & 0xff;
}

static void freepool_init (void)
{
	free_pool_head.prev = &free_pool_head;
	free_pool_head.next = &free_pool_head;
	free_pool_count = 0;
	pthread_mutex_init(&free_pool_mutex, NULL);
}

static void freepool_remove (struct tunnel_info *info)
{
	assert(info->isfree);
	assert(free_pool_count > 0);
	assert(info->next != NULL && info->prev != NULL);
	pthread_mutex_lock(&free_pool_mutex);
	info->isfree = 0;
	info->next->prev = info->prev;
	info->prev->next = info->next;
	info->prev = info->next = NULL;
	free_pool_count --;
	pthread_mutex_unlock(&free_pool_mutex);
}

static void freepool_add (struct tunnel_info *info)
{
	assert(!info->isfree);
	assert(info->next == NULL && info->prev == NULL);
	pthread_mutex_lock(&free_pool_mutex);
	info->isfree = 1;
	info->prev = free_pool_head.prev;
	info->next = &free_pool_head;
	free_pool_head.prev = info;
	info->prev->next = info;
	free_pool_count ++;
	pthread_mutex_unlock(&free_pool_mutex);
}

static struct tunnel_info *freepool_get (void)
{
	struct tunnel_info *info;
	if (free_pool_count == 0)
		return NULL;
	pthread_mutex_lock(&free_pool_mutex);
	if (free_pool_count == 0) {
		pthread_mutex_unlock(&free_pool_mutex);
		return NULL;
	}
	info = free_pool_head.next;
	assert(info->isfree);
	info->isfree = 0;
	free_pool_head.next = info->next;
	info->next->prev = &free_pool_head;
	info->prev = info->next = NULL;
	free_pool_count --;
	pthread_mutex_unlock(&free_pool_mutex);
	return info;
}

int do_stun (int istcp, int tworound, int *localport, struct sockaddr_in *extaddr)
{
	static struct ntl_struct *ntl = NULL;

	if (ntl == NULL) {
		struct sockaddr_in addr;
		assert(resolve_ipv4_address(&addr, option_serverip, option_serverport) == 0);
		ntl = ntl_init(&addr, NULL, option_ntlid);
		if (ntl == NULL)
			return -1;
	}

	return ntl_whoami(ntl, istcp, localport, extaddr, tworound) != 0;
}

# if 0
/* return: 0 time updated
 *         1 ttl is larger
 *         2 error */
static int do_timeoff (int ntlclient)
{
	int msglen;
	char msg[500];
	struct timeval tv;
	unsigned long long t1, t2;
	unsigned long ts_sec, ts_usec;

	assert(gettimeofday(&tv, NULL) == 0);
	t1 = tv.tv_sec * 1000000ll + tv.tv_usec;

	msglen = sprintf(msg, "TIME");
	if (send(ntlclient, msg, msglen, 0) != msglen)
		return 2;

	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;
	assert(setsockopt(ntlclient, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) == 0);
	msglen = recv(ntlclient, msg, sizeof(msg)-1, 0);
	if (msglen <= 0) {
		printf("recv TIME response failed\n");
		return 2;
	}
	msg[msglen] = '\0';
	puts(msg);
	if (sscanf(msg, "TIME_OK\t%lu\t%lu", &ts_sec, &ts_usec) != 2) {
		printf("TIME response error\n");
		return 2;
	}

	assert(gettimeofday(&tv, NULL) == 0);
	t2 = tv.tv_sec * 1000000ll + tv.tv_usec;

	if (t2 - t1 <= timeoff_ttl) {
		timeoff_ttl = t2 - t1;
		timeoff_off = ts_sec * 1000000 + ts_usec - (t2 + t1) / 2;
		printf("Time offset set to %ld (ttl=%lu)\n", (long)timeoff_off, timeoff_ttl);
		return 0;
	} else
		return 1;
}
#endif

static int tunnel_handshake (struct tunnel_info *info)
{
	unsigned char msgbuf[2];
	int msglen;

	if (info->isactive) {
		encode_msglen(msgbuf, CTLMSG_INIT1);
		if (send(info->sock_ext, msgbuf, 2, 0) != 2) {
			perror("tunnel_handshake() send to ext failed");
			return -1;
		}

		msglen = recv(info->sock_ext, msgbuf, 2, 0);
		if (msglen != 2) {
			perror("tunnel_handshake() recv from ext failed");
			return -1;
		}
		if (decode_msglen(msgbuf) != CTLMSG_INIT2) {
			printf("tunnel_handshake() expected CTLMSG_INIT2, but got %02x%02x\n", msgbuf[0], msgbuf[1]);
			return -1;
		}
	} else {
		msglen = recv(info->sock_ext, msgbuf, 2, 0);
		if (msglen != 2) {
			perror("tunnel_handshake() recv from ext failed");
			return -1;
		}
		if (decode_msglen(msgbuf) != CTLMSG_INIT1) {
			printf("tunnel_handshake() expected CTLMSG_INIT1, but got %02x%02x\n", msgbuf[0], msgbuf[1]);
			return -1;
		}

		encode_msglen(msgbuf, CTLMSG_INIT2);
		if (send(info->sock_ext, msgbuf, 2, 0) != 2) {
			perror("tunnel_handshake() send to ext failed");
			return -1;
		}
	}
	return 0;
}

static int tunnel_wait (struct tunnel_info *info)
{
	unsigned char msgbuf[2];
	fd_set rfds;
	int retval, msglen;

	if (info->isactive)
		freepool_add(info);

	FD_ZERO(&rfds);
	if (info->isactive)
		FD_SET(info->control_pipe[0], &rfds);
	FD_SET(info->sock_ext, &rfds);
	retval = select(info->control_pipe[0] > info->sock_ext ? info->control_pipe[0] + 1 : info->sock_ext + 1, &rfds, NULL, NULL, NULL);
	assert(retval == 1);
	if (info->isactive && FD_ISSET(info->control_pipe[0], &rfds)) {
		msglen = read(info->control_pipe[0], msgbuf, sizeof(msgbuf)); // we don't care about the contents
		assert(msglen == 1);
		assert(info->sock_int >= 0);
		assert(!info->isfree); // we should be already unfreed by the pipe writer.
		encode_msglen(msgbuf, CTLMSG_OPEN1);
		if (send(info->sock_ext, msgbuf, 2, 0) != 2) {
			perror("tunnel_wait() send to ext failed");
			return -1;
		}
		msglen = recv(info->sock_ext, msgbuf, 2, 0);
		if (msglen != 2) {
			perror("tunnel_wait() recv from ext failed");
			return -1;
		}
		if (decode_msglen(msgbuf) != CTLMSG_OPEN2) {
			printf("tunnel_wait() expected CTLMSG_OPEN2, but get %02x%02x\n", msgbuf[0], msgbuf[1]);
			return -1;
		}
	}
	if (FD_ISSET(info->sock_ext, &rfds)) {
		struct sockaddr_in addr;
		msglen = recv(info->sock_ext, msgbuf, 2, 0);
		if (msglen < 0) {
			perror("tunnel_wait() recv from ext failed");
			return -1;
		}
		if (msglen == 0) {
			printf("warning: ext sock close without FINI\n");
			return -1;
		}
		if (msglen != 2) {
			printf("tunnel_wait() recv from ext, expect msglen=2, but got %d\n", msglen);
			return -1;
		}
		if (decode_msglen(msgbuf) == CTLMSG_FINI) {
			printf("tunnel_wait() got FINI.\n");
			return -1;
		}
		if (info->isactive || decode_msglen(msgbuf) != CTLMSG_OPEN1) {
			printf("invalid state: active=%d, CTLMSG=%d\n",
					info->isactive,
					decode_msglen(msgbuf));
		}
		info->sock_int = socket(AF_INET, SOCK_STREAM, 0);
		assert(info->sock_int >= 0);
		assert(resolve_ipv4_address(&addr, option_outip, option_outport) == 0);
		assert(connect(info->sock_int, (struct sockaddr *)&addr, sizeof(addr)) == 0);
		encode_msglen(msgbuf, CTLMSG_OPEN2);
		if (send(info->sock_ext, msgbuf, 2, 0) != 2) {
			perror("tunnel_wait() send OPEN2 to ext failed");
			return -1;
		}
	}
	return 0;
}

/* two directions:
 *   up:   recv from int; send to ext
 *   down: recv from ext; send to int
 */
static int tunnel_data (struct tunnel_info *info)
{
	unsigned char bufup[2000], bufdown[2000];
	int uphead, uplen, downhead, downlen; // downhead=0: current packet is incomplete.
	int maxfd;
	int isactiveclose = -1; // active close: our side close first, we send CTLMSG_CLOSE. passive close: we receive CTLMSG_CLOSE.

	// CTLMSG_OPEN1/2 should be already send/recv.
	// no actual data should be send/recv.
	assert(info->sock_int >= 0 && info->sock_ext >= 0);
	uphead = uplen = downhead = downlen = 0;
	maxfd = info->sock_int > info->sock_ext ? info->sock_int + 1 : info->sock_ext + 1;
	while (1) {
		fd_set rfds, wfds; //TODO: how about OOB?

		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		if (uplen == 0)
			FD_SET(info->sock_int, &rfds);
		else
			FD_SET(info->sock_ext, &wfds);
		if (downhead == 0)
			FD_SET(info->sock_ext, &rfds);
		else
			FD_SET(info->sock_int, &wfds);

		assert(select(maxfd, &rfds, &wfds, NULL, NULL) > 0);

		if (FD_ISSET(info->sock_int, &rfds)) {
			int len = recv(info->sock_int, bufup + 2, sizeof(bufup) - 2, 0);
			if (len <= 0) {
				isactiveclose = 1;
				break;
			}
			encode_msglen(bufup, len);
			uphead = 0;
			uplen = len + 2;
		}
		if (FD_ISSET(info->sock_ext, &wfds)) {
			int len = send(info->sock_ext, bufup + uphead, uplen, 0);
			if (len <= 0) {
				perror("tunnel_data() send to ext failed");
				return -1;
			}
			uphead += len;
			uplen -= len;
		}
		if (FD_ISSET(info->sock_ext, &rfds)) {
			int torecv;
			if (downlen < 2)
				torecv = 2 - downlen;
			else
				torecv = decode_msglen(bufdown) + 2 - downlen;
			if (downlen + torecv > sizeof(bufdown)) {
				printf("malicious msglen\n");
				return -1;
			}
			int len = recv(info->sock_ext, bufdown + downlen, torecv, 0);
			if (len <= 0) {
				perror("tunnel_data() recv from ext failed");
				return -1;
			}
			downlen += len;
			if (downlen == 2) {
				int msglen = decode_msglen(bufdown);
				if (msglen == CTLMSG_FINI) {
					printf("tunnel_data() recved FINI\n");
					return -1;
				}
				if (msglen == CTLMSG_CLOSE) {
					isactiveclose = 0;
					break;
				}
				if (msglen > CTLMSG_MAX) {
					printf("unknown ctlmsg %d\n", msglen);
					return -1;
				}
			} else if (downlen > 2) {
				int msglen = decode_msglen(bufdown);
				assert(msglen <= CTLMSG_MAX);
				assert(downlen <= msglen + 2);
				if (downlen == msglen + 2)
					downhead = 2;
			}
		}
		if (FD_ISSET(info->sock_int, &wfds)) {
			assert(downhead >= 2);
			int msglen = decode_msglen(bufdown);
			assert(msglen <= CTLMSG_MAX);
			assert(downlen == msglen + 2);
			assert(downhead < downlen);
			int len = send(info->sock_int, bufdown + downhead, downlen - downhead, 0);
			if (len <= 0) {
				isactiveclose = 1;
				break;
			}
			downhead += len;
			assert(downhead <= downlen);
			if (downhead == downlen)
				downhead = downlen = 0;
		}
	}

	close(info->sock_int);
	info->sock_int = -1;
	// 1. send remaining bufup
	while (uphead < uplen) {
		int len = send(info->sock_ext, bufup + uphead, uplen, 0);
		if (len <= 0) {
			perror("tunnel_data() send to ext failed");
			return -1;
		}
		uphead += len;
		uplen -= len;
	}
	// 2. send CTLMSG_CLOSE
	encode_msglen(bufup, CTLMSG_CLOSE);
	uphead = 0;
	uplen = 2;
	while (uphead < uplen) {
		int len = send(info->sock_ext, bufup + uphead, uplen, 0);
		if (len <= 0) {
			perror("tunnel_data() send to ext failed");
			return -1;
		}
		uphead += len;
		uplen -= len;
	}
	// 3. receive CTLMSG_CLOSE if it's active
	if (downhead > 0)
		downhead = downlen = 0;
	while (isactiveclose) {
		int torecv;
		if (downlen < 2)
			torecv = 2 - downlen;
		else
			torecv = decode_msglen(bufdown) + 2 - downlen;
		if (downlen + torecv > sizeof(bufdown)) {
			printf("malicious msglen\n");
			return -1;
		}
		int len = recv(info->sock_ext, bufdown + downlen, torecv, 0);
		if (len <= 0) {
			perror("tunnel_data() recv from ext failed");
			return -1;
		}
		downlen += len;
		if (downlen == 2) {
			int msglen = decode_msglen(bufdown);
			if (msglen == CTLMSG_FINI) {
				printf("tunnel_data() recved FINI\n");
				return -1;
			}
			if (msglen == CTLMSG_CLOSE) {
				break;
			}
			if (msglen > CTLMSG_MAX) {
				printf("unknown ctlmsg %d\n", msglen);
				return -1;
			}
		} else if (downlen > 2) {
			int msglen = decode_msglen(bufdown);
			assert(msglen <= CTLMSG_MAX);
			assert(downlen <= msglen + 2);
			if (downlen == msglen + 2)
				downlen = 0;
		}
	}

	return 0;
}

static void *thread_tunnel (void *arg)
{
	struct tunnel_info *info = (struct tunnel_info *)arg;

	assert(info->sock_ext >= 0);
	info->isfree = 0;
	info->sock_int = -1;
	info->control_pipe[0] = info->control_pipe[1] = -1;

	printf("try to handshake\n");
	if (tunnel_handshake(info))
		goto errout;
	printf("handshake done\n");

	if (info->isactive)
		assert(pipe(info->control_pipe) == 0);

	while (1) {
		if (tunnel_wait(info))
			break;
		// now info->sock_int is ready. we can do tunneling.
		assert(info->sock_int >= 0);
		assert(!info->isfree);
		if (tunnel_data(info))
			break;
	}

errout:
	if (info->sock_int != -1)
		close(info->sock_int);
	if (info->sock_ext != -1)
		close(info->sock_ext);
	if (info->control_pipe[0] != -1)
		close(info->control_pipe[0]);
	if (info->control_pipe[1] != -1)
		close(info->control_pipe[1]);
	if (info->isfree)
		freepool_remove(info);
	free(info);
	return NULL;
}

static void *thread_listener (void *arg)
{
	int sock;
	struct sockaddr_in addr;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	assert(sock >= 0);
	assert(resolve_ipv4_address(&addr, "0.0.0.0", option_inport) == 0);
	assert(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	assert(listen(sock, 1) == 0);
	while (1) {
		int client;
		struct tunnel_info *info;
		char msg[1];

		client = accept(sock, NULL, NULL);
		assert(client >= 0);
		info = freepool_get();
		if (info == NULL) {
			printf("free pool 0. close new connection\n");
			close(client);
		}

		assert(!info->isfree);
		assert(info->control_pipe[1] >= 0);
		info->sock_int = client;
		assert(write(info->control_pipe[1], msg, 1) == 1);
	}
	return NULL;
}

static int run_register (void)
{
	struct sockaddr_in addr;
	struct ntl_struct *ntl;

	assert(resolve_ipv4_address(&addr, option_serverip, option_serverport) == 0);
	ntl = ntl_init(&addr, NULL, NULL);
	assert(ntl);
	if (ntl_register(ntl))
		return 1;
	printf("Public  ID: %s\n", ntl->pubid);
	printf("Private ID: %s\n", ntl->privid);
	return 0;
}

static int run_whoami (void)
{
	int intport = 0;
	struct sockaddr_in addr;
	struct ntl_struct *ntl;

	assert(resolve_ipv4_address(&addr, option_serverip, option_serverport) == 0);
	ntl = ntl_init(&addr, NULL, NULL);
	assert(ntl);
	printf("Running who-am-i UDP...\n");
	ntl_whoami(ntl, 0, &intport, &addr, 1);
	printf("Running who-am-i TCP...\n");
	ntl_whoami(ntl, 1, &intport, &addr, 1);

	return 0;
}

static int run_passive (void)
{
	struct sockaddr_in addr;
	struct ntl_struct *ntl;
	struct punch_local_param punch_local[2];
	struct punch_param punch_peer[2];
	time_t lastupdate;

	assert(resolve_ipv4_address(&addr, option_serverip, option_serverport) == 0);
	ntl = ntl_init(&addr, NULL, option_ntlid);
	assert(ntl);

	// TODO: handle one fail
	assert(punch_p2pnat_param_init(&punch_local[0], &punch_peer[0], 0) == 0);
	assert(punch_udt_param_init(&punch_local[1], &punch_peer[1], 0) == 0);
	assert(ntl_waitinvite(ntl, 0, punch_peer, 2, NULL) == 0);
	lastupdate = time(NULL);

	while (1) {
		time_t currtime;
		int retval, peersock;
		struct punch_param requested_punch[2];
		struct tunnel_info *info;

		currtime = time(NULL);
		while (currtime - lastupdate >= WAI_EXPIRE) {
			// TODO: handle one fail
			if (punch_p2pnat_param_init(&punch_local[0], &punch_peer[0], 1) == 0)
				break;
			if (punch_udt_param_init(&punch_local[1], &punch_peer[1], 1) == 0)
				break;
			lastupdate = currtime; // we ignore update failure.
		}

		retval = ntl_waitinvite(ntl, lastupdate + WAI_EXPIRE - currtime,
				punch_peer, 2, requested_punch);
		if (retval != 1)
			continue;
		if (requested_punch[0].type != PT_P2PNAT && requested_punch[0].type != PT_UDT)
			continue;
		if (requested_punch[0].type != requested_punch[1].type)
			continue;
		if ((requested_punch[0].type == PT_P2PNAT && memcmp(&requested_punch[0], &punch_peer[0], sizeof(requested_punch[0])) != 0) ||
				(requested_punch[0].type == PT_UDT && memcmp(&requested_punch[0], &punch_peer[1], sizeof(requested_punch[0])) != 0)) {
			printf("INVITE request error: mine is %s but I got %s\n",
					punch_tostring(&punch_peer[requested_punch[0].type == PT_P2PNAT ? 0 : 1]),
					punch_tostring(&requested_punch[0]));
			continue;
		}
		peersock = requested_punch[1].type == PT_P2PNAT ?
			punch_p2pnat(&punch_local[0], &requested_punch[1]) :
			punch_udt(&punch_local[1], &requested_punch[1]);
		if (peersock < 0)
			continue;

		info = (struct tunnel_info *)malloc(sizeof(struct tunnel_info));
		memset(info, 0, sizeof(struct tunnel_info));
		info->isactive = 0;
		info->sock_ext = peersock;
		assert(pthread_create(&info->threadid, NULL, thread_tunnel, info) == 0);
	}

	return 0;
}

static int run_active (void)
{
	struct ntl_struct *ntl;
	pthread_t listenerid;
	struct sockaddr_in addr;

	freepool_init();
	assert(pthread_create(&listenerid, NULL, thread_listener, NULL) == 0);

	assert(resolve_ipv4_address(&addr, option_serverip, option_serverport) == 0);
	ntl = ntl_init(&addr, option_ntlid, NULL);
	assert(ntl);

	for (; ; sleep(5)) {
		int peersock, queryn, i;
		struct punch_local_param local;
		struct punch_param query[3], ext;
		struct tunnel_info *info;

		if (free_pool_count >= MINFREEPOOL)
			continue;

		queryn = ntl_query(ntl, query, sizeof(query)/sizeof(query[0]));
		if (queryn <= 0) {
			printf("ntl_query returns %d\n", queryn);
			continue;
		}
		assert(queryn <= sizeof(query)/sizeof(query[0]));
		for (i = 0; i < queryn; i ++) // TODO should try other methods.
			if (query[i].type == PT_UDT)
				break;
		if (i == queryn) {
			printf("no udt\n");
			continue;
		}

		if (punch_udt_param_init(&local, &ext, 0) != 0)
			continue;
		if (ntl_invite(ntl, &ext, &query[i]) != 0)
			continue;
		assert(query[i].type == PT_UDT);
		peersock = punch_udt(&local, &query[i]);
		if (peersock < 0)
			continue;

		info = (struct tunnel_info *)malloc(sizeof(struct tunnel_info));
		memset(info, 0, sizeof(struct tunnel_info));
		info->isactive = 1;
		info->sock_ext = peersock;
		assert(pthread_create(&info->threadid, NULL, thread_tunnel, info) == 0);
	}
}

int main (int argc, char *argv[])
{
	if (argc == 4 && strcmp(argv[3], "REGISTER") == 0) {
		option_serverip = argv[1];
		option_serverport = atoi(argv[2]);
		option_role = 'R';
	} else if (argc == 4 && strcmp(argv[3], "WHOAMI") == 0) {
		option_serverip = argv[1];
		option_serverport = atoi(argv[2]);
		option_role = 'W';
	} else if (argc == 6) {
		option_serverip = argv[1];
		option_serverport = atoi(argv[2]);
		option_ntlid = argv[3];
		option_outip = argv[4];
		option_outport = atoi(argv[5]);
		option_role = 'P';
	} else if (argc == 5) {
		option_serverip = argv[1];
		option_serverport = atoi(argv[2]);
		option_ntlid = argv[3];
		option_inport = atoi(argv[4]);
		option_role = 'A';
	} else {
		printf("Usage:\n");
		printf("Register: %s ntlserver-ip ntlserver-port REGISTER\n", argv[0]);
		printf("Register: %s ntlserver-ip ntlserver-port WHOAMI\n", argv[0]);
		printf("Passive:  %s ntlserver-ip ntlserver-port privid outip outport\n", argv[0]);
		printf("Active:   %s ntlserver-ip ntlserver-port pubid inport\n", argv[0]);
		return 1;
	}

	signal(SIGPIPE, SIG_IGN);

	switch (option_role) {
		case 'R': return run_register();
		case 'W': return run_whoami();
		case 'P': return run_passive();
		case 'A': return run_active();
	}
	return 0;
}
