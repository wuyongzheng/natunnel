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
#include "udt-wrapper.h"

#define EXPIRE (4*60)
#define TIMEOUT 10
#define PUNCH_RETRY 5
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

static int tab_explode (char *str, int argc, char *argv[])
{
	int i;

	assert(str != NULL);
	if (argc == 0)
		return 0;
	assert(argv != NULL);
	argv[0] = strtok(str, "\t");
	if (argv[0] == NULL)
		return 0;
	for (i = 1; i < argc; i++) {
		char *token = strtok(NULL, "\t");
		if (token == NULL)
			break;
		argv[i] = token;
	}
	return i;
}

static int resolve_ipv4_address (const char *addrstr, struct sockaddr_in *addr, int port)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(addrstr, NULL, &hints, &result) != 0)
		return 1;
	for (rp = result; rp != NULL; rp = rp->ai_next) { //FIXME: noneed loop, just use the first one.
		assert(rp->ai_family == AF_INET);
		assert(rp->ai_addrlen == sizeof(struct sockaddr_in));
		memcpy(addr, rp->ai_addr, sizeof(struct sockaddr_in));
		addr->sin_port = htons(port);
		freeaddrinfo(result);
		return 0;
	}
	return 1;
}

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

static int whoami_test (int tcp, struct sockaddr_in *server_addr, int *intport, struct sockaddr_in *extaddr)
{
	int sock, argc, msglen, retval = 1;
	char msg[500], *argv[6];
	struct timeval tv;

	sock = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
	assert(sock >= 0);
	argc = 1;
	assert(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &argc, sizeof(int)) == 0);
	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;
	assert(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) == 0);

	if (*intport) {
		struct sockaddr_in intaddr;
		intaddr.sin_family = AF_INET;
		intaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		intaddr.sin_port = htons(*intport);
		assert(bind(sock, (struct sockaddr *)&intaddr, sizeof(intaddr)) == 0);
	}

	if (connect(sock, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in))) {
		printf("connect to WAI %s server failed\n", tcp ? "TCP" : "UDP");
		goto out;
	}
	if (!tcp)
		assert(send(sock, "WAI", 3, 0) == 3);
	msglen = recv(sock, msg, sizeof(msg)-1, 0);
	if (msglen <= 0) {
		printf("recv from WAI %s server failed\n", tcp ? "TCP" : "UDP");
		goto out;
	}
	msg[msglen] = '\0';
	puts(msg);
	argc = tab_explode(msg, sizeof(argv)/sizeof(argv[0]), argv);
	if (argc != 4 || strcmp("WHOYOUARE", argv[0]) ||
			resolve_ipv4_address(argv[1], extaddr, atoi(argv[2]))) {
		printf("WAI %s server response error\n", tcp ? "TCP" : "UDP");
		goto out;
	}

	if (!*intport) {
		struct sockaddr_in intaddr;
		socklen_t addrlen = sizeof(struct sockaddr_in);
		memset(&intaddr, 0, sizeof(struct sockaddr_in));
		assert(getsockname(sock, (struct sockaddr *)&intaddr, &addrlen) == 0);
		*intport = ntohs(intaddr.sin_port);
	}
	retval = 0;
out:
	close(sock);
	return retval;
}

/* return: 0 succeed.
 *         1 unmatch. (only happens when tworound=1)
 *         2 other error.
 * */
static int do_whoami (int istcp, int ntlclient, int *intport, struct sockaddr_in *extaddr, int tworound)
{
	int msglen, argc;
	struct sockaddr_in addr, server_addr;
	struct timeval tv;
	char msg[1000], *argv[14];

	assert(istcp == 0 || istcp == 1);

	if (send(ntlclient, "WHOAMI", strlen("WHOAMI"), 0) != strlen("WHOAMI")) {
		printf("send WHOAMI error\n");
		return 2;
	}

	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;
	assert(setsockopt(ntlclient, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) == 0);
	msglen = recv(ntlclient, msg, sizeof(msg)-1, 0);
	if (msglen <= 0) {
		printf("recv WHOAMI response error\n");
		return 2;
	}
	msg[msglen] = '\0';
	puts(msg);
	argc = tab_explode(msg, sizeof(argv)/sizeof(argv[0]), argv);
	if (argc != 13 || strcmp(argv[0], "WAI_UDP") != 0) {
		printf("WHOAMI response error\n");
		return 2;
	}

	if (resolve_ipv4_address(argv[1+istcp*5], &server_addr, atoi(argv[2+istcp*5]))) {
		printf("WHOAMI response error\n");
		return 2;
	}
	if (whoami_test(istcp, &server_addr, intport, extaddr))
		return 2;
	if (!tworound)
		return 0;

	if (resolve_ipv4_address(argv[3+istcp*5], &server_addr, atoi(argv[4+istcp*5]))) {
		printf("WHOAMI response error\n");
		return 2;
	}
	if (whoami_test(istcp, &server_addr, intport, &addr))
		return 2;
	if (memcmp(extaddr, &addr, sizeof(addr)))
		return 1;
	return 0;
}

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

static int do_update (int ntlclient, const char *ntlid, struct sockaddr_in *extaddr_p2pnat, struct sockaddr_in *extaddr_udt)
{
	int msglen;
	char msg[500];
	struct timeval tv;
	unsigned long long t1, t2;
	unsigned long ts_sec, ts_usec;

	assert(gettimeofday(&tv, NULL) == 0);
	t1 = tv.tv_sec * 1000000 + tv.tv_usec;

	msglen = sprintf(msg, "UPDATE\t%s\tP2PNAT\t%s\t%d\tdummy\tUDT\t%s\t%d\tdummy",
			ntlid,
			inet_ntoa(extaddr_p2pnat->sin_addr), ntohs(extaddr_p2pnat->sin_port),
			inet_ntoa(extaddr_udt->sin_addr), ntohs(extaddr_udt->sin_port));
	if (send(ntlclient, msg, msglen, 0) != msglen)
		return 1;

	tv.tv_sec = TIMEOUT;
	tv.tv_usec = 0;
	assert(setsockopt(ntlclient, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) == 0);
	msglen = recv(ntlclient, msg, sizeof(msg)-1, 0);
	if (msglen <= 0) {
		printf("recv UPDATE response failed\n");
		return 1;
	}
	msg[msglen] = '\0';
	puts(msg);
	if (sscanf(msg, "UPDATE_OK\t%lu\t%lu", &ts_sec, &ts_usec) != 2) {
		printf("UPDATE response error\n");
		return 1;
	}

	assert(gettimeofday(&tv, NULL) == 0);
	t2 = tv.tv_sec * 1000000 + tv.tv_usec;

	if (t2 - t1 <= timeoff_ttl) {
		timeoff_ttl = t2 - t1;
		timeoff_off = ts_sec * 1000000 + ts_usec - (t2 + t1) / 2;
		printf("Time offset set to %ld (ttl=%lu)\n", (long)timeoff_off, timeoff_ttl);
	}

	return 0;
}

// return a connected socket.
static int do_punch_p2pnat (int intport, const char *peerip, int peerport)
{
	int sock = -1, i;
	struct sockaddr_in addr;

	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(sock >= 0);
	i = 1;
	assert(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(int)) == 0);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(intport);
	if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr))) {
		printf("bind to port %d failed\n", intport);
		goto errout;
	}

	if (resolve_ipv4_address(peerip, &addr, peerport)) {
		printf("failed to resolve %s\n", peerip);
		goto errout;
	}

	for (i = 0; i < PUNCH_RETRY; i ++) {
		if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) == 0)
			break;
		if (errno != ETIMEDOUT) {
			perror("connect() failed. retry in 2 sec.");
			sleep(2);
		} else {
			perror("connect() failed.");
		}
	}

	if (i >= PUNCH_RETRY) {
		printf("fails to punch through NAT\n");
		goto errout;
	}

	return sock;

errout:
	if (sock >= 0)
		close(sock);
	return -1;
}

struct udt_pipe_struct {
	struct udt_pipe_struct *up, *down; // a trick to distinguish up and down
	int sock_udt, sock_sys;
	pthread_t thread_up, thread_down;
	int running_count;
	pthread_mutex_t running_mutex;
};

static void *thread_udtpipe (void *arg)
{
	struct udt_pipe_struct *udt_pipe = *(struct udt_pipe_struct **)arg;
	int isup;
	unsigned char buff[2000];

	assert(&udt_pipe->up == (struct udt_pipe_struct **)arg || &udt_pipe->down == (struct udt_pipe_struct **)arg);
	isup = &udt_pipe->up == (struct udt_pipe_struct **)arg;

	printf("thread_udtpipe start, isup=%d\n", isup);
	while (1) {
		int sent = 0;
		ssize_t len = isup ?
			recv(udt_pipe->sock_sys, buff, sizeof(buff), 0) :
			udt_recv(udt_pipe->sock_udt, (char *)buff, sizeof(buff), 0);
		if (len <= 0) {
			if (isup)
				perror("thread_udtpipe() recv failed");
			else
				printf("thread_udtpipe() recv failed udt_lasterror=%d\n", udt_getlasterror());
			break;
		}
		printf("%s %d %02x%02x\n", isup ? "up" : "dn", (int)len, buff[0], buff[1]);
		while (sent < len) {
			int len1 = isup ?
				send(udt_pipe->sock_sys, buff+sent, len-sent, 0) :
				udt_send(udt_pipe->sock_udt, (char *)buff+sent, len-sent, 0);
			if (len1 <= 0)
				break;
			sent -= len1;
		}
		if (sent < len) // send error
			break;
	}

	printf("thread_udtpipe end, isup=%d\n", isup);
	pthread_mutex_lock(&udt_pipe->running_mutex);
	if (udt_pipe->running_count == 2) { // I'm the first to exit
		close(udt_pipe->sock_sys);
		udt_close(udt_pipe->sock_udt);
		udt_pipe->running_count --;
		pthread_mutex_unlock(&udt_pipe->running_mutex);
	} else {
		pthread_mutex_unlock(&udt_pipe->running_mutex);
		free(udt_pipe);
	}
	return NULL;
}

// return a connected socket. Here I use socketpair as a wrapper in order to select()
static int do_punch_udt (int intport, const char *peerip, int peerport)
{
	int sock = -1, spair[2];
	struct sockaddr_in addr;
	struct udt_pipe_struct *udt_pipe;

	sock = udt_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(sock >= 0);
	assert(udt_setsockopt_rendezvous(sock, 1) == 0);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(intport);
	if (udt_bind(sock, (const struct sockaddr *)&addr, sizeof(addr))) {
		printf("bind to port %d failed\n", intport);
		goto errout;
	}

	if (resolve_ipv4_address(peerip, &addr, peerport)) {
		printf("failed to resolve %s\n", peerip);
		goto errout;
	}

	printf("try to udt_connect()\n");
	if (udt_connect(sock, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
		printf("failed to udt_connect %s\n", peerip);
		goto errout;
	}
	printf("succeed udt_connect()\n");

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, spair) == 0);

	udt_pipe = (struct udt_pipe_struct *)malloc(sizeof(struct udt_pipe_struct));
	udt_pipe->up = udt_pipe->down = udt_pipe;
	udt_pipe->sock_sys = spair[0];
	udt_pipe->sock_udt = sock;
	udt_pipe->running_count = 2;
	pthread_mutex_init(&udt_pipe->running_mutex, NULL);
	assert(pthread_create(&udt_pipe->thread_up,   NULL, thread_udtpipe, &udt_pipe->up) == 0);
	assert(pthread_create(&udt_pipe->thread_down, NULL, thread_udtpipe, &udt_pipe->down) == 0);
	return spair[1];

errout:
	udt_close(sock);
	return -1;
}

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
		FD_SET(info->control_pipe[1], &rfds);
	FD_SET(info->sock_ext, &rfds);
	retval = select(info->control_pipe[1] > info->sock_ext ? info->control_pipe[1] + 1 : info->sock_ext + 1, &rfds, NULL, NULL, NULL);
	assert(retval == 1);
	if (info->isactive && FD_ISSET(info->control_pipe[1], &rfds)) {
		msglen = recv(info->control_pipe[1], msgbuf, sizeof(msgbuf), 0); // we don't care about the contents
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
		assert(resolve_ipv4_address(option_outip, &addr, option_outport) == 0);
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
	assert(resolve_ipv4_address("0.0.0.0", &addr, option_inport) == 0);
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
		assert(send(info->control_pipe[1], msg, 1, 0) == 1);
	}
	return NULL;
}

static int run_register (void)
{
	int sock, msglen;
	struct sockaddr_in addr;
	char msg[500];

	assert(resolve_ipv4_address(option_serverip, &addr, option_serverport) == 0);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);
	assert(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);

	assert(send(sock, "REGISTER", strlen("REGISTER"), 0) == strlen("REGISTER"));
	msglen = recv(sock, msg, sizeof(msg)-1, 0);
	assert(msglen > 0);
	msg[msglen] = '\0';
	puts(msg);
	return 0;
}

static int run_whoami (void)
{
	int sock, intport = 0;
	struct sockaddr_in addr;

	assert(resolve_ipv4_address(option_serverip, &addr, option_serverport) == 0);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);
	assert(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);

	do_whoami(1, sock, &intport, &addr, 1);

	return 0;
}

static int run_passive (void)
{
	int sock, intporttcp = 0, intportudp = 0;
	struct sockaddr_in addr, addrtcp, addrudp;
	time_t lastupdate;

	assert(resolve_ipv4_address(option_serverip, &addr, option_serverport) == 0);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);
	assert(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);

	assert(do_whoami(0, sock, &intportudp, &addrudp, 1) == 0);
	assert(do_whoami(1, sock, &intporttcp, &addrtcp, 1) == 0);
	assert(do_update(sock, option_ntlid, &addrtcp, &addrudp) == 0);
	lastupdate = time(NULL);

	while (1) {
		struct timeval tv;
		time_t currtime;
		char msg[500], *argv[5];
		int msglen, argc, peersock;

		currtime = time(NULL);
		if (currtime - lastupdate >= EXPIRE) {
			if (do_whoami(0, sock, &intportudp, &addrudp, 0) == 0 &&
					do_whoami(1, sock, &intporttcp, &addrtcp, 0) == 0) {
				do_update(sock, option_ntlid, &addrtcp, &addrudp);
			}
			lastupdate = currtime; // we ignore update failure.
		}

		tv.tv_sec = lastupdate + EXPIRE - currtime;
		tv.tv_usec = 0;
		assert(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) == 0);
		msglen = recv(sock, msg, sizeof(msg)-1, 0);
		if (msglen <= 0)
			continue;
		msg[msglen] = '\0';
		puts(msg);
		argc = tab_explode(msg, sizeof(argv)/sizeof(argv[0]), argv);
		if (argc != 4 || strcmp(argv[0], "INVITE_P") != 0)
			continue;
		if (strcmp(argv[1], "P2PNAT") != 0 && strcmp(argv[1], "UDT") != 0)
			continue;

		peersock = strcmp(argv[1], "P2PNAT") == 0 ?
			do_punch_p2pnat(intporttcp, argv[2], atoi(argv[3])) :
			do_punch_udt(intportudp, argv[2], atoi(argv[3]));
		if (peersock >= 0) {
			struct tunnel_info *info = (struct tunnel_info *)malloc(sizeof(struct tunnel_info));
			memset(info, 0, sizeof(struct tunnel_info));
			info->isactive = 0;
			info->sock_ext = peersock;
			assert(pthread_create(&info->threadid, NULL, thread_tunnel, info) == 0);
		}
	}

	return 0;
}

static int run_active (void)
{
	int sock;
	pthread_t listenerid;
	struct sockaddr_in addr;

	freepool_init();
	assert(pthread_create(&listenerid, NULL, thread_listener, NULL) == 0);

	assert(resolve_ipv4_address(option_serverip, &addr, option_serverport) == 0);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);
	assert(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	do_timeoff(sock);

	while (1) {
		int intport = 0, msglen, argc, peersock;
		char msg[500], *argv[4];

		if (free_pool_count >= MINFREEPOOL) {
			sleep(5);
			continue;
		}

		assert(do_whoami(0, sock, &intport, &addr, 1) == 0);
		msglen = sprintf(msg, "INVITE\t%s\tUDT\t%s\t%d\tdummy",
				option_ntlid, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		assert(send(sock, msg, msglen, 0) == msglen);

		msglen = recv(sock, msg, sizeof(msg)-1, 0);
		assert(msglen > 0);
		msg[msglen] = '\0';
		puts(msg);
		argc = tab_explode(msg, sizeof(argv)/sizeof(argv[0]), argv);
		assert(argc == 4 && strcmp(argv[0], "INVITE_A") == 0);
		peersock = strcmp(argv[1], "P2PNAT") == 0 ?
			do_punch_p2pnat(intport, argv[2], atoi(argv[3])) :
			do_punch_udt(intport, argv[2], atoi(argv[3]));
		if (peersock >= 0) {
			struct tunnel_info *info = (struct tunnel_info *)malloc(sizeof(struct tunnel_info));
			memset(info, 0, sizeof(struct tunnel_info));
			info->isactive = 1;
			info->sock_ext = peersock;
			assert(pthread_create(&info->threadid, NULL, thread_tunnel, info) == 0);
		}
		sleep(5);
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
