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
#include "udt-wrapper.h"

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
		//printf("%s %d %02x%02x%02x%02x\n", isup ? "up" : "dn", (int)len, buff[0], buff[1], buff[3], buff[4]);
		while (sent < len) {
			int len1 = isup ?
				udt_send(udt_pipe->sock_udt, (char *)buff+sent, len-sent, 0) :
				send(udt_pipe->sock_sys, buff+sent, len-sent, 0);
			if (len1 <= 0) {
				if (isup)
					printf("thread_udtpipe() send failed udt_lasterror=%d\n", udt_getlasterror());
				else
					perror("thread_udtpipe() send failed");
				break;
			}
			sent += len1;
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
//int punch_udt (int intport, const char *peerip, int peerport)
int punch_udt (const struct punch_local_param *local, const struct punch_param *peer)
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
	addr.sin_port = htons(local->udt.localport);
	if (udt_bind(sock, (const struct sockaddr *)&addr, sizeof(addr))) {
		printf("bind to port %d failed\n", local->udt.localport);
		goto errout;
	}

	printf("try to udt_connect()\n");
	if (udt_connect(sock, (const struct sockaddr *)&peer->udt.addr, sizeof(struct sockaddr_in)) != 0) {
		printf("failed to udt_connect\n");
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

int punch_udt_param_init (struct punch_local_param *local, struct punch_param *peer, int haslocal)
{
	if (!haslocal)
		local->udt.localport = 0;
	local->type = peer->type = PT_UDT;
	return do_stun(0, haslocal ? 0 : 1, &local->udt.localport, &peer->udt.addr);
}
