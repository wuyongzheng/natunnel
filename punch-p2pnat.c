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
#include "natunnel.h"

#define PUNCH_RETRY 3

// return a connected socket.
//int punch_p2pnat (int intport, const char *peerip, int peerport)
int punch_p2pnat (const struct punch_local_param *local, const struct punch_param *peer)
{
	return -1;
#if 0
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
#endif
}

int punch_p2pnat_param_init (struct punch_local_param *local, struct punch_param *peer, int haslocal)
{
	if (!haslocal)
		local->p2pnat.localport = -1;
	return do_stun(1, haslocal ? 0 : 1, &local->p2pnat.localport, &peer->p2pnat.addr);
}
