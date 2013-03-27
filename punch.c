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

int punch_fromstring (struct punch_param *punch, char *str)
{
	int argc;
	char *argv[4];

	argc = str_explode(str, ":", argv, sizeof(argv)/sizeof(argv[0]));
	if (argc != 3)
		return -1;
	if (strcmp(argv[0], "P2PNAT") == 0) {
		punch->type = PT_P2PNAT;
		if (inet_aton(argv[1], &punch->p2pnat.addr.sin_addr))
			return -1;
		punch->p2pnat.addr.sin_port = htons(atoi(argv[2]));
	} else if (strcmp(argv[0], "UDT") == 0) {
		punch->type = PT_UDT;
		if (inet_aton(argv[1], &punch->udt.addr.sin_addr))
			return -1;
		punch->udt.addr.sin_port = htons(atoi(argv[2]));
	} else
		return -1;

	return 0;
}

char *punch_tostring (const struct punch_param *punch)
{
	static char buffer[32][4];
	static unsigned int ptr = 0;
	char *buf = buffer[ptr ++ % 4];

	switch (punch->type) {
		case PT_P2PNAT:
			snprintf(buf, 32, "P2PNAT:%s:%d",
					inet_ntoa(punch->p2pnat.addr.sin_addr),
					ntohs(punch->p2pnat.addr.sin_port));
			break;
		case PT_UDT:
			snprintf(buf, 32, "UDT:%s:%d",
					inet_ntoa(punch->udt.addr.sin_addr),
					ntohs(punch->udt.addr.sin_port));
			break;
		default:
			return NULL;
	}
	return buf;
}
