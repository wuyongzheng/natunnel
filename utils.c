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

int str_explode (char *str, const char *sep, char *argv[], int argc)
{
	int i;

	assert(str != NULL && sep != NULL);
	if (argc == 0)
		return 0;
	assert(argv != NULL);
	argv[0] = strtok(str, sep);
	if (argv[0] == NULL)
		return 0;
	for (i = 1; i < argc; i++) {
		char *token = strtok(NULL, sep);
		if (token == NULL)
			break;
		argv[i] = token;
	}
	return i;
}

int resolve_ipv4_address (struct sockaddr_in *addr, const char *addrstr, int port)
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

