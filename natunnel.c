#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#define EXPIRE (4*60)

char *option_serverip;
int option_serverport;
char *option_ntlid;
char *option_outip;
int option_outport;
int option_inport;
char option_role;

int tab_explode (char *str, int argc, char *argv[])
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

int resolve_ipv4_address (const char *addrstr, struct sockaddr_in *addr, int port)
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

int run_register (void)
{
	int sock, msglen;
	struct sockaddr_in addr;
	char msg[500];

	assert(resolve_ipv4_address(option_serverip, &addr, option_serverport) == 0);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);

	assert(sendto(sock, "REGISTER", strlen("REGISTER"), 0, (struct sockaddr *)&addr, sizeof(addr)) == strlen("REGISTER"));
	msglen = recvfrom(sock, msg, sizeof(msg)-1, 0, NULL, NULL);
	assert(msglen > 0);
	msg[msglen] = '\0';
	puts(msg);
	return 0;
}

void whoami_tcp (struct sockaddr_in *server_addr, int *intport, struct sockaddr_in *extaddr)
{
	int sock, argc, msglen;
	char msg[500], *argv[6];

	sock = socket(AF_INET, SOCK_STREAM, 0);
	assert(sock >= 0);
	argc = 1;
	assert(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &argc, sizeof(int)) == 0);

	if (*intport) {
		struct sockaddr_in intaddr;
		intaddr.sin_family = AF_INET;
		intaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		intaddr.sin_port = htons(*intport);
		assert(bind(sock, (struct sockaddr *)&intaddr, sizeof(intaddr)) == 0);
	}

	assert(connect(sock, (struct sockaddr *)server_addr, sizeof(struct sockaddr_in)) == 0);
	msglen = recv(sock, msg, sizeof(msg)-1, 0);
	assert(msglen > 0);
	msg[msglen] = '\0';
	puts(msg);
	argc = tab_explode(msg, sizeof(argv)/sizeof(argv[0]), argv);
	assert(argc == 4);
	assert(strcmp("WHOYOUARE", argv[0]) == 0);

	if (!*intport) {
		struct sockaddr_in intaddr;
		socklen_t addrlen = sizeof(struct sockaddr_in);
		memset(&intaddr, 0, sizeof(struct sockaddr_in));
		assert(getsockname(sock, (struct sockaddr *)&intaddr, &addrlen) == 0);
		*intport = ntohs(intaddr.sin_port);
	}
	assert(resolve_ipv4_address(argv[1], extaddr, atoi(argv[2])) == 0);
	close(sock);
}

int do_whoami (int ntlclient, int *intport, struct sockaddr_in *extaddr, int tworound)
{
	int msglen, argc;
	struct sockaddr_in addr, server_addr;
	char msg[500], *argv[6];

	assert(resolve_ipv4_address(option_serverip, &addr, option_serverport) == 0); // should we cache?

	assert(sendto(ntlclient, "WHOAMI", strlen("WHOAMI"), 0, (struct sockaddr *)&addr, sizeof(addr)) == strlen("WHOAMI"));
	msglen = recvfrom(ntlclient, msg, sizeof(msg)-1, 0, NULL, NULL);
	assert(msglen > 0);
	msg[msglen] = '\0';
	puts(msg);
	argc = tab_explode(msg, sizeof(argv)/sizeof(argv[0]), argv);
	assert(argc == 5);

	assert(resolve_ipv4_address(argv[1], &server_addr, atoi(argv[2])) == 0);
	whoami_tcp(&server_addr, intport, extaddr);
	if (!tworound)
		return 0;

	assert(resolve_ipv4_address(argv[3], &server_addr, atoi(argv[4])) == 0);
	whoami_tcp(&server_addr, intport, &addr);
	return memcmp(extaddr, &addr, sizeof(addr));
}

int run_whoami (void)
{
	int sock, intport;
	struct sockaddr_in extaddr;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);

	do_whoami(sock, &intport, &extaddr, 1);

	return 0;
}

int run_passive (void)
{
	return 0;
}

int run_active (void)
{
	return 0;
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

	switch (option_role) {
		case 'R': return run_register();
		case 'W': return run_whoami();
		case 'P': return run_passive();
		case 'A': return run_active();
	}
	return 0;
}
