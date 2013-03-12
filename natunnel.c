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
#include <errno.h>

#define EXPIRE (4*60)
#define TIMEOUT 10
#define PUNCH_RETRY 5

char *option_serverip;
int option_serverport;
char *option_ntlid;
char *option_outip;
int option_outport;
int option_inport;
char option_role;

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

static int whoami_tcp (struct sockaddr_in *server_addr, int *intport, struct sockaddr_in *extaddr)
{
	int sock, argc, msglen, retval = 1;
	char msg[500], *argv[6];
	struct timeval tv;

	sock = socket(AF_INET, SOCK_STREAM, 0);
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
		printf("connect to WAI tcp server failed\n");
		goto out;
	}
	msglen = recv(sock, msg, sizeof(msg)-1, 0);
	if (msglen <= 0) {
		printf("recv from WAI tcp server failed\n");
		goto out;
	}
	msg[msglen] = '\0';
	puts(msg);
	argc = tab_explode(msg, sizeof(argv)/sizeof(argv[0]), argv);
	if (argc != 4 || strcmp("WHOYOUARE", argv[0]) ||
			resolve_ipv4_address(argv[1], extaddr, atoi(argv[2]))) {
		printf("WAI tcp server response error\n");
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
static int do_whoami (int ntlclient, int *intport, struct sockaddr_in *extaddr, int tworound)
{
	int msglen, argc;
	struct sockaddr_in addr, server_addr;
	struct timeval tv;
	char msg[500], *argv[6];

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
	if (argc != 5 || strcmp(argv[0], "WAI_SERVERS") != 0) {
		printf("WHOAMI response error\n");
		return 2;
	}

	if (resolve_ipv4_address(argv[1], &server_addr, atoi(argv[2]))) {
		printf("WHOAMI response error\n");
		return 2;
	}
	if (whoami_tcp(&server_addr, intport, extaddr))
		return 2;
	if (!tworound)
		return 0;

	if (resolve_ipv4_address(argv[3], &server_addr, atoi(argv[4]))) {
		printf("WHOAMI response error\n");
		return 2;
	}
	if (whoami_tcp(&server_addr, intport, &addr))
		return 2;
	if (memcmp(extaddr, &addr, sizeof(addr)))
		return 1;
	return 0;
}

static int do_update (int ntlclient, const char *ntlid, struct sockaddr_in *extaddr)
{
	int msglen;
	char msg[500];
	struct timeval tv;

	msglen = sprintf(msg, "UPDATE\t%s\t%s\t%d\tdummy",
			ntlid, inet_ntoa(extaddr->sin_addr), ntohs(extaddr->sin_port));
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
	if (strcmp("UPDATE_OK", msg)) {
		printf("UPDATE response error\n");
		return 1;
	}

	return 0;
}

// no need to do clean up because exits anyway.
static int do_tunnel (int intport, const char *peerip, int peerport)
{
	int sock, i;
	struct sockaddr_in addr;
	char buff[1600];

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
		return 1;
	}

	if (resolve_ipv4_address(peerip, &addr, peerport)) {
		printf("failed to resolve %s\n", peerip);
		return 1;
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
		return 1;
	}

	snprintf(buff, sizeof(buff), "Hi, I'm %d.", getpid());
	printf("sending \"%s\"\n", buff);
	if (send(sock, buff, strlen(buff) + 1, 0) != strlen(buff) + 1) {
		printf("send() failed.");
		return 1;
	}
	if (recv(sock, buff, sizeof(buff), 0) <= 0) {
		printf("recv() failed.");
		return 1;
	}
	printf("received \"%s\"\n", buff);

	return 0;
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

	do_whoami(sock, &intport, &addr, 1);

	return 0;
}

static int run_passive (void)
{
	int sock, intport = 0;
	struct sockaddr_in addr;
	time_t lastupdate;

	assert(resolve_ipv4_address(option_serverip, &addr, option_serverport) == 0);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);
	assert(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);

	assert(do_whoami(sock, &intport, &addr, 1) == 0);
	assert(do_update(sock, option_ntlid, &addr) == 0);
	lastupdate = time(NULL);

	while (1) {
		struct timeval tv;
		time_t currtime;
		char msg[500], *argv[4];
		int msglen, argc;

		currtime = time(NULL);
		if (currtime - lastupdate >= EXPIRE) {
			if (do_whoami(sock, &intport, &addr, 0) == 0) {
				do_update(sock, option_ntlid, &addr);
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
		if (argc != 3 || strcmp(argv[0], "INVITE_P") != 0)
			continue;

		if (fork() == 0) {
			close(sock);
			do_tunnel(intport, argv[1], atoi(argv[2]));
			exit(0);
		}
	}

	return 0;
}

static int run_active (void)
{
	int sock, intport = 0, msglen, argc;
	struct sockaddr_in addr;
	char msg[500], *argv[4];

	assert(resolve_ipv4_address(option_serverip, &addr, option_serverport) == 0);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);
	assert(connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	assert(do_whoami(sock, &intport, &addr, 1) == 0);

	msglen = sprintf(msg, "INVITE\t%s\t%s\t%d\tdummy",
			option_ntlid, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	assert(send(sock, msg, msglen, 0) == msglen);

	msglen = recv(sock, msg, sizeof(msg)-1, 0);
	assert(msglen > 0);
	msg[msglen] = '\0';
	puts(msg);
	argc = tab_explode(msg, sizeof(argv)/sizeof(argv[0]), argv);
	assert(argc == 3 && strcmp(argv[0], "INVITE_A") == 0);
	return do_tunnel(intport, argv[1], atoi(argv[2]));
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
