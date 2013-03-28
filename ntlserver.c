#include <stdlib.h>
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
#include "sha1.h"

#define HOSTABLE_SIZE (20*1024)
#define EXPIRE (5*60)

//TODO: Use a hash table and a LRU for faster maintaince time
struct hostentry {
	char *pubid;
	time_t utime;
	struct sockaddr_in addr;
	struct hostentry *next;
	char *methods;
};

char option_secret[] = "secret";
int option_port = 6553;
char *option_waiif1 = "58.182.120.26";
char *option_waiif2 = "58.182.120.26";

struct sockaddr_in whoamitcp_addr[2], whoamiudp_addr[2];
struct hostentry *hostable[HOSTABLE_SIZE] = {0};
int hostable_used = 0;
time_t hostable_mtime = 0;

static void free_hostentry (struct hostentry *entry)
{
	assert(entry && entry->pubid);
	free(entry->pubid);
	if (entry->methods)
		free(entry->methods);
	entry->pubid = entry->methods = NULL;
	free(entry);
}

static void hostable_maintain (void)
{
	time_t currtime = time(NULL);
	int i;

	if (currtime - hostable_mtime < 30) // threshold maintain frequency
		return;
	hostable_mtime = currtime;
	for (i = 0; i < HOSTABLE_SIZE; i ++) {
		struct hostentry *entry = hostable[i];
		while (entry != NULL && currtime - entry->utime > EXPIRE) { // deal with head
			hostable[i] = entry->next;
			free_hostentry(entry);
			hostable_used --;
			entry = hostable[i];
		}
		if (entry == NULL)
			continue;
		while (entry->next != NULL) { // deal with non-head
			if (currtime - entry->next->utime > EXPIRE) {
				struct hostentry *todel = entry->next;
				entry->next = todel->next;
				free_hostentry(todel);
				hostable_used --;
			} else {
				entry = entry->next;
			}
		}
	}
}

// methods much be freeable
static void hostable_update (const char *pubid, char *methods, struct sockaddr_in *addr)
{
	unsigned long hashval = 0;
	struct hostentry *entry;
	int i;

	for (i = strlen(pubid) - 1; i >= 0; i --)
		hashval = ((const unsigned char *)pubid)[i] + hashval * 179;
	hashval = hashval % HOSTABLE_SIZE;
	for (entry = hostable[hashval]; entry != NULL && strcmp(entry->pubid, pubid) != 0; entry = entry->next)
		;
	if (entry == NULL) {
		entry = (struct hostentry *)malloc(sizeof(struct hostentry));
		entry->pubid = strdup(pubid);
		entry->methods = methods;
		entry->utime = time(NULL);
		memcpy(&entry->addr, addr, sizeof(struct sockaddr_in));
		entry->next = hostable[hashval];
		hostable[hashval] = entry;
		hostable_used ++;
	} else {
		free(entry->methods);
		entry->methods = methods;
		entry->utime = time(NULL);
		memcpy(&entry->addr, addr, sizeof(struct sockaddr_in));
	}
}

static struct hostentry *hostable_lookup (const char *pubid)
{
	unsigned long hashval = 0;
	struct hostentry *entry;
	int i;

	for (i = strlen(pubid) - 1; i >= 0; i --)
		hashval = ((const unsigned char *)pubid)[i] + hashval * 179;
	hashval = hashval % HOSTABLE_SIZE;
	for (entry = hostable[hashval]; entry != NULL && strcmp(entry->pubid, pubid) != 0; entry = entry->next)
		;
	return entry;
}

// output is hexdump, 41 bytes including null-term
static void compute_priv (const unsigned char *pubid, int publen, char *priv)
{
	struct SHA1Context sha;

	SHA1Reset(&sha);
	SHA1Input(&sha, pubid, publen);
	SHA1Input(&sha, (const unsigned char *)option_secret, strlen(option_secret));
	assert(SHA1Result(&sha));
	sprintf(priv, "%08x%08x%08x%08x%08x",
			sha.Message_Digest[0],
			sha.Message_Digest[1],
			sha.Message_Digest[2],
			sha.Message_Digest[3],
			sha.Message_Digest[4]);
}

static void do_register (int argc, char *argv[], int sock, struct sockaddr_in *addr)
{
	const int PUBID_LEN = 8;
	char pubid[PUBID_LEN+1], prv[41], msg[1000];
	int i, msglen;

	for (i = 0; i < PUBID_LEN; i ++) // use /dev/urandom for security
		pubid[i] = random() % 26 + 'a';
	pubid[i] = '\0';
	compute_priv((const unsigned char *)pubid, PUBID_LEN, prv);

	msglen = sprintf(msg, "REGISTER_OK\t%s\t%s:%s", pubid, pubid, prv);
	assert(sendto(sock, msg, msglen, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == msglen);
}

static void do_update (int argc, char *argv[], int sock, struct sockaddr_in *addr)
{
	char prvbuf[41], *pub, *prv, msg[32], *methods;
	struct timeval tv;
	int msglen, i;

	if (argc < 3)
		goto errout;
	if (strchr(argv[1], ':') == NULL)
		goto errout;

	pub = argv[1];
	prv = strchr(argv[1], ':') + 1;
	prv[-1] = '\0';
	compute_priv((unsigned char *)pub, strlen(pub), prvbuf);
	if (strcmp(prv, prvbuf) != 0)
		goto errout;

	// input validation on ip address?

	for (msglen = 0, i = 2; i < argc; i ++)
		msglen += strlen(argv[i]) + 1;
	methods = malloc(msglen);
	strcpy(methods, argv[2]);
	for (msglen = 0, i = 3; i < argc; i ++) {
		strcat(methods, "\t");
		strcat(methods, argv[i]);
	}

	hostable_update(pub, methods, addr);
	hostable_maintain();

	assert(gettimeofday(&tv, NULL) == 0);
	//msglen = sprintf(msg, "UPDATE_OK\t%lu\t%lu", (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
	msglen = sprintf(msg, "UPDATE_OK");
	assert(sendto(sock, msg, msglen, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == msglen);
	return;
errout:
	msglen = sprintf(msg, "UPDATE_ERROR");
	assert(sendto(sock, msg, msglen, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == msglen);
}

static void do_query (int argc, char *argv[], int sock, struct sockaddr_in *addr)
{
	struct hostentry *entry;
	char msg[1000];
	int msglen;

	if (argc != 2)
		goto errout;

	hostable_maintain();
	entry = hostable_lookup(argv[1]);
	if (entry == NULL)
		goto errout;

	msglen = snprintf(msg, sizeof(msg), "QUERY_OK\t%s", entry->methods);
	assert(sendto(sock, msg, msglen, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == msglen);
	return;
errout:
	msglen = sprintf(msg, "QUERY_ERROR");
	assert(sendto(sock, msg, msglen, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == msglen);
}

static void do_invite (int argc, char *argv[], int sock, struct sockaddr_in *addr)
{
	struct hostentry *entry;
	char msg[1000];
	int msglen;

	if (argc != 4)
		goto errout;

	//TODO: more input validation
	//if (strlen(argv[2]) + strlen(argv[3]) + strlen(argv[4])> 500)
	//	goto errout;

	hostable_maintain();
	entry = hostable_lookup(argv[1]);
	if (entry == NULL)
		goto errout;

	msglen = snprintf(msg, sizeof(msg), "INVITE_A\t%s\t%s", argv[2], argv[3]);
	assert(sendto(sock, msg, msglen, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == msglen);
	msglen = snprintf(msg, sizeof(msg), "INVITE_P\t%s\t%s", argv[2], argv[3]);
	assert(sendto(sock, msg, msglen, 0, (struct sockaddr *)&entry->addr, sizeof(struct sockaddr_in)) == msglen);
	return;
errout:
	msglen = sprintf(msg, "INVITE_ERROR");
	assert(sendto(sock, msg, msglen, 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == msglen);
}

static void do_whoami (int argc, char *argv[], int sock, struct sockaddr_in *addr)
{
	char msg[500], *ptr = msg;
	int i;

	i = random() % 2;
	ptr += sprintf(ptr, "WAI_UDP\t%s\t%d\t", inet_ntoa(whoamiudp_addr[i].sin_addr), ntohs(whoamiudp_addr[i].sin_port));
	ptr += sprintf(ptr, "%s\t%d\t", inet_ntoa(whoamiudp_addr[1-i].sin_addr), ntohs(whoamiudp_addr[1-i].sin_port));
	ptr += sprintf(ptr, "WAI_TCP\t%s\t%d\t", inet_ntoa(whoamitcp_addr[i].sin_addr), ntohs(whoamitcp_addr[i].sin_port));
	ptr += sprintf(ptr, "%s\t%d\t", inet_ntoa(whoamitcp_addr[1-i].sin_addr), ntohs(whoamitcp_addr[1-i].sin_port));
	ptr += sprintf(ptr, "WYA\t%s\t%d", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	assert(sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == strlen(msg));
}

static void do_time (int argc, char *argv[], int sock, struct sockaddr_in *addr)
{
	char msg[500];
	struct timeval tv;

	assert(gettimeofday(&tv, NULL) == 0);
	sprintf(msg, "TIME_OK\t%lu\t%lu", (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
	assert(sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)addr, sizeof(struct sockaddr_in)) == strlen(msg));
}

static void do_msg (char *msg, int sock, struct sockaddr_in *addr)
{
	char *argv[100];
	int argc = 0;

	assert(msg[0] != '\0' && msg[0] != '\t');
	argv[argc ++] = strtok(msg, "\t");
	while (1) {
		if (argc >= sizeof(argv) / sizeof(argv[0]) - 1)
			break;
		if ((argv[argc] = strtok(NULL, "\t")) == NULL)
			break;
		argc ++;
	}

	if (strcmp(argv[0], "REGISTER") == 0)
		do_register(argc, argv, sock, addr);
	else if (strcmp(argv[0], "UPDATE") == 0)
		do_update(argc, argv, sock, addr);
	else if (strcmp(argv[0], "QUERY") == 0)
		do_query(argc, argv, sock, addr);
	else if (strcmp(argv[0], "INVITE") == 0)
		do_invite(argc, argv, sock, addr);
	else if (strcmp(argv[0], "WHOAMI") == 0)
		do_whoami(argc, argv, sock, addr);
	else if (strcmp(argv[0], "TIME") == 0)
		do_time(argc, argv, sock, addr);
}

void run_whoami_server (int tcp, struct sockaddr_in *listen_addr, const char *whoami_if)
{
	int sock;
	struct sockaddr_in addr;
	socklen_t addrlen;

	sock = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
	assert(sock >= 0);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = 0;
	assert(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);

	memset(listen_addr, 0, sizeof(struct sockaddr_in));
	addrlen = sizeof(struct sockaddr_in);
	assert(getsockname(sock, (struct sockaddr *)listen_addr, &addrlen) == 0);
	if (whoami_if)
		assert(inet_aton(whoami_if, &listen_addr->sin_addr)); // TODO support domain name

	if (fork()) { // parent
		close(sock);
		return;
	}

	if (tcp)
		assert(listen(sock, 1) == 0);
	while (1) {
		int client, msglen;
		char *clientip, msg[500];

		memset(&addr, 0, sizeof(addr));
		addrlen = sizeof(addr);
		if (tcp) {
			client = accept(sock, (struct sockaddr *)&addr, &addrlen);
			assert(client >= 0);
		} else {
			assert(recvfrom(sock, msg, sizeof(msg)-1, 0, (struct sockaddr *)&addr, &addrlen) > 0); // ignore message contents
		}
		clientip = inet_ntoa(addr.sin_addr);
		assert(clientip != NULL);

		msglen = sprintf(msg, "WHOYOUARE\t%s\t%d", clientip, ntohs(addr.sin_port));
		if (tcp) {
			assert(send(client, msg, msglen, 0) == msglen);
			close(client);
		} else {
			assert(sendto(sock, msg, msglen, 0, (struct sockaddr *)&addr, addrlen) == msglen);
		}
	}
}

int main (int argc, char *argv[])
{
	int sock;
	struct sockaddr_in addr;

	run_whoami_server(1, &whoamitcp_addr[0], option_waiif1);
	run_whoami_server(1, &whoamitcp_addr[1], option_waiif2);
	run_whoami_server(0, &whoamiudp_addr[0], option_waiif1); // should we have separated if?
	run_whoami_server(0, &whoamiudp_addr[1], option_waiif2);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sock >= 0);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(option_port);
	assert(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0);

	while (1) {
		char buffer[1500];
		socklen_t addrlen;
		ssize_t msglen;

		memset(&addr, 0, sizeof(addr));
		addrlen = sizeof(addr);
		msglen = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addrlen);
		assert(msglen > 0 && msglen < sizeof(buffer));
		buffer[msglen] = '\0';
		printf("R: %s\n", buffer);
		do_msg(buffer, sock, &addr);
	}
}
