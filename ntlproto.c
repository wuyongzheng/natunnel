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
#include <errno.h>
#include "natunnel.h"
#include "ntlproto.h"

#define NTL_TIMEOUTSEC 3
#define NTL_UPDATESEC 60
#define NTL_UPDATELIMITSEC 15

//TODO sequence number, retry

static void setsocketto (int sock, int tosec)
{
	struct timeval tv;
	tv.tv_sec = tosec;
	tv.tv_usec = 0;
	assert(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval)) == 0);
}

struct ntl_struct *ntl_init (const struct sockaddr_in *serveraddr, const char *pubid, const char *privid)
{
	struct ntl_struct *ntl = (struct ntl_struct *)malloc(sizeof(struct ntl_struct));
	ntl->sock = socket(AF_INET, SOCK_DGRAM, 0);
	assert(ntl->sock >= 0);
	if (pubid)
		ntl->pubid = strdup(pubid);
	if (privid)
		ntl->privid = strdup(privid);
	assert(connect(ntl->sock, (const struct sockaddr *)serveraddr, sizeof(struct sockaddr_in)) == 0);
	ntl->lastupdate_recv = ntl->lastupdate_sent = 0;
	return ntl;
}

void ntl_free (struct ntl_struct *ntl)
{
	if (ntl->sock >= 0)
		close(ntl->sock);
	if (ntl->pubid)
		free(ntl->pubid);
	if (ntl->privid)
		free(ntl->privid);
	free(ntl);
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
	tv.tv_sec = tcp ? NTL_TIMEOUTSEC * 2 : NTL_TIMEOUTSEC;
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
	argc = str_explode(msg, "\t", argv, sizeof(argv)/sizeof(argv[0]));
	if (argc != 3 || strcmp("WHOYOUARE", argv[0]) ||
			resolve_ipv4_address(extaddr, argv[1], atoi(argv[2]))) {
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
int ntl_whoami (struct ntl_struct *ntl, int istcp, int *intport, struct sockaddr_in *extaddr, int tworound)
{
	int msglen, argc;
	struct sockaddr_in addr, server_addr;
	char msg[1000], *argv[14];

	if (send(ntl->sock, "WHOAMI", strlen("WHOAMI"), 0) != strlen("WHOAMI")) {
		perror("ntl_whoami() send WHOAMI error");
		return 2;
	}
	setsocketto(ntl->sock, NTL_TIMEOUTSEC);
	msglen = recv(ntl->sock, msg, sizeof(msg)-1, 0);
	if (msglen <= 0) { // TODO retry
		perror("recv WHOAMI response error\n");
		return 2;
	}
	msg[msglen] = '\0';
	puts(msg);
	argc = str_explode(msg, "\t", argv, sizeof(argv)/sizeof(argv[0]));
	if (argc != 13 || strcmp(argv[0], "WAI_UDP") != 0) {
		printf("WHOAMI response error\n");
		return 2;
	}

	if (resolve_ipv4_address(&server_addr, argv[1+istcp*5], atoi(argv[2+istcp*5]))) {
		printf("WHOAMI response error\n");
		return 2;
	}
	if (whoami_test(istcp, &server_addr, intport, extaddr))
		return 2;
	if (!tworound)
		return 0;

	if (resolve_ipv4_address(&server_addr, argv[3+istcp*5], atoi(argv[4+istcp*5]))) {
		printf("WHOAMI response error\n");
		return 2;
	}
	if (whoami_test(istcp, &server_addr, intport, &addr))
		return 2;
	if (memcmp(extaddr, &addr, sizeof(addr)))
		return 1;
	return 0;
}

int ntl_register (struct ntl_struct *ntl)
{
	int argc, msglen;
	char msg[500], *argv[6];

	if (send(ntl->sock, "REGISTER", strlen("REGISTER"), 0) != strlen("REGISTER")) {
		perror("ntl_register() send REGISTER failed");
		return -1;
	}
	setsocketto(ntl->sock, NTL_TIMEOUTSEC);
	msglen = recv(ntl->sock, msg, sizeof(msg)-1, 0);
	if (msglen <= 0) { // TODO retry
		perror("recv REGISTER response error");
		return -1;
	}
	msg[msglen] = '\0';
	puts(msg);
	argc = str_explode(msg, "\t", argv, sizeof(argv)/sizeof(argv[0]));
	if (argc != 3 || strcmp(argv[0], "REGISTER_OK") != 0)
		return -1;
	ntl->pubid = strdup(argv[1]);
	ntl->privid = strdup(argv[2]);
	return 0;
}

// return number of methods
// return -1 on error
int ntl_query (struct ntl_struct *ntl, struct punch_param *supported_punches, int npunch)
{
	int argc, msglen, i;
	char msg[500], *argv[10];

	if (!ntl->pubid) {
		printf("ntl_query() no pubid\n");
		return -1;
	}
	snprintf(msg, sizeof(msg), "QUERY\t%s", ntl->pubid);
	puts(msg);
	if (send(ntl->sock, msg, strlen(msg), 0) != strlen(msg)) {
		perror("ntl_query() send QUERY failed");
		return -1;
	}
	setsocketto(ntl->sock, NTL_TIMEOUTSEC);
	msglen = recv(ntl->sock, msg, sizeof(msg)-1, 0);
	if (msglen <= 0) { // TODO retry
		perror("recv QUERY response error");
		return -1;
	}
	msg[msglen] = '\0';
	puts(msg);
	argc = str_explode(msg, "\t", argv, sizeof(argv)/sizeof(argv[0]));
	if (argc < 2 || strcmp(argv[0], "QUERY_OK") != 0)
		return -1;

	for (i = 0; i < argc - 1 && i < npunch; i ++) {
		if (punch_fromstring(&supported_punches[i], argv[i+1]))
			return -1;
	}
	return i;
}

int ntl_invite (struct ntl_struct *ntl, const struct punch_param *ext, const struct punch_param *peer)
{
	int argc, msglen;
	char msg[500], *argv[10];

	if (!ntl->pubid) {
		printf("ntl_invite() no pubid\n");
		return -1;
	}
	msglen = snprintf(msg, sizeof(msg), "INVITE\t%s\t%s\t%s", ntl->pubid, punch_tostring(peer), punch_tostring(ext));
	puts(msg);
	if (send(ntl->sock, msg, msglen, 0) != msglen) {
		perror("ntl_invite() send INVITE failed");
		return -1;
	}
	setsocketto(ntl->sock, NTL_TIMEOUTSEC);
	msglen = recv(ntl->sock, msg, sizeof(msg)-1, 0);
	if (msglen <= 0) { // TODO retry
		perror("recv INVITE response error");
		return -1;
	}
	msg[msglen] = '\0';
	puts(msg);
	argc = str_explode(msg, "\t", argv, sizeof(argv)/sizeof(argv[0]));
	if (argc != 3 || strcmp(argv[0], "INVITE_A") != 0) // we just ignore the rest??
		return -1;
	return 0;
}

/* timesec: if no invite with n seconds, return 0
 *          0 just update (if necessary) and return
 *          -1 never timeout
 * return: 0 timeout
 *         1 invite comes
 *         -1 error
 */
int ntl_waitinvite (struct ntl_struct *ntl, int timesec,
		struct punch_param *supported_punches, int npunch,
		struct punch_param *requested_punch)
{
	time_t entrytime = time(NULL);

	if (!ntl->privid) {
		printf("ntl_waitinvite() no privid\n");
		return -1;
	}

	while (1) {
		int argc, msglen, i;
		char msg[1000], *argv[10];
		time_t currtime = time(NULL);

		if (currtime - ntl->lastupdate_recv > NTL_UPDATESEC &&
				currtime - ntl->lastupdate_sent > NTL_UPDATELIMITSEC) {
			msglen = snprintf(msg, sizeof(msg), "UPDATE\t%s", ntl->privid);
			for (i = 0; i < npunch && msglen + 100 < sizeof(msg); i ++) {
				msglen += snprintf(msg+msglen, sizeof(msg)-msglen, "\t%s", punch_tostring(&supported_punches[i]));
			}
			puts(msg);
			if (send(ntl->sock, msg, msglen, 0) != msglen) {
				perror("ntl_waitinvite() send UPDATE failed");
				return -1;
			}
			ntl->lastupdate_sent = currtime;
		}

		if (timesec != -1 && entrytime + timesec >= currtime)
			return 0;

		setsocketto(ntl->sock, NTL_UPDATELIMITSEC);
		msglen = recv(ntl->sock, msg, sizeof(msg)-1, 0);
		if (msglen < 0) {
			perror("recv UPDATE_OK/INVITE_P error");
			return -1;
		}
		if (msglen == 0)
			continue;
		msg[msglen] = '\0';
		puts(msg);
		argc = str_explode(msg, "\t", argv, sizeof(argv)/sizeof(argv[0]));
		if (argc == 1 && strcmp(argv[0], "UPDATE_OK") == 0) {
			ntl->lastupdate_recv = time(NULL);
			continue;
		}
		if (argc == 3 && strcmp(argv[0], "INVITE_P") == 0) {
			return (punch_fromstring(&requested_punch[0], argv[1]) || punch_fromstring(&requested_punch[1], argv[1])) ? -1 : 1;
		}
		printf("Unknown message: %s\n", argv[0]);
		return -1;
	}
}
