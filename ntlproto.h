#ifndef NTLPROTO_H
#define NTLPROTO_H

#include "natunnel.h"

struct ntl_struct {
	int sock;
	char *pubid, *privid;
	time_t lastupdate_recv, lastupdate_sent;
};

struct ntl_struct *ntl_init (const struct sockaddr_in *serveraddr, const char *pubid, const char *privid);
void ntl_free (struct ntl_struct *ntl);
int ntl_whoami (struct ntl_struct *ntl, int istcp, int *intport, struct sockaddr_in *extaddr, int tworound);
int ntl_register (struct ntl_struct *ntl);
int ntl_query (struct ntl_struct *ntl, struct punch_param *supported_punches, int npunch);
int ntl_invite (struct ntl_struct *ntl, const struct punch_param *ext, const struct punch_param *peer);
int ntl_waitinvite (struct ntl_struct *ntl, int timesec,
		struct punch_param *supported_punches, int npunch,
		struct punch_param *requested_punch);

#endif
