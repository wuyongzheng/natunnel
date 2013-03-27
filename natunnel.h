#ifndef NATUNNEL_H
#define NATUNNEL_H

enum punch_type {
	PT_FLOOR,
	PT_P2PNAT,
	PT_UDT,
	PT_CEILING
};

struct punch_param {
	enum punch_type type;
	union {
		struct {
			struct sockaddr_in addr;
		} p2pnat;
		struct {
			struct sockaddr_in addr;
		} udt;
	};
};

struct punch_local_param {
	enum punch_type type;
	union {
		struct {
			int localport;
		} p2pnat;
		struct {
			int localport;
		} udt;
	};
};

int str_explode (char *str, const char *sep, char *argv[], int argc);
int resolve_ipv4_address (struct sockaddr_in *addr, const char *addrstr, int port);

int punch_fromstring (struct punch_param *punch, char *str);
char *punch_tostring (const struct punch_param *punch);
int punch_p2pnat_param_init (struct punch_local_param *local, struct punch_param *peer, int haslocal);
int punch_udt_param_init (struct punch_local_param *local, struct punch_param *peer, int haslocal);
int punch_p2pnat (const struct punch_local_param *local, const struct punch_param *peer);
int punch_udt (const struct punch_local_param *local, const struct punch_param *peer);
int do_stun (int istcp, int tworound, int *localport, struct sockaddr_in *extaddr);

#endif
