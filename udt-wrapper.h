#ifdef __cplusplus
extern "C" {
#endif

int udt_socket(int af, int type, int protocol);
int udt_bind(int u, const struct sockaddr* name, int namelen);
int udt_listen(int u, int backlog);
int udt_connect(int u, const struct sockaddr* name, int namelen);
int udt_close(int u);
int udt_setsockopt(int u, int level, int optname, const void* optval, int optlen);
int udt_send(int u, const char* buf, int len, int flags);
int udt_recv(int u, char* buf, int len, int flags);
int udt_getlasterror(void);

int udt_setsockopt_rendezvous(int u, int rendezvous);

#ifdef __cplusplus
}
#endif
