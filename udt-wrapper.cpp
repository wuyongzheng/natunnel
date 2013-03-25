#include <udt.h>

extern "C" {

int udt_socket(int af, int type, int protocol) {
	return (int)UDT::socket(af, type, protocol);
}
int udt_bind(int u, const struct sockaddr* name, int namelen) {
	return UDT::bind((UDTSOCKET)u, name, namelen);
}
int udt_listen(int u, int backlog) {
	return UDT::listen((UDTSOCKET)u, backlog);
}
int udt_connect(int u, const struct sockaddr* name, int namelen) {
	return UDT::connect((UDTSOCKET)u, name, namelen);
}
int udt_close(int u) {
	return UDT::close((UDTSOCKET)u);
}
int udt_setsockopt(int u, int level, int optname, const void* optval, int optlen) {
	return UDT::setsockopt((UDTSOCKET)u, level, (UDT::SOCKOPT)optname, optval, optlen);
}
int udt_send(int u, const char* buf, int len, int flags) {
	return UDT::send((UDTSOCKET)u, buf, len, flags);
}
int udt_recv(int u, char* buf, int len, int flags) {
	return UDT::recv((UDTSOCKET)u, buf, len, flags);
}

int udt_setsockopt_rendezvous(int u, int rendezvous) {
	bool rend = rendezvous;
	return UDT::setsockopt((UDTSOCKET)u, 0, UDT_RENDEZVOUS, &rend, sizeof(bool));
}

}
