natunnel -- Enabling TCP Server in NAT

Servers such as web servers and SSH servers in a NAT network cannot be
connected from outside the network. With natunnel, you are able to do so even
if your client is in a different NAT network.

How it works?
There are three parties: 1. the natunnel proxy server (NProxy), which runs at a
public IP address; 2. the natunnel server-side program (NServer), which runs in
the same host (or same NAT) as the server; and 3. the natunnel client-side
program (NClient), which runs in the same host (or same NAT) as the client.

To use natunnel, first, NServer registers a server ID from a Natunnel Proxy
Server.  This is a one-time operation.  The server ID can then be published so
that the clients know how to identify the server.  The NServer then silently
waits for connection in the background.  Second, NClient uses the server ID to
contact NProxy.  The NClient and NServer can then do NAT traversal with the
help of NProxy.  A tunneling connection is then created between NClient and
NServer.  Last, TCP data is tunnelled through the connection.

As an example, we want to connect to our SSH server in a NAT.
1. on the SSH server, run
# ./natunnel proxy.server.address port REGISTER
Your server ID is abcd1234.
# ./natunnel proxy.server.address port 22
(program runs in background)

2. on the client, run
# ./natunnel proxy.server.address port abcd1234 6666
(program runs in background)
# ssh -p 6666 localhost
