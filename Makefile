all: ntlserver natunnel

ntlserver: ntlserver.c sha1.c
	gcc -Wall -o ntlserver ntlserver.c sha1.c

natunnel: natunnel.c
	gcc -Wall -o natunnel natunnel.c
