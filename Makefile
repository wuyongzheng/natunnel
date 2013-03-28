all: ntlserver natunnel

ntlserver: ntlserver.c sha1.c
	gcc -g -Wall -o ntlserver ntlserver.c sha1.c

natunnel: natunnel.o udt-wrapper.o ntlproto.o punch-p2pnat.o punch-udt.o utils.o punch.o
	gcc -g -Wall -o natunnel $^ -L ~/build/udt4/src -l udt -l pthread -l stdc++ -lm

%.o: %.c
	gcc -g -Wall -c $<

udt-wrapper.o: udt-wrapper.cpp
	g++ -g -Wall -c udt-wrapper.cpp -I ~/build/udt4/src

clean:
	rm -f *.o ntlserver natunnel
