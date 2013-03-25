all: ntlserver natunnel

ntlserver: ntlserver.c sha1.c
	gcc -g -Wall -o ntlserver ntlserver.c sha1.c

natunnel: natunnel.o udt-wrapper.o
	gcc -g -Wall -o natunnel natunnel.o udt-wrapper.o -L ~/build/udt4/src -l udt -l pthread -l stdc++ -lm
natunnel.o: natunnel.c udt-wrapper.h
	gcc -g -Wall -c natunnel.c
udt-wrapper.o: udt-wrapper.cpp
	g++ -g -Wall -c udt-wrapper.cpp -I ~/build/udt4/src
