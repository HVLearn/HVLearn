CC=gcc
CFLAGS=-g -Wall
SHARE=-shared -fPIC

GNUTLS=-lgnutls


SSL_ROOT:=-I..

JDK=-I/usr/lib/jvm/default-java/include/ -I/usr/lib/jvm/default-java/include/linux/

all: server

server: serverJNI.c
	$(CC) $(CFLAGS) $(SHARE) $(JDK) $(SSL_ROOT) \
		serverJNI.c -o libserverJNI.so $(GNUTLS)

clean:
	rm -f libserverJNI.so
