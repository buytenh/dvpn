all:		client gencert genkey server test

clean:
		rm -f client
		rm -f gencert
		rm -f genkey
		rm -f server
		rm -f test

client:		client.c iv_getaddrinfo.c iv_getaddrinfo.h pconn.c pconn.h tun.c tun.h x509.c x509.h
		gcc -Wall -g -o client client.c iv_getaddrinfo.c pconn.c tun.c x509.c -lgnutls -livykis

gencert:	gencert.c x509.c x509.h
		gcc -Wall -g -o gencert gencert.c x509.c -lgnutls

genkey:		genkey.c x509.c x509.h
		gcc -Wall -g -o genkey genkey.c x509.c -lgnutls

server:		server.c pconn.c pconn.h tun.c tun.h x509.c x509.h
		gcc -Wall -g -o server server.c pconn.c tun.c x509.c -lgnutls -livykis

test:		test.c pconn.c pconn.h x509.c x509.h
		gcc -Wall -g -o test test.c pconn.c x509.c -lgnutls -livykis
