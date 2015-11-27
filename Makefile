all:		conftest dvpn gencert genkey

clean:
		rm -f conftest
		rm -f dvpn
		rm -f gencert
		rm -f genkey

conftest:	conftest.c conf.c conf.h
		gcc -Wall -g -o conftest conftest.c conf.c -lini_config

dvpn:		dvpn.c conf.c conf.h connect.c connect.h itf.c itf.h iv_getaddrinfo.c iv_getaddrinfo.h listen.c listen.h pconn.c pconn.h tun.c tun.h x509.c x509.h
		gcc -Wall -g -o dvpn dvpn.c conf.c connect.c itf.c iv_getaddrinfo.c listen.c pconn.c tun.c x509.c -lgnutls -lini_config -livykis

gencert:	gencert.c x509.c x509.h
		gcc -Wall -g -o gencert gencert.c x509.c -lgnutls

genkey:		genkey.c x509.c x509.h
		gcc -Wall -g -o genkey genkey.c x509.c -lgnutls
