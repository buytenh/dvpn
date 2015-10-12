all:		gencert genkey test

clean:
		rm -f gencert
		rm -f genkey
		rm -f test

gencert:	gencert.c x509.c x509.h
		gcc -Wall -o gencert gencert.c x509.c -lgnutls

genkey:		genkey.c x509.c x509.h
		gcc -Wall -o genkey genkey.c x509.c -lgnutls

test:		test.c pconn.c pconn.h
		gcc -Wall -o test test.c pconn.c -lgnutls -livykis
