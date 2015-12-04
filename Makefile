all:		conftest dvpn genkey keyid

clean:
		rm -f client.ini
		rm -f client.key
		rm -f conftest
		rm -f dvpn
		rm -f genkey
		rm -f keyid
		rm -f server.ini
		rm -f server.key

conftest:	conftest.c conf.c conf.h util.c util.h
		gcc -Wall -g -o conftest conftest.c conf.c util.c -lini_config

dvpn:		dvpn.c conf.c conf.h connect.c connect.h itf.c itf.h iv_getaddrinfo.c iv_getaddrinfo.h listen.c listen.h pconn.c pconn.h tun.c tun.h util.c util.h x509.c x509.h
		gcc -Wall -g -o dvpn dvpn.c conf.c connect.c itf.c iv_getaddrinfo.c listen.c pconn.c tun.c util.c x509.c -lgnutls -lini_config -livykis

genkey:		genkey.c x509.c x509.h
		gcc -Wall -g -o genkey genkey.c x509.c -lgnutls

keyid:		keyid.c x509.c x509.h
		gcc -Wall -g -o keyid keyid.c x509.c -lgnutls


test:		client.ini client.key dvpn server.ini server.key

client.ini:	keyid server.key
		@echo PrivateKey=client.key > client.ini
		@echo >> client.ini
		@echo [local] >> client.ini
		@echo Connect=localhost:19275 >> client.ini
		@echo PeerFingerprint=`./keyid server.key` >> client.ini
		@echo PeerType=peer >> client.ini
		@echo TunInterface=tapc%d >> client.ini

client.key:	genkey
		./genkey client.key 4096 > /dev/null

server.ini:	client.key keyid
		@echo PrivateKey=server.key > server.ini
		@echo >> server.ini
		@echo [local] >> server.ini
		@echo Listen=0.0.0.0:19275 >> server.ini
		@echo PeerFingerprint=`./keyid client.key` >> server.ini
		@echo PeerType=peer >> server.ini
		@echo TunInterface=tap0 >> server.ini

server.key:	genkey
		./genkey server.key 4096 > /dev/null
