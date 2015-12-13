all:		conftest dvpn topowalk

clean:
		rm -f *.dot
		rm -f client.ini
		rm -f client.key
		rm -f conftest
		rm -f dvpn
		rm -f server.ini
		rm -f server.key
		rm -f topowalk

conftest:	conftest.c conf.c conf.h util.c util.h
		gcc -Wall -g -o conftest conftest.c conf.c util.c -lini_config

dvpn:		dvpn.c conf.c conf.h confdiff.c confdiff.h connect.c connect.h itf.c itf.h iv_getaddrinfo.c iv_getaddrinfo.h listen.c listen.h pconn.c pconn.h tun.c tun.h util.c util.h x509.c x509.h
		gcc -Wall -g -o dvpn dvpn.c conf.c confdiff.c connect.c itf.c iv_getaddrinfo.c listen.c pconn.c tun.c util.c x509.c -lgnutls -lini_config -livykis

topowalk:	topowalk.c conf.c conf.h cspf.c cspf.h spf.c spf.h
		gcc -Wall -g -o topowalk topowalk.c conf.c cspf.c spf.c x509.c -lgnutls -lini_config


test:		client.ini client.key dvpn server.ini server.key

client.ini:	server.key dvpn
		@echo PrivateKey=client.key > client.ini
		@echo >> client.ini
		@echo [local] >> client.ini
		@echo Connect=localhost:19275 >> client.ini
		@echo PeerFingerprint=`./dvpn --show-key-id server.key` >> client.ini
		@echo PeerType=peer >> client.ini
		@echo TunInterface=tapc%d >> client.ini

client.key:
		certtool --generate-privkey --rsa --sec-param=high --outfile client.key

server.ini:	client.key dvpn
		@echo PrivateKey=server.key > server.ini
		@echo >> server.ini
		@echo [local] >> server.ini
		@echo Listen=0.0.0.0:19275 >> server.ini
		@echo PeerFingerprint=`./dvpn --show-key-id client.key` >> server.ini
		@echo PeerType=peer >> server.ini
		@echo TunInterface=tap0 >> server.ini

server.key:
		certtool --generate-privkey --rsa --sec-param=high --outfile server.key
