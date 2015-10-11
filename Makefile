all:		test

clean:
		rm -f test

test:		test.c pconn.c pconn.h
		gcc -Wall -o test test.c pconn.c -lgnutls -livykis
