#A simple makefile for fcenc and fcdec.
#Both share the same sourcecode and objectfiles, the execution path
#being influenced by the program image's name (argv[0])

#gcc (Ubuntu/Linaro 4.6.1-9ubuntu3) 4.6.1 was used for compilation
CC=gcc

#Gcrypt and ssl libraries are required.
CFLAGS=-Wall -g `libgcrypt-config --cflags --libs` -lssl -lcrypto

all: fcenc fcdec

fcenc:
	$(CC) crypt.c fileCrypt.c $(CFLAGS)  -o fcenc

fcdec:
	$(CC) crypt.c fileCrypt.c $(CFLAGS) -o fcdec

clean:
	rm fcenc fcdec
