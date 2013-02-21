#ifndef NET_H
#define NET_H

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

// A simple mini library to create easy tcp/ip (ipv4) connections

static struct addrinfo* parseValidateAddress(char* addr){
	//Reference: http://www.geekpage.jp/en/programming/winsock/getaddrinfo-1.php
	char addrcpy[256];
	char *ipaddr_s, *port_s; //Strings with ip address and port, respectively
	struct addrinfo hints, *res;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	
	//Finding the colon
	char* colon;
	strncpy(addrcpy, addr, 256);
	colon = strstr(addrcpy, ":");
	
	//If the address doesn't have a colon, it's not valid.
	if(!colon) return 0;
	ipaddr_s = addrcpy;
	port_s = colon+1;
	*colon = 0;
	
	//Parses and validates ip address
	if(getaddrinfo(ipaddr_s, port_s, &hints, &res) != 0) return 0;

	return res;
}

static int net_connect(char* addr){
	struct addrinfo *res = parseValidateAddress(addr);
	if(res == 0) return 0;
	int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(sock == -1 || (connect(sock, res->ai_addr, res->ai_addrlen)) != 0){
		freeaddrinfo(res);
		return 0;
	}
	freeaddrinfo(res);
	return sock;
}

static int net_listen(char* addr){
	struct addrinfo *res = parseValidateAddress(addr);
	if(res == 0) return 0;
	
	int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(sock == -1) goto error;
	
	if(bind(sock, res->ai_addr, res->ai_addrlen) == -1) goto errorCloseSock;
	if(listen(sock,5) == -1) goto errorCloseSock;
	
	int newsock = accept(sock, res->ai_addr, &res->ai_addrlen);
	if(newsock == -1) goto errorCloseSock;
	
	freeaddrinfo(res);
	close(sock);
	return newsock;
	
errorCloseSock:
	close(sock);
error:
	freeaddrinfo(res);
	return 0;
}

#endif
