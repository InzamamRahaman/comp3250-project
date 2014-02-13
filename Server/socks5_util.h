

#ifndef _SOCKS5_UTIL_H_
#define _SOCKS5_UTIL_H_

#include <memory.h>
#include <cstdio>
#include <cstdlib>
#include <winsock2.h>

typedef unsigned char BYTE;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned int SOCKET;

#define MAX_METHODS 255


#define METHOD_NO_AUTH		0x0
#define METHOD_GSSAPI 		0x01
#define METHOD_USERPASS		0x02
#define METHOD_NOACCEPT		0xFF

struct client_version_pkt
{
	BYTE ver;
	BYTE nmethods;
	BYTE methods[MAX_METHODS];
} __attribute__((packed));


struct server_method_pkt
{
	BYTE ver;
	BYTE method;
}  __attribute__((packed);


client_version_pkt* recv_client_version_pkt( SOCKET s );

/*
Return Value: true on success, false on failure
The function only returns successfully if the number of bytes
sent is equal to the size of a server_method_pkt
*/
bool send_server_method_pkt( SOCKET s, BYTE ver, BYTE method )
{
	int bytes_sent = 0;
	server_method_pkt pkt;
	pkt.ver = ver;
	pkt.method = method;

	bytes_sent = send(s,(char*)&pkt,sizeof(server_method_pkt),0);
	return (bytes_sent == sizeof(server_method_pkt));
}



void print_server_method_pkt( server_method_pkt *pkt );

void print_client_version_pkt( client_version_pkt *pkt );

void print_server_method_pkt( server_method_pkt *pkt );


#endif