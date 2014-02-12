

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
};


struct server_method_pkt
{
	BYTE ver;
	BYTE method;
};


client_version_pkt* recv_client_version_pkt( SOCKET s );
void print_client_version_pkt( client_version_pkt *pkt );

#endif