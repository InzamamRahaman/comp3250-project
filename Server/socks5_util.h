

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

//SIZE CONSTANTS
#define MAX_METHODS 255
#define MAX_FQDN_LEN 1024

//AUTHENTICATION METHODS
#define METHOD_NO_AUTH		0x0
#define METHOD_GSSAPI 		0x01
#define METHOD_USERPASS		0x02
#define METHOD_NOACCEPT		0xFF


/*
The structures are declared with __attribute((packed)) to ensure
that there is no padding anywhere from the start of the first member
to the end of the last member. This allows for structures to
be sent and received in their entirety with just one call to
send() or recv().
*/

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
}  __attribute__((packed));


struct socks_request_pkt
{
	BYTE ver;
	BYTE cmd;
	BYTE reserved;
	BYTE addr_type;

	/*
	This variable doesn't necessarily
	have to contain a fully qualified
	domain name. It can also contain either
	an ipv4	address or an ipv6 address.
	MAX_FQDN_LEN+1 is guaranteed to be
	large enough to hold an of the 3
	possible address types.
	*/
	BYTE addr[MAX_FQDN_LEN+1]; //IPV6 NOT CURRENTLY SUPPORTED  

	ushort port;

} __attribute__((packed));



char* METHOD_TO_STRING( unsigned int m );


client_version_pkt* recv_client_version_pkt( SOCKET s );

/*
Return Value: true on success, false on failure
The function only returns successfully if the number of bytes
sent is equal to the size of a server_method_pkt
*/
bool send_server_method_pkt( SOCKET s, BYTE ver, BYTE method );


void print_client_version_pkt( client_version_pkt *pkt );

void print_server_method_pkt( server_method_pkt *pkt );




#endif