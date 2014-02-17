
#ifndef _SOCKS5_UTIL_H_
#define _SOCKS5_UTIL_H_

#include <memory.h>
#include <cstdio>
#include <cstdlib>
#include <winsock2.h>

#define _DEBUG_


typedef unsigned char BYTE;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned int SOCKET;

//SIZE CONSTANTS
#define MAX_METHODS 255
#define MAX_FQDN_LEN 255

#define SERVER_VERSION 0x05

//AUTHENTICATION METHODS
#define METHOD_NO_AUTH		0x0
#define METHOD_GSSAPI 		0x01
#define METHOD_USERPASS		0x02
#define METHOD_NOACCEPT		0xFF

//ADDR TYPES
#define ADDR_IPV4 0x01
#define ADDR_FQDN 0x03
#define ADDR_IPV6 0x04

//ADDR TYPE LENGTHS
#define ADDR_IPV4_LEN 0x04
#define ADDR_IPV6_LEN 0x10


//COMMANDS
#define CMD_CONNECT 0x01
#define CMD_BIND 0x02
#define CMD_UDPASSOC 0x03


/*
o  REP    Reply field:
     o  X'00' succeeded
     o  X'01' general SOCKS server failure
     o  X'02' connection not allowed by ruleset
     o  X'03' Network unreachable
     o  X'04' Host unreachable
     o  X'05' Connection refused
     o  X'06' TTL expired
     o  X'07' Command not supported
     o  X'08' Address type not supported
     o  X'09' to X'FF' unassigned
*/

//REPLY TYPES
#define REPLY_SUCCESS 0x00
#define REPLY_FAILURE 0x01
#define REPLY_NOALLOW 0x02
#define REPLY_NONETREACH 0x03
#define REPLY_NOHOSTREACH 0x04
#define REPLY_CONNREFUSED 0x05
#define REPLY_TTLEXP 0x06
#define REPLY_NOCOMMAND 0x07
#define REPLY_NOADDR 0x08

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


struct client_request_pkt
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




struct server_reply_pkt
{
	BYTE ver;
	BYTE reply;
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
char* REPLY_TO_STRING( unsigned int r ); 
char* ADDRTYPE_TO_STRING( unsigned int a );
char* CMD_TO_STRING( unsigned int c );

client_request_pkt* recv_client_request_pkt( SOCKET s );
client_version_pkt* recv_client_version_pkt( SOCKET s );

/*
Return Value: true on success, false on failure
The function only returns successfully if the number of bytes
sent is equal to the size of a server_method_pkt
*/
bool send_server_method_pkt( SOCKET s, BYTE ver, BYTE method );

bool send_server_reply_pkt( SOCKET s, BYTE ver, BYTE reply, BYTE addr_type, BYTE *addr , int addr_len ,ushort port ); /*TODO*/


void print_client_version_pkt( client_version_pkt *pkt );
void print_server_method_pkt( server_method_pkt *pkt );
void print_client_request_pkt( client_request_pkt *pkt );
void print_server_reply_pkt( server_reply_pkt *pkt ); /*TODO*/

#endif