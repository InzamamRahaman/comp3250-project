
#include "socks5_util.h"

/*
//AUTHENTICATION METHODS
#define METHOD_NO_AUTH		0x0
#define METHOD_GSSAPI 		0x01
#define METHOD_USERPASS		0x02
#define METHOD_NOACCEPT		0xFF
*/
char* METHOD_TO_STRING( unsigned int m )
{
	char *s = NULL;

	switch(m)
	{
		case METHOD_NO_AUTH:  s = "METHOD_NO_AUTH"; break;
		case METHOD_GSSAPI:   s = "METHOD_GSSAPI"; break;
		case METHOD_USERPASS: s = "METHOD_USERPASS"; break;
		case METHOD_NOACCEPT: s = "METHOD_NOACCEPT"; break;
		default:
			if( m >= 0x80 ) s = "METHOD_PRIVATE";
			else s = "METHOD_IANA_ASSIGNED";
	};

	return s;
}


/*
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
*/
char* REPLY_TO_STRING( unsigned int r )
{
	char *s = NULL;

	switch(r)
	{
		case REPLY_SUCCESS: s = "REPLY_SUCCESS"; break;
		case REPLY_FAILURE: s = "REPLY_FAILURE"; break;
		case REPLY_NOALLOW: s = "REPLY_NOALLOW"; break;
		case REPLY_NONETREACH: s = "REPLY_NONETREACH"; break;
		case REPLY_NOHOSTREACH: s = "REPLY_NOHOSTREACH"; break;
		case REPLY_CONNREFUSED: s = "REPLY_CONNREFUSED"; break;
		case REPLY_TTLEXP: s = "REPLY_TTLEXP"; break;
		case REPLY_NOCOMMAND: s = "REPLY_NOCOMMAND"; break;
		case REPLY_NOADDR: s = "REPLY_NOADDR"; break;

		default:
			s = "REPLY_UNKNOWN";
	};

	return s;
}



/*
//ADDR TYPES
#define ADDR_IPV4 0x01
#define ADDR_FQDN 0x03
#define ADDR_IPV6 0x04
*/
char* ADDRTYPE_TO_STRING( unsigned int a )
{
	char *s = NULL;

	switch(a)
	{
		case ADDR_IPV4: s = "ADDR_IPV4"; break;
		case ADDR_FQDN: s = "ADDR_FQDN"; break;
		case ADDR_IPV6: s = "ADDR_IPV6"; break;
		default:
			s = "ADDR_UNKNOWN";
	};

	return s;
}



/*
//COMMANDS
#define CMD_CONNECT 0x01
#define CMD_BIND 0x02
#define CMD_UDPASSOC 0x03
*/
char* CMD_TO_STRING( unsigned int c )
{
	char *s = NULL;

	switch(c)
	{
		case CMD_CONNECT: s = "CMD_CONNECT"; break;
		case CMD_BIND: s = "CMD_BIND"; break;

		/*TODO: UDP_ASSOC ( WHEN PROXY SERVER IS EXTENDED TO SUPPORT UDP )*/
		// case CMD_UDPASSOC: s = "CMD_UDPASSOC"; break;
		default:
			s = "CMD_NOTIMPLEMENTED";
	};

	return s;
}


void print_client_version_pkt( client_version_pkt *pkt )
{
	printf("[+]	Printing client version packet...\n");
	printf("ver = %d\nnmethods = %d\nmethods = ",(int)pkt->ver,(int)pkt->nmethods);
	for(int i = 0; i < pkt->nmethods; ++i) 
			printf(" %d(%s)",pkt->methods[i],METHOD_TO_STRING(pkt->methods[i]));
		
	printf("\n\n");
}


void print_server_method_pkt( server_method_pkt *pkt )
{
	printf("[+]Printing Server Method Packet\nVer: %d\nMethod: %d(%s)\n\n",
		pkt->ver,pkt->method,METHOD_TO_STRING(pkt->method));
}



void print_client_request_pkt( client_request_pkt *pkt )
{
	char *addr;
	int len;

	printf("[+] Printing client request packet...\n");
	printf("ver = %d\ncommand: %d(%s)\naddress type: %d(%s)\n",
			pkt->ver,pkt->cmd,CMD_TO_STRING(pkt->cmd),pkt->addr_type,ADDRTYPE_TO_STRING(pkt->addr_type));	

	switch( pkt->addr_type )
	{
		case ADDR_IPV4:
			struct in_addr in;
			in.s_addr = *((int*)pkt->addr);
			addr = inet_ntoa(in);
			break;

		case ADDR_FQDN:
			addr = (char*)&pkt->addr[1];
			break;

		default:
			addr = "NULL";
	};

	printf("addr: %s\nport: %u\n",addr,pkt->port);
}


void print_server_reply_pkt( server_reply_pkt *pkt ); /*TODO*/


client_request_pkt* recv_client_request_pkt( SOCKET s )
{
	int b1,b2,b3,b4,b5,rlen;
	b1 = b2 = b3 = b4 = 0;

	if( s == INVALID_SOCKET ) return NULL;

	client_request_pkt *cr_pkt = (client_request_pkt*)malloc(sizeof(client_request_pkt));

	if( cr_pkt )
	{
		memset(cr_pkt,0,sizeof(client_request_pkt));
		b1 = recv(s,(char*)&cr_pkt->ver,1,0);
		b2 = recv(s,(char*)&cr_pkt->cmd,1,0);
		b3 = recv(s,(char*)&cr_pkt->reserved,1,0);
		b4 = recv(s,(char*)&cr_pkt->addr_type,1,0);

		if( b4 == 1 )
		{
			switch( cr_pkt->addr_type )
			{
				case ADDR_IPV4:
					rlen = ADDR_IPV4_LEN;
					b4 = recv(s,(char*)&cr_pkt->addr,rlen,0);
				break;

				case ADDR_IPV6:
					rlen = ADDR_IPV6_LEN;
					b4 = recv(s,(char*)cr_pkt->addr,rlen,0);
				break;

				case ADDR_FQDN:
					b4 = recv(s,(char*)cr_pkt->addr,1,0);
					if( b4 == 1 )
					{
						rlen = (int)cr_pkt->addr[0];
						b4 = recv(s,(char*)&cr_pkt->addr[1],rlen,0);
						cr_pkt->addr[rlen+1] = '\0'; //NULL TERMINATES STRING
					}
				break;

			
			};
		}

		b5 = recv(s,(char*)&cr_pkt->port,2,0);

		if( b1!=1 || b2!=1 || b3!=1 || b4 != rlen || b5 != 2 )
		{
			//ERROR
			free(cr_pkt);
			cr_pkt = NULL;
		}

		cr_pkt->port = ntohs(cr_pkt->port);
	}

	return cr_pkt;
}


client_version_pkt* recv_client_version_pkt( SOCKET s )
{
	int b1,b2,b3;
	b1 = b2 = b3 = 0;

	if( s == INVALID_SOCKET ) return NULL;

	client_version_pkt *cv_pkt = (client_version_pkt*)malloc(sizeof(client_version_pkt));

	if( cv_pkt )
	{
		memset(cv_pkt,0,sizeof(client_version_pkt));	
		b1 = recv(s,(char*)&cv_pkt->ver,1,0);
		b2 = recv(s,(char*)&cv_pkt->nmethods,1,0);

		//There is no need to check the value of cv_pkt->nmethods
		//because it's value is restricted to 255(MAX_METHODS) and therefore
		//can never overflow cv->methods.
		b3 = recv(s,(char*)&cv_pkt->methods,cv_pkt->nmethods,0);

		if( b1 != 1 || b2 != 1 || b3 != cv_pkt->nmethods )
		{
			//Error!
			free(cv_pkt);
			cv_pkt = NULL;
		}
	}
	return cv_pkt;
}



bool send_server_method_pkt( SOCKET s, BYTE ver, BYTE method )
{
	int bytes_sent = 0;
	server_method_pkt pkt;
	pkt.ver = ver;
	pkt.method = method;

	bytes_sent = send(s,(char*)&pkt,sizeof(server_method_pkt),0);

	#ifdef _DEBUG_
		print_server_method_pkt(&pkt);
	#endif

	return (bytes_sent == sizeof(server_method_pkt));
}