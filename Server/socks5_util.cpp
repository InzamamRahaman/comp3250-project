
#include "socks5_util.h"

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




client_request_pkt* recv_client_request_pkt( SOCKET s )
{
	int b1,b2;
	b1 = b2 = 0;

	if( s == INVALID_SOCKET ) return NULL;

	client_request_pkt *cr_pkt = (client_request_pkt*)malloc(sizeof(client_request_pkt));

	if( cr_pkt )
	{
		memset(cr_pkt,0,sizeof(client_request_pkt));
		b1 = recv(s,(char*)cr_pkt);
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
	return (bytes_sent == sizeof(server_method_pkt));
}