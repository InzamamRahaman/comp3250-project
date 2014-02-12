
#include "socks5_util.h"



void print_client_version_pkt( client_version_pkt *pkt )
{
	printf("Printing client version packet...\n");
	printf("ver = %d\nnmethods = %d\nmethods = ",(int)pkt->ver,(int)pkt->nmethods);
	for(int i = 0; i < pkt->nmethods; ++i) 
		{
			printf(" %d",pkt->methods[i]);
			switch( pkt->methods[i] )
			{
				case METHOD_NO_AUTH: printf("(METHOD_NO_AUTH)"); break;
				case METHOD_GSSAPI: printf("(METHOD_GSSAPI)"); break;
				case METHOD_USERPASS: printf("(METHOD_USERPASS)"); break;
				case METHOD_NOACCEPT: printf("METHOD_NOACCEPT"); break;
				default:
					if( pkt->methods[i] >= 0x80 ) printf("(PRIVATE)");
					else printf("(IANA ASSIGNED)");
			};

		}
	printf("\n\n");
}




client_version_pkt* recv_client_version_pkt( SOCKET s )
{
	int b1,b2,b3;
	b1 = b2 = b3 = 0;

	if( s == INVALID_SOCKET ) return NULL;

	client_version_pkt *cv_pkt = (client_version_pkt*)malloc(sizeof(client_version_pkt));
	memset(cv_pkt,0,sizeof(client_version_pkt));

	if( cv_pkt )
	{
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


