#include <cstdio>
#include <cstdlib>
#include <windows.h>
#include <winsock2.h>
#include "socks5_util.h"

#define PORT 8080

int main()
{
	WSADATA data;
	WSAStartup(MAKEWORD(2,0),&data);

	SOCKET s = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if( s == INVALID_SOCKET ) printf("socket failed with error: %d\n",WSAGetLastError());

	sockaddr_in bind_info;
	memset(&bind_info,0,sizeof(sockaddr_in));

	bind_info.sin_family = AF_INET;
	bind_info.sin_port = htons(PORT);
	bind_info.sin_addr.s_addr = INADDR_ANY;


	int ret = bind(s,(sockaddr*)&bind_info,sizeof(sockaddr_in));

	if( ret != 0  ) printf("bind failed with error: %d\n",WSAGetLastError());
 
	ret = listen(s,10);

	if( ret != 0  ) printf("listen failed with error: %d\n",WSAGetLastError());

	SOCKET c = accept(s,NULL,NULL);

	if( c == INVALID_SOCKET ) { printf("Error in accept: %d\n",WSAGetLastError()); }


	printf("Client connected!\n");

	client_version_pkt *cv_pkt = recv_client_version_pkt(c);
	if( cv_pkt == NULL ) printf("Failed to receive client version packet! with error: %d\n",WSAGetLastError());
	else print_client_version_pkt(cv_pkt);

	WSACleanup();
	return 0;
}