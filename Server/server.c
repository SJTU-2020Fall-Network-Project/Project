#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>


int main() {
	int sfd; char buf[1024]; int n, i;

	struct sockaddr_in serv_addr, cli_addr;
	socklen_t len;
	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(5012);
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind(sfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	while(1) {
		len = sizeof(cli_addr);
		n = recvfrom(sfd, buf , 1024, 0, (struct sockaddr *)&cli_addr, &len);
		for (i = 0; i < n; ++i) buf[i] = toupper(buf[i]);
		sendto(sfd,buf, n,0,(struct sockaddr *)&cli_addr, len);
	}
	close(sfd);
	return 0;
}
