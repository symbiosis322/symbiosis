/*
-
	Bypass.c

	2015. 06. 24
-
*/

// Header
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h> 	// ioctl()
#include <fcntl.h> 		// O_RDWR

#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include "common.h"

// Define
#define DEBUG_BYPASS



// Function
int tun_alloc(char * dev, int flags)
{
	struct ifreq ifr;
	int fd, err;

	if ( ( fd = open( "/dev/net/tun", O_RDWR ) ) < 0 ) {
		perror("Opening /dev/net/tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if ( *dev ) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if ( ( err = ioctl( fd, TUNSETIFF, (void *) &ifr ) ) < 0 ) {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;
}


// Main
int main(int argc, char **argv)
{
	// ----------- Variable

	// IP Header : 20 bytes + Option
	// TCP Header : 20 bytes + Option
	// Buffer : IP Header + TCP Header + Contents(1024)
	char bypass_buff[BUFF_SIZE];

	struct iphdr *	ip_header	= (struct iphdr *) bypass_buff;
	struct tcphdr *	tcp_header	= 0;


	// ----------- Start
	printf("\nStart Server\n\n");



	// ----------- TUN device
	// printf("Get TUN Device\n");

	// char* tun_name = malloc(IFNAMSIZ);
	// tun_name[0] = '\0';

	// int tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
	// if(tun_fd < 0)
	// {
	// 	perror("Interface allocation failed");
	// 	exit(1);
	// }
	// else
	// {
	// 	printf("TUN device name\t: %s\n", tun_name);
	// 	printf("TUN device FD\t: %d\n", tun_fd);
	// }



	// ----------- Raw Socket (TCP)
	int send_socket = socket( PF_INET, SOCK_RAW, IPPROTO_TCP );

	if( send_socket == -1 ) {
		perror("socket");
		exit(1);
	}

	// ----------- Set Socket Option
	int on = 1;

	if( setsockopt( send_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on) ) < 0 )
	{
		perror("setsockopt");
		exit(1);
	}



	// ----------- UDP Socket
	printf("Create UDP Socket(Receive)\n");

	struct sockaddr_in bypass_addr;
	int bypass_socket = socketUDP(BYPASS_PORT, &bypass_addr);



	// ----------- Main Loop
	printf("Enter Main Loop\n");

	int r;
	while(1)
	{
		recvUDP( bypass_socket, bypass_buff, BUFF_SIZE, &bypass_addr );

		// ----------- Receive UDP Packet
		printf("\nReceive UDP Packet\n");

		tcp_header = (struct tcphdr *) (bypass_buff + ip_header->ihl * 4);

		// printf( "IP check : %d\n", ip_header->check );
		// printf( "TCP check : %x\n", (tcp_header->check) );

		// ip_header->daddr = inet_addr(PROXY_ADDR);
		// tcp_header->dest = htons(PROXY_PORT);

		// tcp_header->check = 0;
		// tcp_header->check = tcp_checksum(ip_header, tcp_header);

		// ip_header->check = 0;
		// ip_header->check = checksum2((unsigned short*)ip_header, sizeof(struct iphdr));
		

		#ifdef DEBUG_BYPASS
			printf("-----------------------------------------\n");

			printf( "[ 패킷을 받았습니다. ]\n" );
			printf( "Source IP : %s\n", inet_ntoa( * (struct in_addr*) &ip_header->saddr) );
			printf( "Source Port : %5u\n", ntohs(tcp_header->source) );
			printf( "Destination IP : %s\n", inet_ntoa( * (struct in_addr*) &ip_header->daddr) );
			printf( "Destination Port : %5u\n", ntohs(tcp_header->dest) );
			printf( "IP packet size : %d\n", ntohs(ip_header->tot_len));
			printf( "IP check : %d\n", ip_header->check );
			printf( "TCP check : %d\n", (tcp_header->check) );
			printf( "IP Version : %d\n", ip_header->version ); // IP 버전 정보 출력
			printf( "Time To Live : %d\n", ip_header->ttl );  // TTL 정보 출력
			printf( "Window Size : %d\n", tcp_header->window );  // 윈도우 사이즈 정보 출력
			printf( "Flags : " );  // 플래그 정보 출력
			if( tcp_header->fin == 1 ) printf( "[FIN]\n" );
			if( tcp_header->syn == 1 ) printf( "[SYN]\n" );
			if( tcp_header->rst == 1 ) printf( "[RST]\n" );
			if( tcp_header->psh == 1 ) printf( "[PSH]\n" );
			if( tcp_header->ack == 1 ) printf( "[ACK]\n" );
			if( tcp_header->urg == 1 ) printf( "[URG]\n" );

			printf("-----------------------------------------\n");
		#endif



		// ----------- Send Packet to Server
		printf("Send Packet to Server\n");
		//bypass_addr.sin_addr.s_addr	= inet_addr(SERVER_ADDR); // route?
		//printf("port: %d\n", bypass_addr.sin_port );
		//printf("addr: %s\n", inet_ntoa(bypass_addr.sin_addr) );
		sendto( send_socket, &bypass_buff, ntohs(ip_header->tot_len), 0, (struct sockaddr *) &bypass_addr, sizeof(bypass_addr) );


		// ----------- Send Packet to TUN Device
		// printf("Send Packet to TUN Device\n");

		// r = write( tun_fd, bypass_buff, ntohs(ip_header->tot_len) );
		// printf( "Write tun device %d\n", r);
	}
}
