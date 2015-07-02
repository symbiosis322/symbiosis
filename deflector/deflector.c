/*
-
	Deflector.c

	2015. 06. 24
-
*/

// Header
#include <sys/stat.h>

#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "common.h"











// Define
#define DEBUG_DEFLECTOR



// Main
int main(int argc, char **argv)
{
	// ----------- Variable
	char recv_packet[BUFF_SIZE+40];

	struct iphdr *	ip_header	= (struct iphdr *) recv_packet;
	struct tcphdr *	tcp_header	= 0;
	
	

	// ----------- Start
	printf("\nStart Deflector\n\n");



	// ----------- Raw Socket
	printf("Create Raw Socket(Receive)\n");

	int recv_socket = socketRaw(IPPROTO_TCP, DEFLECTOR_PORT);



	// ----------- UDP
	printf("Create UDP Socket(Send)\n");

	int send_socket = socket( PF_INET, SOCK_DGRAM, 0 );

	struct sockaddr_in bypass_addr;
	memset( &bypass_addr, 0, sizeof(bypass_addr) );
	bypass_addr.sin_family		= AF_INET;
	bypass_addr.sin_port			= htons(BYPASS_PORT);
	bypass_addr.sin_addr.s_addr	= inet_addr(BYPASS_ADDR);



	// ----------- Main Loop
	printf("Enter Main Loop\n");
	while(1)
	{
		recvRaw( recv_socket, recv_packet, sizeof(recv_packet) );
		
		tcp_header = (struct tcphdr *) (recv_packet + ip_header->ihl * 4);

		if ( ntohs( tcp_header->dest ) == DEFLECTOR_PORT )
		{

			tcp_header = (struct tcphdr *) (recv_packet + ip_header->ihl * 4);

			tcp_header->check = 0;
			tcp_header->check = tcp_checksum(ip_header, tcp_header);

			ip_header->check = 0;
			ip_header->check = checksum2((unsigned short*)ip_header, sizeof(struct iphdr));

			// ----------- Receive Packet
			printf("\nReceive Packet\n");

			#ifdef DEBUG_DEFLECTOR
				printf("----------------------------------------\n");
				
				printf( "[ 패킷을 받았습니다. ]\n" );
				printf( "발신자 IP : %s\n", inet_ntoa( * (struct in_addr*) &ip_header->saddr) );
				printf( "발신자 Port : %5u\n", ntohs(tcp_header->source) );
				printf( "수신자 IP : %s\n", inet_ntoa( * (struct in_addr*) &ip_header->daddr) );
				printf( "수신자 Port : %5u\n", ntohs(tcp_header->dest) );
				printf( "IP packet size : %d\n", ntohs(ip_header->tot_len));
				printf( "IP check : %d\n", ip_header->check );
				printf( "IP Version : %d\n", ip_header->version ); // IP 버전 정보 출력
				printf( "Time To Live : %d\n", ip_header->ttl );  // TTL 정보 출력
				printf( "TCP check : %d\n", tcp_header->check );
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

			// ----------- Send UDP Packet
			printf("Send UDP Packet\n");

			sendto( send_socket, (void *) &recv_packet, sizeof(recv_packet)+1, 0, (struct sockaddr *) &bypass_addr, sizeof(bypass_addr) );
		}
	}
}