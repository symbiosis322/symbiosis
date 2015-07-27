/* 
-
	Common.h

	2015. 06. 24
-
*/

// Header
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>


// Define
#define PROTOCOL		1 // TCP : 0, UDP : 1


#define SYMBIOSIS_PORT	27000

#define BEE_PORT		SYMBIOSIS_PORT + 1

#define FLOWER_PORT		SYMBIOSIS_PORT + 2

#define DEFLECTOR_PORT	SYMBIOSIS_PORT + 4

#define BYPASS_ADDR		"155.98.39.83"
#define BYPASS_PORT		SYMBIOSIS_PORT + 5

#define SERVER_PORT		SYMBIOSIS_PORT + 3



// Cell: ( Type:1, Length:2, StreamID:2, Digest:32, Data:987 )
#define SYMBIOSIS_CELL_TYPE_REQUEST		0
#define SYMBIOSIS_CELL_TYPE_RESPONSE	1

#define BUFF_SIZE		1024




// Structure
struct pseudo_header
{
  __u32 src_addr;
  __u32 dst_addr;
  __u8 zero;
  __u8 proto;
  __u16 length;
};



// Function

// Raw Socket
int socketRaw(int type, unsigned short port)
{
	// type: IPPROTO_TCP | IPPROTO_UDP
	// port: uint16_t

	// ----------- Raw Socket
	int sockfd = socket( PF_INET, SOCK_RAW, type );

	if( sockfd == -1 ) {
		perror("socket");
		exit(1);
	}

	// ----------- Bind
	struct sockaddr_in raw_address;

	memset( &raw_address, 0, sizeof(raw_address) );
	raw_address.sin_port = htons(port);

	if( bind( sockfd, (struct sockaddr *) &raw_address, sizeof(raw_address) ) < 0 ) 
	{
		perror("bind");
		exit(1);
	}

	// ----------- Set Socket Option
	int on = 1;

	if( setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on) ) < 0 )
	{
		perror("setsockopt");
		exit(1);
	}

	return sockfd;
}

// recvTCPRaw
int recvRaw(int raw_fd, char* recv_packet, int len)
{
	memset(recv_packet, 0, len);

	return recv( raw_fd, recv_packet, len, 0 );
}

// sendUDPRaw
int sendRaw()
{
	return 0;
}

// TCP Socket
int socketTCP(char * ip, unsigned short port, struct sockaddr_in * tcp_addr)
{
	// ----------- TCP Socket
	int sockfd = socket(PF_INET, SOCK_STREAM, 0);

	if( sockfd == -1 )
	{
		perror("socket");
		exit(1);
	}

	if(tcp_addr == 0) return sockfd;

	memset( tcp_addr, 0, sizeof(struct sockaddr_in) );
	tcp_addr->sin_family		= AF_INET;
	tcp_addr->sin_port			= htons(port);
	tcp_addr->sin_addr.s_addr	= inet_addr(ip);

	if(ip == 0)
	{
		// ----------- Bind
		if( bind( sockfd, (struct sockaddr *) tcp_addr, sizeof(struct sockaddr_in) ) < 0 )
		{
			perror("bind");
			exit(1);
		}
	}
	else
	{
		// ----------- Connect
		if( connect( sockfd, (struct sockaddr *) tcp_addr, sizeof(struct sockaddr_in) ) < 0 )
		{
			perror("connect");
			exit(1);
		}
	}

	return sockfd;
}

int sendTCP()
{
	return 0;
}

int recvTCP()
{
	return 0;
}


// UDP Socket
int socketUDP(unsigned short port, struct sockaddr_in * udp_addr)
{
	// ----------- UDP Socket
	int sockfd = socket(PF_INET, SOCK_DGRAM, 0);

	if( sockfd == -1 )
	{
		perror("socket");
		exit(1);
	}

	if( port == -1 || udp_addr == 0) return sockfd;

	// ----------- Bind
	memset( udp_addr, 0, sizeof(struct sockaddr_in) );
	udp_addr->sin_family		= AF_INET;
	udp_addr->sin_port			= htons(port);
	udp_addr->sin_addr.s_addr	= htonl(INADDR_ANY);

	if( bind( sockfd, (struct sockaddr*) udp_addr, sizeof(struct sockaddr_in) ) < 0 )
	{
		perror("bind");
		exit(1);
	}

	return sockfd;
}

int sendUDP(int sockfd, char * buffer, int len, struct sockaddr_in * udp_addr)
{
	return sendto( sockfd, &buffer, len, 0, (struct sockaddr *) &udp_addr, sizeof(udp_addr) );
}

int recvUDP(int sockfd, char* recv_packet, int len, struct sockaddr_in * udp_addr)
{
	int udp_len = sizeof(struct sockaddr_in);

	memset(recv_packet, 0, len);

	return recvfrom( sockfd, recv_packet, len, 0, (struct sockaddr *)udp_addr, &udp_len );
}


// Checksum
long checksum2(unsigned short *addr, unsigned int count)
{
	register long sum = 0;

	while( count > 1 ) {
		sum += * addr++;
		count -= 2;
	}

	if( count > 0 )
		sum += * (unsigned char *) addr;

	while ( sum >> 16 )
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

unsigned short checksum(unsigned short * buf, int len)
{
	register unsigned long sum = 0;

	while(len--)
	    sum += *buf++;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (unsigned short)(~sum);
}


// Print Header
void printPseudoHeader(struct pseudo_header * pseudo)
{
	printf("------------Pseudo Header\n");
	printf("src_addr: %s\n", inet_ntoa( * (struct in_addr *) &pseudo->src_addr));
	printf("dst_addr: %s\n", inet_ntoa( * (struct in_addr *) &pseudo->dst_addr));
	printf("zero: %d\n", pseudo->zero);
	printf("proto: %d\n", pseudo->proto);
	printf("length:%d\n", ntohs(pseudo->length));
	printf("----------------------\n\n");
}

void printIPHeader(struct iphdr * iph)
{
	printf("------------IP Header\n");
	printf("ip header length : %d\n", iph->ihl * 4);
	printf("total length: %d\n", ntohs(iph->tot_len));
	printf("source: \t%s\n", inet_ntoa( * (struct in_addr*) &iph->saddr));
	printf("dest: \t\t%s\n", inet_ntoa( * (struct in_addr*) &iph->daddr));
	printf("check: %d\n", iph->check);
	printf("----------------------\n\n");
}

void printTCPHeader(struct tcphdr * tcph)
{
	printf("------------TCP Header\n");
	printf("tcp header length : %zu\n", sizeof(struct tcphdr));
	printf("tcp option length : %d\n", tcph->doff * 4 - 20);

	printf("source port: \t%d\n", ntohs(tcph->source));
	printf("dest port: \t%d\n", ntohs(tcph->dest));
	printf("ack_seq: \t\t%d\n", tcph->ack_seq);
	printf("doff: \t\t%d\n", tcph->doff);
	printf("res1: \t\t%d\n", tcph->res1);
	printf("cwr: \t\t%d\n", tcph->cwr);
	printf("ece: \t\t%d\n", tcph->ece);
	printf("urg: \t\t%d\n", tcph->urg);
	printf("ack: \t\t%d\n", tcph->ack);
	printf("psh: \t\t%d\n", tcph->psh);
	printf("rst: \t\t%d\n", tcph->rst);
	printf("syn: \t\t%d\n", tcph->syn);
	printf("fin: \t\t%d\n", tcph->fin);
	printf("window: \t\t%d\n", tcph->window);
	printf("check: \t\t%x\n", tcph->check);
	printf("urg_ptr: \t\t%d\n", tcph->urg_ptr);
	printf("----------------------\n\n");
}

void printUDPHeader(struct udphdr * udph)
{
	printf("------------UDP Header\n");
	printf("udp total length : %d\n", ntohs(udph->len));
	printf("source port: \t%d\n", ntohs(udph->source));
	printf("dest port: \t%d\n", ntohs(udph->dest));
	printf("check: %d\n", udph->check);
	printf("----------------------\n\n");
}


unsigned short tcp_checksum(struct iphdr * iph, struct tcphdr * tcph)
{
	int tcp_len = ntohs(iph->tot_len) - iph->ihl * 4;

	// ----------- IP Header
	printIPHeader(iph);

	// ----------- TCP Header
	printTCPHeader(tcph);

	// ----------- Pseudo Header
	struct pseudo_header pseudo;
	pseudo.src_addr = iph->saddr;
	pseudo.dst_addr = iph->daddr;
	pseudo.zero = 0;
	pseudo.proto = iph->protocol;
	pseudo.length = htons(tcp_len);

	printPseudoHeader(&pseudo);
	

	// ----------- Combine
	int temp_len = sizeof(struct pseudo_header) + tcp_len;

	unsigned short * temp = (unsigned short *) malloc(temp_len);


	// ----------- Pseudo Header
	memcpy((unsigned char *)temp, &pseudo, sizeof(struct pseudo_header));
	// ----------- TCP Header
	memcpy((unsigned char *)temp + sizeof(struct pseudo_header), (unsigned char *)tcph, tcph->doff * 4);
	// ----------- TCP Data
	memcpy((unsigned char *)temp + sizeof(struct pseudo_header) + tcph->doff * 4, (unsigned char *)tcph + (tcph->doff * 4), tcp_len - (tcph->doff * 4));


	unsigned short result = checksum(temp, temp_len / sizeof(unsigned short));

	free(temp);


	// ----------- Result
	return result;
}



unsigned short udp_checksum(struct iphdr * iph, struct udphdr * udph)
{
	int udp_len = ntohs(udph->len);
	
	// ----------- IP Header
	//printIPHeader(iph);

	// ----------- UDP Header
	//printUDPHeader(udph);

	// ----------- Pseudo Header
	struct pseudo_header pseudo;
	pseudo.src_addr = iph->saddr;
	pseudo.dst_addr = iph->daddr;
	pseudo.zero = 0;
	pseudo.proto = iph->protocol;
	pseudo.length = udph->len;

	//printPseudoHeader(&pseudo);


	// ----------- Combine
	int temp_len = sizeof(struct pseudo_header) + udp_len;

	unsigned short * temp = (unsigned short *) malloc(temp_len);


	// ----------- Pseudo Header
	memcpy((unsigned char *)temp, &pseudo, sizeof(struct pseudo_header));
	// ----------- UDP Header & Data
	memcpy((unsigned char *)temp + sizeof(struct pseudo_header), (unsigned char *)udph, udp_len);


	unsigned short result = checksum2(temp, temp_len);

	free(temp);


	// ----------- Result
	return result;
}