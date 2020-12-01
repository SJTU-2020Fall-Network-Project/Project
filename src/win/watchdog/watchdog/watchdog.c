#include <stdlib.h>
#include <stdio.h>
#include <WinSock2.h>
#include <pcap.h>
#include "utils.h"

int select_device_by_name(char *, char *);
/* select_packet
*		sender -> receiver
*/



void select_packet_reno(struct timeval *now_ts, int len, uint32_t seq, uint32_t ack, uint16_t rwnd, int flag) {
	static uint32_t last_seq = 0; // the newest packet already seen
	static uint32_t ack_seq = 0; // the newest ack
	static uint32_t phase_start_seq = 0;
	static uint32_t flight_size = 0;
	static int fal_num = 0;
	static int dupack_num = 0;
	static int ssthresh = 65536;
	int MSS = 1460;
	int cwnd = 10;
	
	/* forecast RTT */
	/* I think no need to do */
	static int state_RTT = 2; /* 0 is DEFAULT; 1 is FROZEN; 2 is INIT */
	static uint32_t sample_RTT_seq = 0; // the first seq in next RTT
	static uint32_t start_RTT_seq = 0;
	static struct timeval start_RTT_ts = 0;
	
	if (flag) {
		// the packet is from sender to receiver.
		// Assume TSO is closed, each packet's len <= MSS
		if (len < MSS) return; // not data packet
		if (seq < ack_seq) return;	// already ack'd
		// validate packet
		// init phase_start_seq
		if (phase_start_seq == 0)
			phase_start_seq = seq;
		// 
		if (seq > last_seq) { last_seq = seq; return; }
		if (seq == last_seq && dupack_num > 3) {
			// Reransmission
			// 1. calculate new ocwnd (cwnd before it deflates)
			int acked = (ack_seq - phase_start_seq) / MSS; /* the number of packets acked */
			
			/* slow-start phase */
			int new_cwnd = min(cwnd + acked, ssthresh); 
			cwnd = new_cwnd;

			/* congestion avoidance phase */
			acked -= new_cwnd - cwnd;
			while (acked > cwnd) {
				acked -= cwnd;
				++cwnd;
			}
			// 2. calculate flightsize
			int flightsize = last_seq - ack_seq + 1;
			
			if (flightsize > cwnd)
				++fal_num;

			// 3. decrease cwnd
			cwnd = cwnd / 2;
			ssthresh = cwnd;
		}
		
		/* Decision process for the classification of out-of-sequence packets
		*              +---------------------+
		*              |packet already ack'd?|
		*              +---------------------+
		*                         |  yes
		*                         |-------> Unneeded Retransmission
		*                       no|
		*                         v
		*              +---------------------+
		*              | packet already seen |
		*              +---------------------+
		*                         |        +----------------------+
		*                         |   no   |   Time lag > RTO ?   |  no   +------------------+  no
		*                         |------->|         OR           |------>| Time lag < RTT ? |------> unknown
		*                         |        | Duplicate acks > 3 ? |       +------------------+
		*                      yes|        +----------------------+                |  yes
		*                         |                   |                            +-------> Reordering
		*                         v                   |yes
		*              +----------------------+       |
		*              |  IP ID different ?   |       |
		*              |          OR          | yes   v
		*              |   Time lag > RTO ?   |-----> Retransmission
		*              |          OR          |
		*              | Duplicate acks > 3 ? |
		*              +----------------------+
		*                         | no
		*                         +----> Network Duplicate
		*  Because of the monitor standing on receiver
		*   (If packet has already seen, ack for it also has been sent), 
		*  we only need to care
		*              +---------------------+
		*              |packet already ack'd?|
		*              +---------------------+
		*                         |  yes
		*                         |-------> Unneeded Retransmission
		*                       no|
		*                         v
		*              +----------------------+
		*              |   Time lag > RTO ?   | yes
		*              |          OR          |-----> Retransmission
		*              | Duplicate acts > 3 ? |
		*              +----------------------+
		*                         | no
		*                         +----> Otherwise
		*/
	}
	else {
		if (ack_seq > ack) return; // dup packet, just ignore
		if (ack_seq == ack /* && */) { ++dupack_num; return; }
		else {
			if (dupack_num > 3) {
				phase_start_seq = ack;
			}
			dupack_num = 0;
		}
		// new ack
		

		ack_seq = ack;

	}

}



void pcap_handle(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	static struct timeval start_ts;
	static int ofd = -1;
	static char of_name[50];
	static uint32_t yf_seq, sv_seq; // yifan's seq, server's seq
	static uint8_t yf_scale = 0, sv_scale = 0; // yifan's window scale, server's window scale
	static uint16_t yf_mss = 1460, sv_mss = 1460;

	char of_buf[100];
	struct timeval now_ts;
	const unsigned long interval_usec = 2000; // 2ms
	ETHHEADER *eth_header = (ETHHEADER *)pkt_data;

	printf("Packet length: %d \n", header->len);

	if (header->len >= 14 + 4) { // ether_header_len + ether_tailer_len
		IPHEADER *ip_header = (IPHEADER*)(pkt_data + 14);
		//解析协议类型
		if (ip_header->proto != 6) return;

		TCPHEADER *tcp_header = (TCPHEADER *)(pkt_data + 14 + ((ip_header->ver_ihl & 0x0F) << 2));
		int data_len = ntohs(ip_header->total_len) - ((ip_header->ver_ihl & 0xF) << 2) - (tcp_header->data_offset >> 2);
		int is_from_sender = cmp_ip(ip_header->sourceIP);
		// need to check RST? No!
		int syn = tcp_header->flags & SYN;
		int ack = tcp_header->flags & ACK;
		if (syn && !ack) {
			printf("begin to connecting\n");
			start_ts.tv_sec = header->ts.tv_sec;
			start_ts.tv_usec = header->ts.tv_usec;
			if (is_from_sender)
				sv_seq = ntohl(tcp_header->seq);
			else
				yf_seq = ntohl(tcp_header->seq);

			if (ofd != -1) _close(ofd);
			sprintf(of_name, "output_%4lx", header->ts.tv_usec & 0xFFFF);
			ofd = _open(of_name, O_WRONLY | O_CREAT, 0777);
		}
		else if (syn && ack) {
			if (cmp_ip(ip_header->sourceIP))
				sv_seq = ntohl(tcp_header->seq);
			else
				yf_seq = ntohl(tcp_header->seq);
		}

		if (start_ts.tv_usec > header->ts.tv_usec) {
			now_ts.tv_sec = header->ts.tv_sec - start_ts.tv_sec - 1;
			now_ts.tv_usec = header->ts.tv_usec + 1000000 - start_ts.tv_usec;
		}
		else {
			now_ts.tv_sec = header->ts.tv_sec - start_ts.tv_sec;
			now_ts.tv_usec = header->ts.tv_usec - start_ts.tv_usec;
		}

		if (is_from_sender) {
			tcp_header->seq = ntohl(tcp_header->seq) - sv_seq;
			tcp_header->ack = ntohl(tcp_header->ack) - yf_seq;
		}
		else {
			tcp_header->seq = ntohl(tcp_header->seq) - yf_seq;
			tcp_header->ack = ntohl(tcp_header->ack) - sv_seq;
		}


		//printf("%ld.%06ld : Source IP : %d.%d.%d.%d ==> ", now_ts.tv_sec, now_ts.tv_usec, ip_header->sourceIP[0], ip_header->sourceIP[1], ip_header->sourceIP[2], ip_header->sourceIP[3]);
		//printf("Dest   IP : %d.%d.%d.%d\n", ip_header->destIP[0], ip_header->destIP[1], ip_header->destIP[2], ip_header->destIP[3]);
		//printf("            seq %u , ack %u\n", tcp_header->seq, tcp_header->ack);
		//printf("            %s\n", str_flags[tcp_header->flags & 0x1F]);
		//printf("            window size: %d Bytes", tcp_header->window_size);
		
		
		{
			int header_length = (tcp_header->data_offset & 0xF0) >> 2;
			uint8_t *opt = (uint8_t *)tcp_header + 20;
			printf("            header length : %d Bytes", header_length);
			header_length -= 20;
			while (header_length > 0) {
				TCPOPTION *opt_ = (TCPOPTION *)opt;
				if (opt_->kind == 0) break;
				if (opt_->kind == 1) { header_length -= 1; ++opt; continue;}
				switch (opt_->kind) {
				case 2:
					if (is_from_sender)
						sv_mss = ntohs(*(uint16_t *)(opt + 2));
					else
						yf_mss = ntohs(*(uint16_t *)(opt + 2));
					break;
				case 3:
					if (is_from_sender)
						sv_scale = *(opt + 2);
					else
						yf_scale = *(opt + 2);
					break;
				
				}
				
				header_length -= opt_->size;
				opt = opt + opt_->size;


			}

		}
		if (is_from_sender)
			select_packet_reno(&now_ts, data_len, tcp_header->seq, tcp_header->ack, ntohs(tcp_header->window_size) << sv_scale, 1);
		else
			select_packet_reno(&now_ts, data_len, tcp_header->seq, tcp_header->ack, ntohs(tcp_header->window_size) << yf_scale, 0);
		
		sprintf(of_buf, "%d,%ld.%06ld,%d.%d.%d.%d,%d.%d.%d.%d,%u,%u,%s,%d,%d\n", data_len,
			now_ts.tv_sec, now_ts.tv_usec, ip_header->sourceIP[0], ip_header->sourceIP[1],
			ip_header->sourceIP[2], ip_header->sourceIP[3], ip_header->destIP[0],
			ip_header->destIP[1], ip_header->destIP[2], ip_header->destIP[3],
			tcp_header->seq, tcp_header->ack, str_flags[tcp_header->flags & 0x1F],
			ntohs(tcp_header->window_size), is_from_sender? sv_mss:yf_mss);
		if (ofd != -1)
			_write(ofd, of_buf, strlen(of_buf));
		
	}

	printf("\n\n");
}



int main(int argc, char **argv) {
	char device[DEV_NAME_LEN];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *phandle;
	struct bpf_program fcode;

	int r = select_device_by_name(device, errbuf);
	if (r == -1) {
		perror(errbuf);
		return 1;
	}

	phandle = pcap_open(device, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
	if (phandle == NULL) {
		perror(errbuf);
		return 1;
	}

	pcap_compile(phandle, &fcode, "src host 47.100.45.27 or dst host 47.100.45.27", 1, 0);
	pcap_setfilter(phandle, &fcode);

	pcap_loop(phandle, -1, pcap_handle, NULL);

	return 0;

}

char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
int select_device_by_name(char *dev_name, char *errbuf) {
	pcap_if_t *it;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &it, errbuf) == -1)
		return -1;

	strcpy(dev_name, it->name);

	{
		const pcap_if_t *tmp = it;
		const pcap_addr_t *a = NULL;
		char ip6str[128];
		while (tmp) {
			printf(":%s\n", tmp->name);
			if (tmp->description)
				printf("\tDescription: (%s)\n", tmp->description);
			else
				printf("\tDescription: (No description available)\n");
			
			for (a = tmp->addresses; a; a = a->next) {
				printf("\tAddress Family: #%d\n", a->addr->sa_family);
				switch (a->addr->sa_family) {
				case AF_INET:
					printf("\tAddress Family Name: AF_INET\n");
					if (a->addr)
						printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
					if (a->netmask)
						printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
					if (a->broadaddr)
						printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
					if (a->dstaddr)
						printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
					break;

				case AF_INET6:
					printf("\tAddress Family Name: AF_INET6\n");
					if (a->addr)
						printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
					break;

				default:
					printf("\tAddress Family Name: Unknown\n");
					break;
				}
			}
			
			tmp = tmp->next;
		}
	}

	pcap_freealldevs(it);
	printf("select a device to watch([%s] default):", dev_name);

	{
		char c = getchar();
		int i = 0;
		while (c != '\n' /* only on linux*/ && i != DEV_NAME_LEN - 1) {
			dev_name[i++] = c;
			c = getchar();
		}
		if (i != 0) dev_name[i] = 0;
	}

	printf("you select device: [%s]\n", dev_name);
	return 0;
}

#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}
