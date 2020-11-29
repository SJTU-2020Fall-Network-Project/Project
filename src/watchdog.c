#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define DEV_NAME_LEN 20

// Link layer
typedef struct {
	u_char dest_mac[6];
	u_char src_mac[6];
	u_char etype[2];
}ETHHEADER;

// IP layer
typedef struct {
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t total_len;
	uint16_t ident;
	uint16_t flags;
	uint8_t ttl;
	uint8_t proto;
	uint16_t checksum;
	u_char sourceIP[4];
	u_char destIP[4];
}IPHEADER;

// TCP layer
typedef struct {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t data_offset; // 4 bits ; pos = data_offset * 4 bytes
	uint8_t flags;
#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20
#define ECE 0x40
#define CWR 0x80
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_p;
}TCPHEADER;

// TCP option
typedef struct {
	uint8_t kind;
	uint8_t size;
}TCPOPTION;

// 
char *Proto[] = {
	"Reserved","ICMP","IGMP","GGP", "IP","ST","TCP"
};
// 17 = "UDP"
char *str_flags[] = {
	"[]", "[FIN]", "[SYN]", "[SYN, FIN]", "[RST]", "[RST, FIN]", "[RST, SYN]",
	"[RST, SYN, FIN]", "[PSH]", "[PSH, FIN]", "[PSH, SYN]",  "[PSH, SYN, FIN]",
	"[PSH, RST]", "[PSH, RST, FIN]", "[PSH, RST, SYN]", "[PSH, RST, SYN, FIN]", 
	"[ACK]", "[ACK, FIN]", "[ACK, SYN]", "[ACK, SYN, FIN]", "[ACK, RST]", 
	"[ACK, RST, FIN]", "[ACK, RST, SYN]", "[ACK, RST, SYN, FIN]", "[ACK, PSH]", 
	"[ACK, PSH, FIN]", "[ACK, PSH, SYN]", "[ACK, PSH, SYN, FIN]", 
	"[ACK, PSH, RST]", "[ACK, PSH, RST, FIN]", "[ACK, PSH, RST, SYN]",
	"[ACK, PSH, RST, SYN, FIN]" 
};
/* select_packet
 *		sender -> receiver
 */
void select_packet(struct timeval *now_ts, int len, uint32_t seq, uint32_t ack, uint16_t rwnd, int flag) {
	static uint32_t unack_seq = 0; // the next seq sender to send
	static uint32_t acked_seq = 0; // the next seq receiver want
	static uint32_t flight_size = 0;
	static int dupack_num = 0;
	int MSS = 1460;
	int cwnd = 10;
	if (flag) {
	// the packet is from sender to receiver.
		if (len < MSS) return;
		int num = len / MSS;
		if (num * MSS > len) ++num;
		unack_seq += seq + num * MSS;
	
		/* Decision process for the classification of out-of-sequence packets
		 *              +--------------------+
		 *              |packet alredy ack'd?|
		 *              +--------------------+
		 *                         |  yes
		 *                         |-------> Unneeded Retransmission
		 *                       no|
		 *                         v
		 *              +--------------------+
		 *              |packet already seen |
		 *              +--------------------+
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
		 */
	} else {
		if (acked_seq > ack) return; // dup packet, just ignore
		if (acked_seq == ack) ++dupack_num;
		
		acked_seq = ack;
	
	}

}

int cmp_ip(char ip[4]) {
	static char sv_ip[4] = {47, 100, 45, 27};
	if ((ip[0]==sv_ip[0]) && (ip[1]==sv_ip[1]) && (ip[2]==sv_ip[2]) && (ip[3]==sv_ip[3]))
		return 1;
	return 0;
}

void pcap_handle(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	static struct timeval start_ts;
	static struct timeval next_ts;
	static int ofd = -1;
	static char of_name[50];
	static uint32_t yf_seq, sv_seq; // yifan's seq, server's seq

	char of_buf[100];
	struct timeval now_ts;
	const unsigned long interval_usec = 2000; // 2ms
	ETHHEADER *eth_header = (ETHHEADER *)pkt_data;

	printf("Packet length: %d \n", header->len);
	
	if(header->len>=14 + 4) { // ether_header_len + ether_tailer_len
        IPHEADER *ip_header=(IPHEADER*)(pkt_data+14);
        //解析协议类型
        if(ip_header->proto != 6) return;
		
		TCPHEADER *tcp_header = (TCPHEADER *)(pkt_data+14+((ip_header->ver_ihl & 0x0F)<<2));
       	int data_len = ntohs(ip_header->total_len) - ((ip_header->ver_ihl & 0xF) << 2) - (tcp_header->data_offset >> 2);
		// need to check RST?
		int syn = tcp_header->flags & SYN;
		int ack = tcp_header->flags & ACK;
		if (syn && !ack) { 
			printf("begin to connecting\n");
			start_ts.tv_sec = header->ts.tv_sec;
			start_ts.tv_usec = header->ts.tv_usec;
			next_ts.tv_usec = 0;
			next_ts.tv_sec = 0;
			if (cmp_ip(ip_header->sourceIP)) 
				sv_seq = ntohl(tcp_header->seq);
			else 
				yf_seq = ntohl(tcp_header->seq);

			if (ofd != -1) close(ofd);
			sprintf(of_name, "output_%4lx", header->ts.tv_usec & 0xFFFF);
			ofd = open(of_name, O_WRONLY | O_CREAT, 0777);
		} else if (syn && ack) {
			if (cmp_ip(ip_header->sourceIP))
				sv_seq = ntohl(tcp_header->seq);
			else 
				yf_seq = ntohl(tcp_header->seq);
		}
		if (start_ts.tv_usec > header->ts.tv_usec) {
			now_ts.tv_sec = header->ts.tv_sec - start_ts.tv_sec - 1;
			now_ts.tv_usec = header->ts.tv_usec + 1000000 - start_ts.tv_usec;
		} else {
			now_ts.tv_sec = header->ts.tv_sec - start_ts.tv_sec;
			now_ts.tv_usec = header->ts.tv_usec - start_ts.tv_usec;
		}

		if ((now_ts.tv_sec == next_ts.tv_sec && now_ts.tv_usec > next_ts.tv_usec) || now_ts.tv_sec > next_ts.tv_sec) {
			unsigned long x = next_ts.tv_usec + interval_usec;
			next_ts.tv_usec = x % 1000000;
			next_ts.tv_sec += x / 1000000;
		}

		if (cmp_ip(ip_header->sourceIP)) {
			tcp_header->seq = ntohl(tcp_header->seq) - sv_seq;
			tcp_header->ack = ntohl(tcp_header->ack) - yf_seq;
		} else {
			tcp_header->seq = ntohl(tcp_header->seq) - yf_seq;
			tcp_header->ack = ntohl(tcp_header->ack) - sv_seq;
		}

			
		printf("%ld.%06ld : Source IP : %d.%d.%d.%d ==> ", now_ts.tv_sec, now_ts.tv_usec, ip_header->sourceIP[0], ip_header->sourceIP[1], ip_header->sourceIP[2], ip_header->sourceIP[3]);
		printf("Dest   IP : %d.%d.%d.%d\n", ip_header->destIP[0], ip_header->destIP[1], ip_header->destIP[2], ip_header->destIP[3]);
		printf("            seq %u , ack %u\n", tcp_header->seq, tcp_header->ack);
		printf("            %s\n", str_flags[tcp_header->flags & 0x1F]);
		//printf("            window size: %d Bytes", tcp_header->window_size);
		uint16_t mss = 0;
		/*
		{
			int header_length = (tcp_header->data_offsize & 0xF0) >> 2;
			uint8_t *opt = (uint8_t *)tcp_header + 20;
			printf("            header length : %d Bytes", header_length);
			header_length -= 20;
			while (header_length > 0) {
				TCPOPTION *opt_ = (TCPOPTION *)opt;
				if (opt_->kind == 0) break;
				if (opt_->kind == 1) { header_length -= 1; ++opt; continue;}
				if (opt_->kind == 2) {
					mss = ntohs((uint16_t)*(opt + 2));
					printf("            MSS: %d\n", mss);
				}

				
				

				header_length -= opt_->size;
				opt = opt + opt_->size;


			}

		}
		*/
		select_packet(&now_ts, data_len, tcp_header->seq, tcp_header->ack, ntohs(tcp_header->window_size), cmp_ip(ip_header->sourceIP));
		sprintf(of_buf, "%d,%ld.%06ld,%d.%d.%d.%d,%d.%d.%d.%d,%u,%u,%s,%d\n", data_len,
						now_ts.tv_sec, now_ts.tv_usec, ip_header->sourceIP[0], ip_header->sourceIP[1],
						ip_header->sourceIP[2], ip_header->sourceIP[3], ip_header->destIP[0],
						ip_header->destIP[1], ip_header->destIP[2], ip_header->destIP[3],
						tcp_header->seq, tcp_header->ack, str_flags[tcp_header->flags & 0x1F],
						ntohs(tcp_header->window_size));
		
		write(ofd, of_buf, strlen(of_buf));
    }

	printf("\n\n");
}

int select_device_by_name(char *dev_name, char *errbuf) {
	pcap_if_t *it;
	int r;

	r = pcap_findalldevs(&it, errbuf);
	if (r == -1) return r;

	strcpy(dev_name, it->name);

	
	{
		const pcap_if_t *tmp = it;
		while (tmp) {
			printf(":%s\n", tmp->name);
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

int main(int argc, char **argv) {
	char device[DEV_NAME_LEN];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *phandle;

	bpf_u_int32 ipaddress, ipmask;
	struct bpf_program fcode;
	int datalink;

	int r = select_device_by_name(device, errbuf);
	if (r == -1) {
		perror(errbuf);
		return 1;
	}

	phandle = pcap_open_live(device, 200, 0, 500, errbuf);
	if (phandle == NULL) {
		perror(errbuf);
		return 1;
	}
	
	if (pcap_lookupnet(device, &ipaddress, &ipmask, errbuf) == -1) {
		perror(errbuf);
		return 1;
	} else {
		char ip[INET_ADDRSTRLEN], mask[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &ipaddress, ip, sizeof(ip)) == NULL)
			perror("inet_ntop error");
		else if (inet_ntop(AF_INET, &ipmask, mask, sizeof(mask)) == NULL)
			perror("inet_ntop error");
		printf("IP address: %s, Network Mask: %s\n", ip, mask);
	}
/*
	int flag = 1;
	while (flag) {
		printf("Input packet Filter: ");
		char filterString[1024];
		scanf("%s", filterString);

		if (pcap_compile(phandle, &fcode, filterString, 0, ipmask) == -1)
			fprintf(stderr, "pcap_compile: %s, please input again....\n")
	}
*/

	pcap_compile(phandle, &fcode, "src host 47.100.45.27 or dst host 47.100.45.27", 1, 0);
	pcap_setfilter(phandle, &fcode);

	if ((datalink = pcap_datalink(phandle) == -1)) {
		fprintf(stderr, "pcap_datalink: %s\n", pcap_geterr(phandle));
		return 1;
	}

	printf("datalink = %d\n", datalink);

	pcap_loop(phandle, -1, pcap_handle, NULL);
	
	return 0;
}


