#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

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
	uint8_t data_offset; // 4 bits
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

// 
char *Proto[] = {
	"Reserved","ICMP","IGMP","GGP", "IP","ST","TCP"
};
// 17 = "UDP"
char *str_flags[] = { "[]", "[FIN]", "[SYN]", "[SYN, FIN]", "[RST]", "[RST, FIN]", "[RST, SYN]",
					 "[RST, SYN, FIN]", "[PSH]", "[PSH, FIN]", "[PSH, SYN]",  "[PSH, SYN, FIN]",
					 "[PSH, RST]", "[PSH, RST, FIN]", "[PSH, RST, SYN]", "[PSH, RST, SYN, FIN]", 
					 "[ACK]", "[ACK, FIN]", "[ACK, SYN]", "[ACK, SYN, FIN]", "[ACK, RST]", 
					 "[ACK, RST, FIN]", "[ACK, RST, SYN]", "[ACK, RST, SYN, FIN]", "[ACK, PSH]", 
					 "[ACK, PSH, FIN]", "[ACK, PSH, SYN]", "[ACK, PSH, SYN, FIN]", 
					 "[ACK, PSH, RST]", "[ACK, PSH, RST, FIN]", "[ACK, PSH, RST, SYN]",
					 "[ACK, PSH, RST, SYN, FIN]" };

void pcap_handle(u_char *user, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	static struct timeval last_ts;
	struct timeval now_ts;
	ETHHEADER *eth_header = (ETHHEADER *)pkt_data;

	printf("Packet length: %d \n", header->len);
	
	if(header->len>=14 + 4) { // ether_header_len + ether_tailer_len
        IPHEADER *ip_header=(IPHEADER*)(pkt_data+14);
        //解析协议类型
        if(ip_header->proto != 6) return;
		
		TCPHEADER *tcp_header = (TCPHEADER *)(pkt_data+14+((ip_header->ver_ihl & 0x0F)<<2));
       	
		// need to check RST?
		int syn = tcp_header->flags & SYN;
		int ack = tcp_header->flags & ACK;
		if (syn && !ack) { 
				printf("begin to connecting\n");
				last_ts.tv_sec = header->ts.tv_sec;
				last_ts.tv_usec = header->ts.tv_usec;
		}
		if (last_ts.tv_usec > header->ts.tv_usec) {
			now_ts.tv_sec = header->ts.tv_sec - last_ts.tv_sec - 1;
			now_ts.tv_usec = header->ts.tv_usec + 1000000 - last_ts.tv_usec;
		} else {
			now_ts.tv_sec = header->ts.tv_sec - last_ts.tv_sec;
			now_ts.tv_usec = header->ts.tv_usec - last_ts.tv_usec;
		}

			
		printf("%ld.%06ld : Source IP : %d.%d.%d.%d ==> ", now_ts.tv_sec, now_ts.tv_usec, ip_header->sourceIP[0], ip_header->sourceIP[1], ip_header->sourceIP[2], ip_header->sourceIP[3]);
		printf("Dest   IP : %d.%d.%d.%d\n", ip_header->destIP[0], ip_header->destIP[1], ip_header->destIP[2], ip_header->destIP[3]);
		printf("            seq %u , ack %u\n", tcp_header->seq, tcp_header->ack);
		printf("            %s\n", str_flags[tcp_header->flags & 0x1F]);
		printf("            window size: %d Bytes", tcp_header->window_size);
	


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

