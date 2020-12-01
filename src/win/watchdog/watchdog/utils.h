#pragma once
#include <stdint.h>

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

int cmp_ip(char ip[4]) {
	static char sv_ip[4] = { 47, 100, 45, 27 };
	if ((ip[0] == sv_ip[0]) && (ip[1] == sv_ip[1]) && (ip[2] == sv_ip[2]) && (ip[3] == sv_ip[3]))
		return 1;
	return 0;
}
