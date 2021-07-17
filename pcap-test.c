#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test eth0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

typedef struct{
	u_int8_t byte1;
	u_int8_t byte2;
	u_int8_t byte3;
	u_int8_t byte4;
	u_int8_t byte5;
	u_int8_t byte6;
}Mac;

typedef struct{
	u_int8_t byte1;
	u_int8_t byte2;
	u_int8_t byte3;
	u_int8_t byte4;
}Ipv4;

typedef struct{
	Mac destination;
	Mac source;
	u_int8_t type[2];
}Ethernet;

typedef struct{
	u_int8_t version;
	u_int8_t tos;
	u_int16_t length;
	u_int16_t identification;
	u_int16_t flags_offset;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t checksum;
	Ipv4 source;
	Ipv4 destination;
}Ip;

typedef struct{
	u_int16_t source;
	u_int16_t destination;
	u_int32_t seq_num;
	u_int32_t ack_num;
	u_int8_t length;
	u_int8_t flags;
	u_int16_t window;
	u_int16_t checksum;
	u_int16_t urgent;
}Tcp;

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void macPrint(Mac *mac){
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac->byte1, mac->byte2, mac->byte3, mac->byte4, mac->byte5, mac->byte6);
}

void ipPrint(Ipv4 *ip){
	printf("%d.%d.%d.%d\n", ip->byte1, ip->byte2, ip->byte3, ip->byte4);
}

void analysis(const u_char* packet, int paclen){
	Ethernet* eth = (Ethernet*)(packet);
	Ip* ip = (Ip*)(packet+sizeof(Ethernet));
	Tcp* tcp = (Tcp*)(packet+sizeof(Ethernet)+sizeof(Ip));

	if (ip->protocol != 0x06){
		return ;
	}
	printf("%u bytes captured\n", paclen);

	printf("====================================\n");
	printf("Source Mac: ");
	macPrint(&(eth->source));

	printf("Destination Mac: ");
	macPrint(&(eth->destination));

	printf("Source IP: ");
	ipPrint(&(ip->source));

	printf("Destination IP: ");
	ipPrint(&(ip->destination));

	printf("Source Port: ");
	printf("%d\n", htons(tcp->source));

	printf("Destination Port: ");
	printf("%d\n", htons(tcp->destination));

	int tcp_header_size = (tcp->length >> 4) *4;

	int size = sizeof(Ethernet)+sizeof(Ip)+tcp_header_size;
	u_int8_t * payload = (u_int8_t*)(packet+size);
	
	printf("payload : ");

	int max = paclen - size > 8 ? 8 : paclen - size;
	for (int i=0; i< max ; i++){
		printf("%02x ", payload[i]);
	}
	printf("\n\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		analysis(packet, header->caplen);
	}
	pcap_close(pcap);
}
