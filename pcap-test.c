#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


void ethernet_header(struct libnet_ethernet_hdr* eth_hdr) {
	int idx = 0;
	while (idx < ETHER_ADDR_LEN){

	}
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
		
		struct libnet_ethernet_hdr *eth_hdr;
		struct libnet_ipv4_hdr *ip_hdr;
		struct libnet_tcp_hdr *tcp_hdr;

		if(packet[0x17] == 0x06) { // If TCP
			printf("########## TCP PACKET ##########\n");
			printf("%u bytes captured\n", header->caplen);
			// Ethernet Header Parsing
			eth_hdr = (struct libnet_ethernet_hdr *)packet;

			printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
			            eth_hdr->ether_shost[0], eth_hdr->ether_shost[1],
		        	    eth_hdr->ether_shost[2], eth_hdr->ether_shost[3],
			            eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

			printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                    eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1],
                                    eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3],
                                    eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);

			// IP Header Parsing
			ip_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(*eth_hdr));
			
			printf("Source IP: %s\n", inet_ntoa(ip_hdr->ip_src));
			printf("Destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
			

			// TCP Header Parsing
			tcp_hdr = (struct libnet_tcp_hdr *)(packet + sizeof(*eth_hdr) + sizeof(*ip_hdr));

			printf("Source port: %d\n", ntohs(tcp_hdr->th_sport));
			printf("Destination port: %d\n", ntohs(tcp_hdr->th_dport));

			// Payload
			int payload_offset = sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(*tcp_hdr);
			int payload_end;

			if(header->caplen - payload_offset < 20){
				payload_end = header->caplen;
			} else {
				payload_end = payload_offset + 20;
			}

			printf("payload: ");
			for(int idx = payload_offset; idx < payload_end; idx++) {
				printf("%02x ", packet[idx]);
			}
			
			printf("\n\n");
		}

	}

	pcap_close(pcap);
}
