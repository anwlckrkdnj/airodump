#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "mac.h"
#include "airoutil.h"

#define MAXBEACONCNT 256
#define MAXPROBECNT 256
#define MAXNAMELENGTH 64

static pcap_t* handle;

struct beacon {
	Mac bea_bssid;
	int bea_beacons;
	char bea_essid[MAXNAMELENGTH];
};

struct probe {
	Mac prb_bssid;
	Mac prb_station;
	int prb_frames;
	char prb_probe[MAXNAMELENGTH];
};


struct beacon beacon_list[MAXBEACONCNT];
struct probe probe_list[MAXPROBECNT];

void usage() {
	printf("> wrong format!\n");
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
}

bool checkFormat(int argc, char* argv[]) {
	printf("checking input format...\n");
	if (argc != 2)
		return false;
	printf("> done!\n\n");
	return true;
}

void printMac(Mac mac) {
	uint8_t a[6];
	memcpy(a, &mac, sizeof(Mac));
	for(int i = 0 ; i < 6 ; i++) {
		printf("%02x", a[i]);
		if(i < 5)
			printf(":");
	}
}

bool checkFrameList2(Mac packet_bssid, Mac packet_station, int probe_cnt) {
	for(int i = 0 ; i < probe_cnt ; i++) {
		if(packet_station == probe_list[i].prb_station) {
			if(packet_bssid == probe_list[i].prb_bssid) {
				probe_list[i].prb_frames++;
				return true;
			}
		}
	}
	return false;
}

bool checkFrameList1(Mac packet_station, int probe_cnt) {
	for(int i = 0 ; i < probe_cnt ; i++) {
		if(packet_station == probe_list[i].prb_station) {
			probe_list[i].prb_frames++;
			return true;	// duplicate
		}
	}
	return false;			// new
}

bool checkBeaconList(Mac packet_bssid, int beacon_cnt) {
	for(int i = 0; i < beacon_cnt ; i++) {
		if(packet_bssid == beacon_list[i].bea_bssid) {
			beacon_list[i].bea_beacons++;
			return true;	// duplicate
		}
	}
	return false;			// new
}

void printResult(int beacon_total, int beacon_cnt, int probe_total, int probe_cnt) {
	system("clear");
	printf("beacon : %d\n", beacon_total);
	printf("bssid - beacons - essid\n");
	for(int i = 0 ; i < beacon_cnt ; i++) {
		printMac(beacon_list[i].bea_bssid);
		printf(" %d", beacon_list[i].bea_beacons);
		printf(" %s\n", beacon_list[i].bea_essid);
	}
	printf("probe : %d\n", probe_total);
	printf("bssid - station - frames - probe\n");
	for(int i = 0; i < probe_cnt ; i++) {
		if(probe_list[i].prb_bssid == Mac("00:00:00:00:00:00"))
			printf("(not associated)");
		else
			printMac(probe_list[i].prb_bssid);
		printf(" ");
		printMac(probe_list[i].prb_station);
		printf(" %d", probe_list[i].prb_frames);
		printf(" %s\n", probe_list[i].prb_probe);
	}
}

int main(int argc, char* argv[]) {
	if (checkFormat(argc, argv) == false) {
		usage();
		return -1;
	}

	int beacon_total = 0;	// beacon total number
	int probe_total = 0;	// probe total number
	int beacon_cnt = 0;	// beacon list count
	int probe_cnt = 0;	// probe list count

	struct radiotap_hdr* rad_hdr;
	struct beacon_frame* bea_frm; 

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	struct pcap_pkthdr* header;
	const u_char* packet;
	u_char* relayPacket;
	int res;
	while (true) {
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		rad_hdr = (struct radiotap_hdr*) packet;
		packet += rad_hdr->radhdr_len;
		bea_frm = (struct beacon_frame*) packet;
		packet += 24;

		if(bea_frm->beafrm_type == 0x80) {
			beacon_total++;
			if(checkBeaconList(bea_frm->beafrm_bss, beacon_cnt) == false) {
				beacon_list[beacon_cnt].bea_bssid = bea_frm->beafrm_bss;
				beacon_list[beacon_cnt].bea_beacons = 1;
				memcpy(beacon_list[beacon_cnt].bea_essid, packet + 14, *(uint8_t*)(packet + 13));
				beacon_cnt++;
			}
			printResult(beacon_total, beacon_cnt, probe_total, probe_cnt);
		}

		else if(bea_frm->beafrm_type == 0x40) {
			probe_total++;
			if(checkFrameList1(bea_frm->beafrm_src, probe_cnt) == false) {
				probe_list[probe_cnt].prb_station = bea_frm->beafrm_src;
				probe_list[probe_cnt].prb_frames = 1;
				memcpy(probe_list[probe_cnt].prb_probe, packet + 2, *(uint8_t*)(packet + 1));
				probe_cnt++;
			}
			printResult(beacon_total, beacon_cnt, probe_total, probe_cnt);
		}	

		else if(bea_frm->beafrm_type == 0x48) {
			probe_total++;
			if(checkFrameList2(bea_frm->beafrm_rcv, bea_frm->beafrm_src, probe_cnt) == false) {
				probe_list[probe_cnt].prb_station = bea_frm->beafrm_src;
				probe_list[probe_cnt].prb_bssid = bea_frm->beafrm_rcv;
 	                        probe_list[probe_cnt].prb_frames = 1;
				probe_cnt++;
                        }
			printResult(beacon_total, beacon_cnt, probe_total, probe_cnt);
		}
	}

	return 0;
}
