#define le16_to_cpu __le16_to_cpu

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <seq.h>
#include <time.h>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <iostream>

#include "ieee80211.h"
#include "ieee80211_radiotap.h"
static int MAX_COUNT = 1000 ;

using namespace std ;

int counter = 0 ;

vector<Subdivision> Device ;  // a set of device

void trackDevice(int seq, double clk, int fingerprint, string ss , uint8_t s0 , uint8_t s1 , uint8_t s2 , uint8_t s3 ,uint8_t s4, uint8_t s5){
  counter += 1 ;
  bool find = false;
  Frame new_frame = Frame(seq,clk,fingerprint,ss ,s0 ,s1 , s2 ,s3 ,s4,s5);
  vector<Subdivision>::iterator s ;
  for(s = Device.begin() ; s!= Device.end() ;  s++)
  {
    if(fingerprint == s->fingerprint)
    {
      Frame last_frame = *((s->track).end() - 1) ;
      if(seq - last_frame.seq > 0 && seq - last_frame.seq <= maxSeqDistance && clk - last_frame.clock > 0 && clk - last_frame.clock < maxTimeDistance)
      {
        (s->track).push_back(new_frame);
        find = true ;
        break;
      }
    }
  }
  if(!find) // not find the matching device
  {
    Subdivision newS;
    newS.fingerprint = fingerprint ;
    newS.track.push_back(new_frame);
    Device.push_back(newS);
  }
}

void printFile()
{
  ofstream file("trackDevice.txt");
  vector<Subdivision>::iterator s;
  vector<Frame>::iterator f;
  for(s = Device.begin() ; s != Device.end() ; s ++)
  {
    file << (s->fingerprint) << " " << endl ;
    for(f = (s->track).begin() ; f!=(s->track).end() ; f ++)
    {
      file << "Seq: " << dec << f->seq << " Time: " << f->clock ;
      file << " Mac: " << hex << setw(2)<<f->sa[0] << "-"
      << f->sa[1] << "-" << f->sa[2] << "-" << f->sa[3] << "-" << f->sa[4] << "-" << f->sa[5] << "  SSID: " << f->ssid << endl ;
     }
  }
  file.close() ;
}

void parseProbeRequest(const u_char* fm_data, int max_offset) {
    struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *) fm_data;

    struct ieee80211_ie *ie = (struct ieee80211_ie *) mgmt->u.probe_req.variable;
    int offset = 0, is_history = 0, ssid_len = 0,ht = 0 ;
    int seq = (int)mgmt->seq_ctrl >> 4 ;
    char ssid[IEEE80211_MAX_SSID_LEN];


    while(max_offset - offset > FCS_LEN) {
        switch (ie->id){
            case WLAN_EID_SSID:
                if (ie->len > IEEE80211_MAX_SSID_LEN) return;
                ssid_len = (int)ie->len; // Convert the type of ie->len from unsigned int with 8 bits to int
                strncpy(ssid, (char *) ie->data, ssid_len);
                ssid[ssid_len] = '\0';
                break;

            case WLAN_EID_VENDOR_SPECIFIC:
                is_history = 1;
                break;
            case WLAN_EID_HT_CAPABILITY:
                  struct ieee80211_ht_cap * htcap = (struct ieee80211_ht_cap *) ie->data;
                  ht = (int)htcap->cap_info ;
                  break;

        }
        offset += ie->len + 1 + 1;
        ie = (struct ieee80211_ie *) ((uint8_t *) ie  + ie->len + 1 + 1 );
    }

    if (is_history && ssid_len != 0 && strlen(ssid) != 0) {
        // printf("History\t");
        printf("SEQ: %d " ,seq) ;
        printf("HT: %d " , ht) ;
        printf(" Source_MAC: %02X-%02X-%02X-%02X-%02X-%02X\t", mgmt->sa[0], mgmt->sa[1], mgmt->sa[2], mgmt->sa[3], mgmt->sa[4], mgmt->sa[5]);
        printf(" SSID: %-32.*s\n", ssid_len, ssid);

        double clk = (double)clock() / (double)CLOCKS_PER_SEC * 1000.0;
        if(counter != MAX_COUNT)
        {
          trackDevice(seq,clk,ht,ssid,mgmt->sa[0], mgmt->sa[1], mgmt->sa[2], mgmt->sa[3], mgmt->sa[4], mgmt->sa[5]);
        }
        else
        {
          printFile();
        }
        // printf("SSID: %s\n", ssid);
    } else {
        // printf("Not\t");
    }

    return;
}


// Callback
void pcap_handle(u_char *user,const struct pcap_pkthdr *pkt_header,const u_char *pkt_data)
{
    struct ieee80211_radiotap_header *rt_header = (struct ieee80211_radiotap_header *) pkt_data;
    int rt_len = le16_to_cpu(rt_header->it_len);

    if (rt_len > (int)pkt_header->caplen) {
        printf("radiotap length exceeds package caplen");
        exit(EXIT_FAILURE);
    }

    struct ieee80211_hdr *hdr = (struct ieee80211_hdr *) (pkt_data + rt_len);

    if (1 == ieee80211_is_probe_req(hdr->frame_control) && counter <= MAX_COUNT){
        parseProbeRequest(pkt_data + rt_len, (int)(pkt_header->caplen - rt_len));
    }
    else if(counter > MAX_COUNT)
    {
      return ;
    }
}

int main(int argc, char **argv)
{
    cout << CLOCKS_PER_SEC << endl;
    char device[] = "wlp2s0";  //device name
    char errbuf[1024];
    pcap_t *phandle;
    phandle = pcap_open_live(device, 65535, 1, 0, errbuf);

    if(phandle==NULL){
        perror(errbuf);
        exit(EXIT_FAILURE);
    }
    pcap_loop(phandle, -1 , pcap_handle, (u_char *) "error");

    return 0;
}
