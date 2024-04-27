#include "packet_capture.h"
#include "packet_analysis.h"
#include <stdio.h>



// Callback function to analyze packets
// void PacketCallback(const struct pcap_pkthdr *header, const u_char *packet) {
//   AnalyzePacket(header, packet);
// }

void PacketCallback(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
  AnalyzePacket(header, packet);
}



int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <device>\n", argv[0]);
    return 1;
  }

  // Initialize packet capture
  pcap_t *handle = InitPacketCapture(argv[1]);
  if (handle == NULL) {
    return 2;
  }

  // Start capturing packets
  StartCapture(handle, PacketCallback);
  
  pcap_breakloop(handle);
  pcap_close(handle);
  return 0;
}
