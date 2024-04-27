#include "packet_analysis.h"
#include "attack_detection.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <netinet/ip_icmp.h>



// Log packet details
void LogPacket(const char *protocol, const char *info) {
  printf("%s Packet: %s\n", protocol, info);
}

// Analyze TCP packets for specific attack patterns
void AnalyzeTcpPacket(const struct pcap_pkthdr *header, const unsigned char *packet) {
  struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
  char info[100];
  snprintf(info, sizeof(info), "Source Port: %d, Dest Port: %d", ntohs(tcp_header->source), ntohs(tcp_header->dest));
  LogPacket("TCP", info);
  AnalyzeTcpAttack(header, packet); // Function for attack analysis
}

// Analyze UDP packets for specific attack patterns
void AnalyzeUdpPacket(const struct pcap_pkthdr *header, const unsigned char *packet) {
  struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
  char info[100];
  snprintf(info, sizeof(info), "Source Port: %d, Dest Port: %d", ntohs(udp_header->source), ntohs(udp_header->dest));
  LogPacket("UDP", info);
  AnalyzeUdpAttack(header, packet); // Function for attack analysis
}

void AnalyzeIcmpPacket(const struct pcap_pkthdr *header, const unsigned char *packet) {
  struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
  struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);

  // Log ICMP packet details
  char info[100];
  snprintf(info, sizeof(info), "Type: %d, Code: %d", icmp_header->icmp_type, icmp_header->icmp_code);
  LogPacket("ICMP", info);
  //AnalyzeIcmpAttack(header, packet)

}

void AnalyzePacket(const struct pcap_pkthdr *header, const unsigned char *packet) {
  struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));

  // Determine the protocol and analyze accordingly
  switch (ip_header->ip_p) {
    case IPPROTO_TCP:
      AnalyzeTcpPacket(header, packet);
      break;
    case IPPROTO_UDP:
      AnalyzeUdpPacket(header, packet);
      break;
    case IPPROTO_ICMP:
      AnalyzeIcmpPacket(header, packet); 
      break;
    default:
      // Unsupported protocol
      break;
  }
}
