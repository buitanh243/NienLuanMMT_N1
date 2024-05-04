#ifndef PACKET_ANALYSIS_H
#define PACKET_ANALYSIS_H

#include <pcap.h>

/**
 * Analyze and log the packet.
 *
 * @param header Packet header information.
 * @param packet Packet data.
 */
void AnalyzePacket(const struct pcap_pkthdr *header, const unsigned char *packet);


/**
 * Analyze UDP packets for UDP Flood attack pattern.
 *
 * @param header Packet header information.
 * @param packet Packet data.
 */
void AnalyzeUdpAttack(const struct pcap_pkthdr *header, const unsigned char *packet);

#endif // PACKET_ANALYSIS_H
