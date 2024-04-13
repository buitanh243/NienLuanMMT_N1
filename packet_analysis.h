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

#endif // PACKET_ANALYSIS_H
