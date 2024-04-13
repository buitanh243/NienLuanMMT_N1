#ifndef ATTACK_DETECTION_H
#define ATTACK_DETECTION_H

#include <pcap.h>

/**
 * Analyze a TCP packet for specific attack patterns.
 *
 * @param header Packet header information.
 * @param packet Packet data.
 */
void AnalyzeTcpAttack(const struct pcap_pkthdr *header, const unsigned char *packet);

/**
 * Analyze a UDP packet for specific attack patterns.
 *
 * @param header Packet header information.
 * @param packet Packet data.
 */
void AnalyzeUdpAttack(const struct pcap_pkthdr *header, const unsigned char *packet);

#endif // ATTACK_DETECTION_H
