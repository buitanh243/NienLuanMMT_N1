#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <pcap.h>

/**
 * Initialize packet capture on the specified device.
 *
 * @param device Name of the device for packet capture.
 * @return A pcap_t handle for packet capture.
 */
pcap_t *InitPacketCapture(const char *device);

/**
 * Start capturing packets on the specified pcap_t handle.
 *
 * @param handle Pcap handle for packet capture.
 * @param callback Callback function for packet analysis.
 */
void StartCapture(pcap_t *handle, pcap_handler callback);

#endif // PACKET_CAPTURE_H
