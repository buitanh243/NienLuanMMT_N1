#include "packet_capture.h"
#include <stdlib.h>

pcap_t *InitPacketCapture(const char *device) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
    return NULL;
  }
  return handle;
}

void StartCapture(pcap_t *handle, pcap_handler callback) {
 if (handle != NULL) {
	 pcap_loop(handle, 0, callback, NULL);
	}
}
