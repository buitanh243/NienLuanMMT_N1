#include "attack_detection.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/ip_icmp.h>


#define SCAN_THRESHOLD 10 // Threshold for SYN packets to detect port scanning
#define TIME_WINDOW 60   // Time window in seconds to consider for port scanning

// Structure to keep track of source IPs for port scanning detection
struct SourceEntry {
  in_addr_t source_ip; // Source IP address
  int syn_count;       // Count of SYN packets
  time_t last_time;    // Last time a SYN packet was received from this source
  struct SourceEntry *next; // Next entry in the list
};

struct SourceEntry *sources_acttack=NULL;// Linked list head for source entries

// Function to log alerts to a file
void LogAlertToFile(const char *attack_name) {
  FILE *file = fopen("alerts.log", "a");
  if (file == NULL) {
    perror("Could not open alerts.log");
    return;
  }
  fprintf(file, "ALERT: %s\n", attack_name);
  fclose(file);
}

// Function to alert an attack
void AlertAttack(const char *attack_name) {
  printf("ALERT: %s\n", attack_name);
  LogAlertToFile(attack_name); // Log the alert to a file
}

// Function to analyze TCP packets for various attack patterns
void AnalyzeTcpAttack(const struct pcap_pkthdr *header, const unsigned char *packet) {
  struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
  struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);

  // Check for SYN-Flood attack pattern
  if (tcp_header->syn && !tcp_header->ack) {
    AlertAttack("Possible SYN-Flood attack detected");
  }

  // Check for XMAS attack pattern
  if (tcp_header->fin && tcp_header->urg && tcp_header->psh) {
    AlertAttack("Possible XMAS attack detected");
  }

  // Check for Port Scanning attack pattern
  if (tcp_header->syn && !tcp_header->ack) {
    struct SourceEntry *current = sources_acttack;
    time_t now = time(NULL);

    // Iterate through linked list of sources
    while (current != NULL) {
      if (current->source_ip == ip_header->ip_src.s_addr) {
        if (current->last_time < now - TIME_WINDOW) {
          current->syn_count = 1; // Reset count if outside the time window
        } else {
          current->syn_count++;
          if (current->syn_count >= SCAN_THRESHOLD) {
            AlertAttack("Possible Port Scanning attack detected");
          }
        }
        current->last_time = now;
        return;
      }
      current = current->next;
    }

    // Add a new source entry if not found
    struct SourceEntry *new_source = malloc(sizeof(struct SourceEntry));
    new_source->source_ip = ip_header->ip_src.s_addr;
    new_source->syn_count = 1;
    new_source->last_time = now;
    new_source->next = sources_acttack;
    sources_acttack = new_source;
  }

  // Add more TCP attack analysis as needed
}

// Function to analyze UDP packets for specific attack patterns
void AnalyzeUdpAttack(const struct pcap_pkthdr *header, const unsigned char *packet) {
  struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
  struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);

  // if (header->caplen >= 1000) {
  //   AlertAttack("Possible UDP Flood attack detected"); // Can sua de chi bat UDP
  // }
}

void AnalyzeIcmpAttack(const struct pcap_pkthdr *header, const u_char *packet) {
  struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
  struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);

//  if (icmp_header->icmp_type == ICMP_ECHO) {
//     AlertAttack("Possible ICMP Echo Request (ping) Flood attack detected");
//   } Khong thong bao
}
