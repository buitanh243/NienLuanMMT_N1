#include "attack_detection.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/ip_icmp.h>


#define SCAN_THRESHOLD 100 // Threshold for SYN packets to detect port scanning
#define TIME_WINDOW 10   // Time window in seconds to consider for port scanning


// Structure to keep track of source IPs for port scanning detection
struct SourceEntry {
  in_addr_t source_ip; // Source IP address
  int syn_count;       // Count of SYN packets
  time_t last_time;    // Last time a SYN packet was received from this source
  struct SourceEntry *next; // Next entry in the list
};

struct SourceEntry *sources_acttack=NULL;

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
  LogAlertToFile(attack_name); 
}

// Function to analyze TCP packets for various attack patterns
void AnalyzeTcpAttack(const struct pcap_pkthdr *header, const unsigned char *packet) {
  struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
  struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);

  // Check for SYN-Flood attack pattern
  
  if (tcp_header->syn >= SCAN_THRESHOLD && !tcp_header->ack) {
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

// New code to detect SSH Brute Force attack
  if (tcp_header->dest == htons(22)) { // Check if the destination port is SSH (port 22)
    struct SourceEntry *current = sources_acttack;
    time_t now = time(NULL);

    while (current != NULL) {
      if (current->source_ip == ip_header->ip_src.s_addr) {
        if (current->last_time < now - TIME_WINDOW) {
          current->syn_count = 1; // Reset count if outside the time window
        } else {
          current->syn_count++;
          if (current->syn_count >= 4) {
            AlertAttack("Possible SSH Brute Force attack detected");
          }
        }
        current->last_time = now;
        return;
      }
      current = current->next;
    }

    struct SourceEntry *new_source = malloc(sizeof(struct SourceEntry));
    new_source->source_ip = ip_header->ip_src.s_addr;
    new_source->syn_count = 1;
    new_source->last_time = now;
    new_source->next = sources_acttack;
    sources_acttack = new_source;
  }
  }

void AnalyzeUdpAttack(const struct pcap_pkthdr *header, const unsigned char *packet) {
  struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
  struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);

  // UDP Flood detection

  struct SourceEntry *current = sources_acttack;
  time_t now = time(NULL);

  while (current != NULL) {
    if (current->source_ip == ip_header->ip_src.s_addr) {
      if (current->last_time < now - TIME_WINDOW) {
        current->syn_count = 1; 
      } else {
        current->syn_count++;
        if (current->syn_count >= SCAN_THRESHOLD) {
          AlertAttack("Possible UDP Flood attack detected");
        }
      }
      current->last_time = now;
      return;
    }
    current = current->next;
  }

  struct SourceEntry *new_source = malloc(sizeof(struct SourceEntry));
  new_source->source_ip = ip_header->ip_src.s_addr;
  new_source->syn_count = 1;
  new_source->last_time = now;
  new_source->next = sources_acttack;
  sources_acttack = new_source;

   
}

  

void AnalyzeIcmpAttack(const struct pcap_pkthdr *header, const u_char *packet) {
  struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
  struct icmp *icmp_header = (struct icmp *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);

  
  // Kiểm tra nếu ICMP packet là ICMP Fragmentation Attack
  if (ip_header->ip_off & htons(IP_MF) || ip_header->ip_off & htons(IPOPT_OFFSET)) {
    AlertAttack("Possible ICMP Fragmentation Attack detected");
  }
  else {

  
  // ICMP Flood detection
  struct SourceEntry *current = sources_acttack;
  time_t now = time(NULL);

  while (current != NULL) {
    if (current->source_ip == ip_header->ip_src.s_addr) {
      if (current->last_time < now - TIME_WINDOW) {
        current->syn_count = 1; // Reset count if outside the time window
      } else {
        current->syn_count++;
        if (current->syn_count >= SCAN_THRESHOLD) {
          AlertAttack("Possible ICMP Flood attack detected");
        }
      }
      current->last_time = now;
      return;
    }
    current = current->next;
  }

  struct SourceEntry *new_source = malloc(sizeof(struct SourceEntry));
  new_source->source_ip = ip_header->ip_src.s_addr;
  new_source->syn_count = 1;
  new_source->last_time = now;
  new_source->next = sources_acttack;
  sources_acttack = new_source;
  }

  // Detect Ping of Death attack
  // if (icmp_header->icmp_type == ICMP_ECHO) { // If ICMP type is Echo (Ping) request
  //   uint16_t icmp_length = ntohs(ip_header->ip_len) - sizeof(struct ip);
    // if (icmp_length > 65000) {
    //   AlertAttack("Possible Ping of Death attack detected");
    // }
  //}

}


