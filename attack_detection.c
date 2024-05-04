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


void AnalyzeUdpAttack(const struct pcap_pkthdr *header, const unsigned char *packet) {
  struct ip *ip_header = (struct ip *)(packet + sizeof(struct ethhdr));
  struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ip_hl * 4);

  // Tạo một cấu trúc để lưu trữ thông tin về nguồn gốc của gói tin UDP
  struct SourceEntry *current = sources_acttack;
  struct SourceEntry *prev = NULL;
  in_addr_t source_ip = ip_header->ip_src.s_addr;

  time_t now = time(NULL);

  // Lặp qua danh sách nguồn gốc đã biết
  while (current != NULL) {
    // Nếu tìm thấy nguồn gốc của gói tin UDP trong danh sách
    if (current->source_ip == source_ip) {
      // Nếu gói tin được gửi trong khoảng thời gian quy định
      if (difftime(now, current->last_time) <= TIME_WINDOW) {
        current->syn_count++; // Tăng số lượng gói tin từ nguồn gốc này
        // Nếu số lượng gói tin vượt quá ngưỡng
        if (current->syn_count >= SCAN_THRESHOLD) {
          AlertAttack("Possible UDP Flood attack detected"); // Cảnh báo về tấn công UDP Flood
          break; // Dừng việc kiểm tra vì đã phát hiện tấn công
        }
      } else {
        // Nếu gói tin được gửi sau khoảng thời gian TIME_WINDOW, đặt lại số lượng gói tin
        current->syn_count = 1;
        current->last_time = now;
      }
      break; // Dừng việc duyệt danh sách vì đã xử lý xong
    }
    prev = current;
    current = current->next;
  }

  // Nếu không tìm thấy nguồn gốc của gói tin UDP trong danh sách, thêm mới vào danh sách
  if (current == NULL) {
    struct SourceEntry *new_source = malloc(sizeof(struct SourceEntry));
    if (new_source != NULL) {
      new_source->source_ip = source_ip;
      new_source->syn_count = 1;
      new_source->last_time = now;
      new_source->next = NULL;

      // Nếu danh sách trống, gán nguồn gốc mới làm đầu danh sách
      if (prev == NULL) {
        sources_acttack = new_source;
      } else {
        // Nếu danh sách không trống, thêm nguồn gốc mới vào cuối danh sách
        prev->next = new_source;
      }
    }
  }
}

