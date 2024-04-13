# Network Packet Analysis and Attack Detection

## Overview

This project is designed to capture and analyze network packets on a given interface, looking for specific attack patterns such as SYN-Flood, XMAS, and Port Scanning attacks. Detected attack patterns are alerted and logged to a file.

## Features

- **Packet Capturing**: Captures raw packets using the pcap library.
- **Protocol Analysis**: Parses TCP and UDP packets and identifies potential security threats.
- **Attack Detection**: Implements detection algorithms for various attack patterns:
  - SYN-Flood Attack
  - XMAS Attack
  - Port Scanning Attack
- **Alerting**: Prints alerts to the console and logs them to a file.

## Dependencies

- `libpcap` (Packet capture library)

## Files

- `main.c`: Entry point for the application.
- `packet_capture.c/h`: Handles the initialization and capture of packets.
- `packet_analysis.c/h`: Analyzes the packets and delegates specific attack analysis to `attack_detection`.
- `attack_detection.c/h`: Contains functions to analyze specific attack patterns and handle alerting.

## Configuration

You may need to adjust certain configurations such as SCAN_THRESHOLD and TIME_WINDOW in attack_detection.c to tune the sensitivity of the port scanning detection.

## How to Build

1. Install the `libpcap` development package.
2. Compile the source files:

   ```bash
   gcc main.c packet_capture.c packet_analysis.c attack_detection.c -lpcap -o packet_analyzer

## How to Run

Replace <device> with the name of the network device you want to monitor (e.g., eth0, wlan0).

   ```bash
   ./packet_analyzer <device>
