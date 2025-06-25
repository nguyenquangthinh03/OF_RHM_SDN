# Moving Target Defense in SDN Networks

This project implements **OpenFlow-Random Host Mutation(OF-RHM)** strategy in **Software-Defined Networking (SDN)** environments using the **Ryu controller**. The system dynamically mutates host IP addresses based on session activity to reduce vulnerability to network reconnaissance (e.g., scanning) attacks, while preserving active communication sessions.
## Objectives

- Apply IP mutation techniques per host, based on the number of active sessions.
- Mitigate the effectiveness of reconnaissance tools (e.g., Nmap).
- Maintain connection stability without disrupting ongoing sessions.

## 🧩 Key Features

- **Real-to-Virtual IP Mapping**: Each host has a real IP and a rotating virtual IP.
- **Session-Aware Mutation**: Delays IP changes if an active session is ongoing.
- **Internal DNS Logic**: Resolves domain names like `host1.mtd.` to real IPs dynamically.
- **Flow Table Management**: Clears and rebuilds OpenFlow entries after each IP mutation.
- **Dynamic Timeout Adjustment**: Timeout values for each host adapt to traffic volume.
- **Logging**:
  - `session_log.txt`: Tracks active communication sessions.
  - `ip_mutation_log.txt`: Logs each IP mutation with timestamps.

## Simulation & Evaluation

The system was tested using:

- **Mininet**: Emulates SDN topology with 8 hosts.
- **iPerf**: Generate traffic with tcp and udp packets.
- **Nmap**: Scans for live IPs to assess mutation effectiveness.

Results show the system reduces IP exposure to scanning while maintaining session stability through intelligent IP change delays.
