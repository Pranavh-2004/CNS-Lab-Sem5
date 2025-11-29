# UE23CS343AB6 : Computer Network Security Laboratory

This repository contains code, documentation, packet captures, and detailed problem statements for the laboratory exercises and CTF challenges conducted during the fifth semester as part of the **Computer Network Security (CNS)** course.

## Repository Overview

The repository is structured into lab folders for hands-on exercises, CTF folders for capture-the-flag competitions, and supplementary materials for course activities.

### Folders

- **Lab1**: Packet Sniffing and Spoofing - Introduction to packet manipulation using Scapy with tasks on sniffing ICMP, TCP, and subnet traffic, along with packet spoofing techniques.
- **Lab2**: ARP Cache Poisoning Attack - Implementation and analysis of ARP spoofing attacks using Docker containers to understand Man-in-the-Middle vulnerabilities.
- **Lab3**: TCP/IP Attacks - Exploration of TCP session hijacking, SYN flooding, and RST attacks to understand transport layer security vulnerabilities.
- **Lab4**: Firewall Exploration - Hands-on configuration and testing of packet filtering firewalls using iptables to implement security policies.
- **Lab5**: Local DNS Attack - DNS cache poisoning and spoofing attacks to understand DNS security vulnerabilities and defenses.
- **Lab6**: Remote DNS Attack - Advanced DNS attacks including Kaminsky attack implementation and defense mechanisms.
- **Lab7**: BGP Exploration and Attack - Border Gateway Protocol analysis, route hijacking, and prefix hijacking attacks on internet routing infrastructure.
- **Lab8**: VPN Tunneling - Implementation and analysis of Virtual Private Networks using TLS/SSL and IPsec protocols.
- **Lab9**: Packet Sniffing & Spoofing - Advanced packet manipulation techniques and network traffic analysis.
- **Lab10**: Additional network security exercises and explorations.
- **CTF-26th-Aug**: First CTF competition with challenges on ARP Deception, Beacon, DNS Mystery, Echoes in the Headers, Flooding, Port Knocking, and HTTP Request Smuggling.
- **CTF-18th-Sept**: Second CTF competition featuring BAZINGA, Eavesdropping, Encrypted Codex, Format vulnerabilities, and network analysis challenges.
- **CTF-15th-Nov**: Final CTF competition with advanced challenges including BLACKOUT (TLS decryption), DNS exfiltration, ICMP forensics, TCP covert channels, and packet analysis.
- **CaseStudy**: Security case studies and analysis documents.
- **ClassTest**: In-class assessment materials and solutions.
- **Lab Set up**: Environment setup instructions and configurations for Windows, Linux, and macOS (Intel).

## About the Course

The course, _UE23CS343AB6 : Computer Network Security_, focuses on hands-on learning of network security principles, attack vectors, and defense mechanisms. Topics include packet-level network analysis, cryptographic protocols, DNS security, routing security, VPN technologies, and practical exploitation techniques through CTF challenges.

## Installation Instructions for macOS

To work on the exercises in this repository, you will need Python 3.x, Docker, and various network security tools. Here's how to set up your environment:

### Prerequisites

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3
brew install python3

# Install Docker Desktop for Mac
brew install --cask docker

# Install Wireshark for packet analysis
brew install --cask wireshark

# Install network tools
brew install nmap tcpdump

# Install Python packages for network security labs
pip3 install scapy          # For packet manipulation
pip3 install pycryptodome   # For cryptographic operations
pip3 install dnspython      # For DNS operations
pip3 install requests       # For HTTP operations
pip3 install cryptography   # For TLS/SSL operations
```

### Docker Setup

Most labs use Docker containers for isolated network environments. Make sure Docker Desktop is running:

```bash
# Start Docker Desktop (or launch from Applications)
open -a Docker

# Verify Docker installation
docker --version
docker-compose --version
```

### Running Lab Exercises

Each lab folder contains its own problem statement PDF and docker-compose configuration. Generally:

```bash
# For Lab1 (Packet Sniffing and Spoofing)
cd Lab1
docker-compose up -d
sudo python3 Task1.1A.py    # Basic packet sniffing
sudo python3 Task1.2A.py    # ICMP packet spoofing

# For Lab2 (ARP Cache Poisoning)
cd Lab2
docker-compose up -d
docker exec -it <container_name> /bin/bash
# Follow lab instructions for ARP poisoning

# For Lab5 (DNS Attack)
cd Lab5
docker-compose up -d
# Configure attack and user containers as per lab instructions

# General pattern for all labs
cd Lab<X>
docker-compose up -d        # Start the lab environment
docker ps                   # List running containers
docker exec -it <container> /bin/bash  # Access container
docker-compose down         # Stop and remove containers
```

### CTF Challenges

CTF folders contain challenge prompts and solution scripts:

```bash
# For packet capture analysis
cd "CTF-15th-Nov/BLACKOUT"
wireshark challenge5.pcap   # Analyze with Wireshark
python3 decrypt_tls.py      # Run decryption scripts

# For DNS challenges
cd "CTF-15th-Nov/Lost in DNS: Broken Breadcrumbs"
wireshark dns_exfil.pcap
python3 solution.py

# For forensics challenges
cd "CTF-15th-Nov/Echoes & Echoes"
wireshark icmp_spoof_forensics_instance5.pcap
```

### Useful Commands

```bash
# Packet capture with tcpdump
sudo tcpdump -i en0 -w capture.pcap

# Analyze packets with tshark (CLI Wireshark)
tshark -r capture.pcap

# Docker network inspection
docker network ls
docker network inspect <network_name>

# Check open ports
sudo lsof -i -P -n | grep LISTEN
```

## Lab Topics Overview

### Network Layer Security

- **Packet Sniffing**: Capturing and analyzing network traffic using raw sockets and Scapy
- **Packet Spoofing**: Crafting and injecting malicious packets (ICMP, TCP, UDP)
- **ARP Attacks**: Cache poisoning and Man-in-the-Middle attacks

### Transport Layer Security

- **TCP Attacks**: SYN flooding, RST injection, session hijacking
- **Firewall Evasion**: Testing and bypassing packet filtering rules

### Application Layer Security

- **DNS Attacks**: Cache poisoning, spoofing, exfiltration, Kaminsky attack
- **HTTP Attacks**: Request smuggling, header manipulation

### Infrastructure Security

- **BGP Attacks**: Route hijacking, prefix hijacking, path manipulation
- **VPN Technologies**: Tunneling protocols, TLS/SSL VPN, IPsec VPN

### Forensics & Analysis

- **Packet Analysis**: Wireshark and tshark for network forensics
- **Covert Channels**: Data hiding in ICMP, TCP window fields, DNS queries
- **Traffic Decryption**: TLS/SSL traffic analysis and decryption techniques

## CTF Challenge Categories

The three CTF competitions cover various security domains:

- **Network Forensics**: Analyzing packet captures to find hidden data
- **Cryptography**: Decrypting network traffic and encoded messages
- **Protocol Analysis**: Understanding and exploiting protocol weaknesses
- **Steganography**: Finding hidden information in network packets
- **Exploitation**: Practical attacks on network services

## Contributions

We welcome contributions to improve this repository! Here's how you can contribute:

1. **Bug Reports**: If you find any issues in the code or documentation, feel free to open an issue in the repository.
2. **Enhancements**: Submit pull requests to add new exploits, improve existing code, or update documentation.
3. **Challenge Solutions**: Share alternative solutions to CTF challenges with detailed explanations.
4. **Tool Scripts**: Contribute automation scripts for common network security tasks.

### Guidelines for Contributors

- Ensure your code follows Python best practices and PEP 8 style guidelines.
- Test all network scripts in isolated Docker environments to avoid unintended network impacts.
- Provide detailed comments explaining attack vectors and defense mechanisms.
- Include packet capture samples where applicable.
- Document any dependencies and setup requirements clearly.
- Follow responsible disclosure practices - do not use these techniques on networks without authorization.

**⚠️ Ethical Use Warning**: The tools and techniques in this repository are for educational purposes only. Unauthorized network attacks are illegal. Always obtain proper authorization before testing on any network.

Thank you for your contributions!

## License

This repository is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgments

Special thanks to the faculty and teaching assistants of UE23CS343AB6 for their guidance and support throughout the course, and for organizing engaging CTF competitions that enhanced our practical understanding of network security.

## Resources

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [SEED Labs Project](https://seedsecuritylabs.org/) - Foundation for many lab exercises
- [RFC Index](https://www.rfc-editor.org/rfc-index.html) - Network protocol specifications

---

**Course**: UE23CS343AB6 - Computer Network Security  
**Semester**: 5th Semester (August - December 2024)  
**Institution**: PES University
