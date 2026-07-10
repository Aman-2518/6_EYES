# 6_Eyes - Network Security Scanner

A beginner-friendly Python-based Network Security Scanner that performs TCP port scanning, service detection using banner grabbing, basic risk analysis, and generates detailed security reports.

This project was built as part of my cybersecurity learning journey to understand how network scanners work internally without relying on tools like Nmap.

---

## Features

- IPv4 & IPv6 Validation
- TCP Port Scanning
- Common Ports Scan
- Single Port Scan
- Custom Port Range Scan
- Service Detection using:
  - Banner Grabbing
  - HTTP/HTTPS Requests
  - Known Port Identification
- Basic Risk Analysis
- Security Score Calculation
- Automatic Report Generation
- Structured Project Architecture

---

## Project Structure

```
6_eyes/
│
├── main.py
├── validator.py
├── port_scanner.py
├── service_detector.py
├── risk_analyzer.py
├── report_generator.py
├── config.py
│
├── Reports/
│   ├── report01.txt
│   ├── report02.txt
│   └── ...
│
└── README.md
```

---

## How It Works

```
User Input
      │
      ▼
IP Validation
      │
      ▼
Port Scanner
      │
      ▼
Open Port Detection
      │
      ▼
Service Detection
(Banner Grabbing + HTTP Request)
      │
      ▼
Risk Analysis
      │
      ▼
Security Score Calculation
      │
      ▼
Report Generation
```

---

## Technologies Used

- Python 3
- socket
- ssl
- ipaddress
- os
- datetime

---

## Modules

### validator.py

- Validates IPv4 and IPv6 addresses.
- Detects IP version.

---

### port_scanner.py

- TCP Connect Scan
- IPv4 Support
- IPv6 Support
- Common Port Scan
- Single Port Scan
- Custom Range Scan

---

### service_detector.py

Detects services using:

- Banner Grabbing
- HTTP HEAD Requests
- HTTPS Requests using SSL
- Known Port Mapping
- Service Signature Matching

---

### risk_analyzer.py

Performs basic security assessment by assigning:

- Risk Level
- Reason
- Recommendation
- Security Penalty Score

Supported services include:

- SSH
- FTP
- SMTP
- HTTP
- HTTPS
- DNS
- POP3
- IMAP
- RPC
- SMB
- RDP
- MySQL
- PostgreSQL
- Redis

---

### report_generator.py

Automatically generates reports such as:

```
Reports/
    report01.txt
    report02.txt
    report03.txt
```

Each report contains:

- Scan Information
- Open/Closed Ports
- Detected Services
- Risk Analysis
- Recommendations
- Security Score

---

## Example Output

```
STATE   PORT   SERVICE    RISK

OPEN    135    RPC        MEDIUM
OPEN    445    SMB        HIGH
CLOSED  22     SSH        -

Security Score : 74/100
```

---

## Security Score

The scanner starts with a score of **100**.

Each detected service decreases the score according to predefined risk rules.

Example:

| Service | Risk | Penalty |
|---------|------|---------|
| SSH | Low | -2 |
| HTTP | Medium | -15 |
| SMB | High | -18 |
| FTP | High | -20 |
| Redis | High | -25 |

---

## Current Capabilities

- IPv4 Scanning
- IPv6 Scanning
- TCP Connect Scan
- Banner Grabbing
- HTTP Detection
- HTTPS Detection
- Service Identification
- Risk Assessment
- Security Score
- Report Generation

---

## Future Improvements

Planned features include:

- Multi-threaded Scanning
- OS Detection
- Banner Fingerprinting Improvements
- CVE Lookup
- Vulnerability Detection
- HTML Report Generation
- PDF Report Export
- JSON/XML Report Export
- CLI Arguments
- Scan Progress Bar
- Logging
- Scan History
- Better Error Handling

---

## Sample Report

```
NETWORK SECURITY SCANNER REPORT

Target IP : 127.0.0.1

Open Ports:
135 -> RPC
445 -> SMB

Security Score : 74/100
```

---

## Learning Objectives

This project helped me understand:

- Socket Programming
- TCP Connections
- IPv4 vs IPv6 Networking
- Banner Grabbing
- HTTP/HTTPS Communication
- SSL Wrapping
- Service Detection
- Risk Assessment
- Modular Python Project Design
- File Handling
- Report Generation

---

## Disclaimer

This project is intended for educational purposes only.

Use it only on systems you own or have explicit permission to test.

Unauthorized scanning of networks may violate laws or organizational policies.

---

## Author

**Abzam Yakkoob**

Cybersecurity Student | Python Learner | Ethical Hacking Enthusiast

Currently learning:

- Python
- Networking
- Linux
- Ethical Hacking
- TryHackMe
- Hack The Box
- Secure Software Development

---

⭐ If you found this project useful or have suggestions for improvement, feel free to open an issue or contribute.
