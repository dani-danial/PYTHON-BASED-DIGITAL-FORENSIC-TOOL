# NetTrace: Python-Based Digital Forensic Tool 🕵️‍♂️💻

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**NetTrace** is an automated network forensic analysis tool designed to conduct systematic and efficient examinations of Packet Capture (PCAP/PCAPNG) files. It bridges the gap between raw packet analysis and formal forensic procedures by integrating automated threat detection with strict evidence integrity verification.

## 🚀 Key Features
* **Evidence Integrity:** Implements dual-stage (Ingress/Egress) hashing using SHA-256 and MD5 to mathematically prove non-destructive analysis.
* **Heuristic Detection Engine:** Automatically flags suspicious activities, including:
    * Malware Command-and-Control (C2) communication.
    * DDoS flooding patterns via traffic volume analysis.
    * Suspicious HTTP behaviors and User-Agent signatures.
* **Professional Reporting:** Generates interactive HTML dashboards and static PDF forensic reports for stakeholders.
* **Audit Trail:** Maintains a timestamped processing log for every action taken during the investigation.

## 🛠️ Tech Stack
* **Core Engine:** `pyshark` for Deep Packet Inspection (DPI).
* **Analysis:** `pandas` and `numpy` for data structuring.
* **Visualization:** `matplotlib` for generating threat distribution charts.
* **Reporting:** `fpdf` (PDF generation) and HTML/JavaScript (Interactive Dashboard).

## 📂 Project Structure
```text
├── src/                # Source code
├── evidence/           # Folder for PCAP/PCAPNG files [cite: 119]
├── reports/            # Generated PDF and HTML reports [cite: 130]
├── requirements.txt    # Python dependencies
└── launcher.bat        # Custom Windows launcher script [cite: 233, 716]
