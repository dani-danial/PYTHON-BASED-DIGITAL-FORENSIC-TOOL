# NetTrace: Python-Based Digital Forensic Tool 🕵️‍♂️💻

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[cite_start]**NetTrace** is an automated network forensic analysis tool designed to conduct systematic and efficient examinations of Packet Capture (PCAP/PCAPNG) files[cite: 23]. [cite_start]It bridges the gap between raw packet analysis and formal forensic procedures by integrating automated threat detection with strict evidence integrity verification[cite: 24, 36].

## 🚀 Key Features
* [cite_start]**Evidence Integrity:** Implements dual-stage (Ingress/Egress) hashing using SHA-256 and MD5 to mathematically prove non-destructive analysis[cite: 48, 431, 441].
* **Heuristic Detection Engine:** Automatically flags suspicious activities, including:
    * [cite_start]Malware Command-and-Control (C2) communication[cite: 49, 448].
    * [cite_start]DDoS flooding patterns via traffic volume analysis[cite: 61, 446].
    * [cite_start]Suspicious HTTP behaviors and User-Agent signatures[cite: 49, 448].
* [cite_start]**Professional Reporting:** Generates interactive HTML dashboards and static PDF forensic reports for stakeholders[cite: 51, 56, 449, 455].
* [cite_start]**Audit Trail:** Maintains a timestamped processing log for every action taken during the investigation[cite: 422].

## 🛠️ Tech Stack
* [cite_start]**Core Engine:** `pyshark` for Deep Packet Inspection (DPI)[cite: 134, 428].
* [cite_start]**Analysis:** `pandas` and `numpy` for data structuring[cite: 134].
* [cite_start]**Visualization:** `matplotlib` for generating threat distribution charts[cite: 134].
* [cite_start]**Reporting:** `fpdf` (PDF generation) and HTML/JavaScript (Interactive Dashboard)[cite: 134, 429, 458].

## 📂 Project Structure
```text
├── src/                # Source code
├── evidence/           # Folder for PCAP/PCAPNG files [cite: 119]
├── reports/            # Generated PDF and HTML reports [cite: 130]
├── requirements.txt    # Python dependencies
└── launcher.bat        # Custom Windows launcher script [cite: 233, 716]
