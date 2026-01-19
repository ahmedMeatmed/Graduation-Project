# Hybrid Intrusion Detection System (IDS) – Graduation Project

## Project Overview

This project presents a **Hybrid Intrusion Detection System (IDS)** designed to monitor network traffic, detect malicious activities, and provide real-time alerts through a web-based interface.

The system combines:

* **Signature-Based Detection** for known attacks
* **Behavior-Based & AI-Based Detection** for unknown and zero-day attacks

This layered approach helps reduce false positives and improves overall detection accuracy.

---

## System Architecture

The system is composed of three main modules:

### 1. IDS Core (C#)

* Captures live network traffic
* Analyzes packets and flows
* Applies signature-based detection
* Extracts features for AI analysis

### 2. AI Detection Engine (Python)

* Machine learning model trained on network traffic data
* Analyzes traffic when no signature is matched
* Classifies traffic as Normal or Attack

### 3. Web Application

* Displays alerts and logs
* Manages signatures and configurations
* Provides dashboards and statistics

---

## Technologies Used

* **C# (.NET)** – Core IDS engine
* **SharpPcap & PacketDotNet** – Packet capturing and parsing
* **Python (Flask, Machine Learning)** – AI detection engine
* **SQL Server** – Logs and signatures database
* **PHP / JavaScript / HTML / CSS / Larvel/ Vue js** – Web application
* **GitHub** – Version control and collaboration

---

## Project Structure

```
IDS_Project/
│── IDSCore/        # C# IDS core and AI integration
│── AI/             # Python AI engine
│── WebApp/         # Web application
│── Docs/           # Documentation
│── README.md       # Main project documentation
│── .gitignore
```

---

## Detection Workflow

1. Capture network packets
2. Apply signature-based detection
3. If no signature matches:

   * Extract flow features
   * Send data to AI engine
4. Receive AI prediction
5. Log results in the database
6. Display alerts on the web interface

---

## Key Concepts

* Signature-Based Detection
* Anomaly Detection
* False Positive & False Negative Handling
* Flow-Based Network Analysis

---

## Future Enhancements

* Real-time notifications
* Advanced visualization dashboards
* Automated AI model retraining
* Support for additional detection engines (Snort, Suricata, Zeek)
