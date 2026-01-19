# IDS Core & AI Integration Module (C#)

## Module Overview

This module represents the **core detection engine** of the IDS system.
It is responsible for capturing network traffic, analyzing packets and flows, detecting known attacks using signatures, and forwarding suspicious traffic to the AI engine when necessary.

---

## Responsibilities

* Live packet capture
* Packet parsing and protocol identification
* Signature-based attack detection
* Behavioral detection (e.g. scanning behavior)
* Feature extraction for AI analysis
* Communication with AI engine
* Logging detection results

---

## Packet Capture & Processing

* Network packets are captured using **SharpPcap**
* Packet details are parsed using **PacketDotNet**
* Extracted data includes:

  * Source IP / Destination IP
  * Source Port / Destination Port
  * Protocol
  * Packet size
  * Payload size
  * TCP flags
  * Flow direction
  * Packet count and duration

---

## Signature-Based Detection

* Packets are compared against stored signatures
* Signatures are retrieved from the database
* If a match is found:

  * The packet is classified as malicious
  * The corresponding attack type is logged

---

## AI-Based Detection Integration

When no signature matches:

1. Traffic features are extracted
2. Features are sent to the AI engine via HTTP (Flask API)
3. The AI model analyzes the traffic
4. A prediction is returned:

   * Normal
   * Attack
5. The result is logged and handled accordingly

This approach allows detection of **unknown and zero-day attacks**.

---

## Feature Set Used for AI

* Protocol
* Source Port
* Destination Port
* Packet Size
* Payload Size
* Packet Count
* Flow Duration
* Flow Direction
* TCP Flags

---

## Logging & Database Interaction

* All detection results are stored in the database
* Logs include:

  * Detection type (Signature / AI)
  * Attack name (if available)
  * Packet and flow details
  * Timestamp

---

## Design Advantages

* Layered detection approach
* Reduced false positives
* Real-time traffic analysis
* Scalable and modular design

---

## Future Improvements

* Flow-based aggregation optimization
* Improved AI feature engineering
* Performance tuning for high traffic environments
* Integration with additional AI models
