# 🚀 AI Incident Response Assistant Pro

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.x-yellow?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/Platform-Linux-black?style=for-the-badge&logo=linux">
  <img src="https://img.shields.io/badge/Security-AI%20Powered-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge">
</p>

<p align="center">
  <b>AI-Powered Threat Intelligence & Automated Incident Response System</b><br>
  <i>Analyze • Detect • Respond • Secure</i>
</p>

<p align="center">
  ⚡ Real-Time Threat Detection • 🧠 AI-Driven Analysis • 🛡 Automated IP Isolation
</p>

---

## 📌 Overview

**AI Incident Response Assistant Pro** is an advanced cybersecurity CLI tool designed to:

* Analyze suspicious IP addresses
* Detect threats using real-time intelligence APIs
* Automatically respond to high-risk incidents

It combines **threat intelligence, network scanning, and firewall automation** into a single powerful system.

---

## ✨ Features

* 🧠 AI-Based Threat Analysis
* 🌍 IP Geolocation & ISP Intelligence
* ⚠️ Abuse Confidence Scoring (AbuseIPDB)
* 🔍 Common Port Scanning
* 📡 Ping & Reachability Detection
* 🔐 Automatic IP Isolation (iptables)
* 📲 Telegram Alert Integration
* 📁 JSON Logging System
* ⚡ Multi-threaded Fast Processing
* 🛡 Whitelist Protection

---

## 🧰 Tech Stack

* Python 3
* requests
* socket
* subprocess
* iptables
* ThreadPoolExecutor
* AbuseIPDB API
* IP-API

---

## 📦 Installation

```bash
git clone https://github.com/your-username/ai-incident-response-pro.git
cd ai-incident-response-pro

pip install requests
```

---

## ⚙️ Setup

### 🔑 Environment Variables

```bash
export ABUSEIPDB_API_KEY="your_api_key"
export TELEGRAM_TOKEN="your_bot_token"
export TELEGRAM_CHAT_ID="your_chat_id"
```

---

### 🛡 Run With Root Privileges

```bash
sudo python3 main.py
```

---

## 💻 Usage

```bash
scan <ip>       # Analyze IP
isolate <ip>    # Block IP
remove <ip>     # Unblock IP
logs            # View logs
help            # Show commands
exit            # Quit
```

---

## 🔍 Example

```bash
> scan 8.8.8.8
```

### ✔ Output Includes:

* Threat Score
* Reports Count
* ISP & Domain
* Open Ports
* Geolocation
* Reachability Status

⚠ If threat score exceeds threshold → prompts for **IP isolation**

---

## 🧠 How It Works

1. Validates IP address
2. Fetches threat intelligence
3. Runs parallel analysis:

   * AbuseIPDB scoring
   * Geolocation lookup
   * Ping test
   * Port scan
4. Calculates threat level
5. Suggests or performs mitigation
6. Logs events & sends alerts

---

## 📁 Logging

All activity is stored in:

```
incident_log.json
```

### Includes:

* Timestamp
* IP Address
* Threat Score
* Actions Taken

---

## 🔥 Firewall Automation

* Uses **iptables**
* Automatically blocks malicious IPs
* Prevents duplicate rules
* Saves rules persistently

---

## 📡 Telegram Alerts

```
🧠 AI INCIDENT RESPONSE

🌐 IP: x.x.x.x  
⚠️ Threat Score: 85/100  
🛡 Action: Isolated  
🕒 Time: YYYY-MM-DD HH:MM:SS
```

---

## 🛑 Security Notes

* Requires **root privileges**
* Linux only (iptables required)
* Keep API keys secure
* Use responsibly

---

## 🧑‍💻 Contributors

* **Arjun Bohara**
* **Krishna Sharma**

---

## ⭐ Final Words

> **Don’t Just Detect Threats — Eliminate Them.** 😈
