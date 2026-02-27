# 🛡️ Real-Time Cyber Threat Monitoring Dashboard

## 📌 Introduction

The Real-Time Cyber Threat Monitoring Dashboard is a network security monitoring system designed to capture, analyze, and visualize live network traffic in order to detect potential cyber threats. 

In today’s digital environment, organizations face constant risks from malicious actors attempting unauthorized access, scanning vulnerabilities, or launching denial-of-service attacks. Traditional reactive security models are no longer sufficient. This project demonstrates how real-time packet analysis combined with intelligent threat detection can significantly reduce organizational risk.

The system continuously monitors network packets, identifies suspicious behavior patterns, and presents insights through an interactive web-based dashboard.

---

## 🎯 Project Objectives

- To implement real-time packet capture using Python.
- To analyze live network traffic and detect suspicious activity.
- To visualize traffic analytics through a dynamic dashboard.
- To demonstrate practical application of cybersecurity monitoring concepts.
- To provide early detection of network-level threats before escalation.

---

## 🚀 Key Features

- ✅ Live Network Packet Capture using Scapy  
- ✅ Real-Time Threat Detection Engine  
- ✅ Detection of:
  - Port Scanning Attempts
  - Brute-Force Login Attempts
  - Abnormal Traffic Spikes
  - Suspicious IP Behavior
- ✅ Monitoring of IP Addresses, Ports, Protocols, and TCP Flags  
- ✅ Interactive Dashboard Visualization  
- ✅ Lightweight and Scalable Architecture  

---

## 🧠 System Workflow

### 1️⃣ Packet Capture Layer

The system uses the Scapy library to capture live network packets from the host machine. Each packet contains metadata such as:

- Source IP Address  
- Destination IP Address  
- Protocol Type (TCP/UDP/ICMP)  
- Source and Destination Ports  
- TCP Flags  

This raw packet data forms the foundation for threat analysis.

---

### 2️⃣ Threat Detection Engine

Captured packets are analyzed in real-time using rule-based logic. The detection engine identifies suspicious patterns such as:

- Repeated connection attempts to multiple ports (Port Scanning)
- High-frequency traffic from a single IP (Potential DDoS behavior)
- Continuous login attempts (Brute-force attempts)
- Sudden abnormal increase in traffic volume

If suspicious activity exceeds defined thresholds, it is flagged and displayed on the dashboard.

---

### 3️⃣ Data Processing & Backend

Relevant packet information is structured and sent to the backend server (Flask/FastAPI). The backend processes and prepares the data for visualization and monitoring.

---

### 4️⃣ Interactive Dashboard

The dashboard provides:

- Real-time traffic statistics
- Threat alerts
- Protocol distribution charts
- IP activity monitoring
- Traffic spike visualization

This enables security teams to quickly understand network behavior and respond proactively.

---

## 🏗️ System Architecture

```
Network Traffic
       ↓
Packet Capture (Scapy)
       ↓
Threat Detection Engine
       ↓
Backend Server (Flask/FastAPI)
       ↓
Web Dashboard (Visualization)
```

The modular architecture ensures scalability, maintainability, and efficient real-time processing.

---

## 🛠️ Technology Stack

**Programming Language**
- Python

**Networking**
- Scapy

**Backend Framework**
- Flask / FastAPI

**Frontend**
- HTML
- CSS
- JavaScript

**Data Visualization**
- Chart.js / Plotly

**Version Control**
- Git & GitHub

**Development Environment**
- Visual Studio Code

---

## 💻 Installation Guide

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPOSITORY_NAME.git
cd YOUR_REPOSITORY_NAME
```

---

### Step 2: Install Required Dependencies

```bash
pip install -r requirements.txt
```

---

### Step 3: Run the Application

```bash
python app.py
```

The application will start at:

```
http://localhost:5000
```

Make sure you run the terminal with appropriate permissions if packet capture requires elevated access.

---

## 🌐 Live Deployment

You can access the deployed version of the dashboard here:

🔗 **Live Application:**  
https://dashb-mu.vercel.app/

---

## 🎥 Dashboard Demonstration Video






https://github.com/user-attachments/assets/323524de-7401-4814-86b8-77e98d80f6a0
---
## 📊 Real-World Applications

This project can be used in:

- Security Operations Centers (SOC)
- Enterprise Network Monitoring
- Academic Cybersecurity Labs
- Real-time Threat Detection Research
- Cybersecurity Awareness Demonstrations

---

## 🔐 Importance of Real-Time Monitoring

Real-time cyber threat monitoring significantly reduces organizational risk because:

- Early detection prevents data breaches
- Suspicious activity is identified before escalation
- Response time is minimized
- Network integrity is maintained
- Business continuity is protected

Continuous monitoring ensures that security teams stay proactive rather than reactive.

---

## 🔮 Future Enhancements

- Machine Learning-based anomaly detection
- Email and SMS alert system integration
- Cloud-native scalable deployment
- Historical log storage and analytics
- Role-based dashboard access control
- Integration with SIEM tools

---

## 👥 Project Contribution

This project was developed to demonstrate practical implementation of real-time network monitoring and cybersecurity threat detection concepts.

It reflects an understanding of packet analysis, network behavior monitoring, backend development, and dashboard visualization.

---

## 📬 Contact

For collaboration, improvements, or technical discussion, feel free to connect.

---

⭐ If you find this project valuable, please consider giving it a star on GitHub!

