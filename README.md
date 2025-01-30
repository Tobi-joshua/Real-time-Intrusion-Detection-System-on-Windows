# Real-time Intrusion Detection System on Windows

![Intrusion Detection System](https://github.com/user-attachments/assets/e75c65ff-c318-4f94-bde5-a315265d756c)

[![Buy Me a Coffee](https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png)](https://www.buymeacoffee.com/Tobijoshua)

## 📌 Overview
This project implements a **Real-time Intrusion Detection System (IDS) for Windows**, leveraging **Machine Learning** techniques to detect network intrusions. The system is designed to monitor network traffic and identify potential security threats using:

- ✅ **Supervised Learning**: Uses a **Random Forest model** to classify known attacks from **CICIDS 2018** and **SCVIC-APT** databases.
- ✅ **Unsupervised Learning**: Uses an **Autoencoder model** to detect anomalies in network behavior.

## 🚀 Features
- **Real-time network traffic analysis**
- **Signature-based detection with supervised learning**
- **Anomaly detection with unsupervised learning**
- **User-friendly web interface**
- **Detailed logging and alert system**

## 🛠️ Requirements
Before installing and running the IDS, ensure your system meets the following requirements:

### ✅ System Requirements
- **Windows OS**
- **Python 3.9**  
  📥 [Download Python 3.9](https://www.python.org/downloads/)  
  ⚠️ Ensure you select **"Add Python 3.9 to PATH"** during installation.

- **Npcap 1.71** (for packet capture)  
  📥 [Download Npcap](https://nmap.org/npcap/)  

### ✅ Python Dependencies
All required Python packages are listed in `requirements.txt`.

---

## ⚙️ Installation and Setup

### 🔹 Step 1: Set Up a Virtual Environment
Create a virtual environment:
```sh
python3.9 -m venv venv
