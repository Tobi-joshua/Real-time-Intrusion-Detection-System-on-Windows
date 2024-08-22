# Real-time Intrusion Detection System on Windows

![Uploading 2024-08-2117-09-23-ezgif.com-video-to-gif-converter.gif…]()


Overview
This project implements a Real-time Intrusion Detection System (IDS) for Windows, leveraging Machine Learning techniques to detect network intrusions. The system uses:

Supervised Learning: Random Forest model for identifying known attacks from CICIDS 2018 & SCVIC-APT databases.
Unsupervised Learning: Autoencoder model for anomaly detection.
Requirements
Windows OS
Python 3.9
Download Python 3.9 from Python Official Website
Ensure to select "Add Python 3.9 to PATH" during installation.
Npcap 1.71
Download from Npcap Official Website
Installation and Setup
Set up Virtual Environment
Create a virtual environment:
- python3.9 -m venv venv
Activate the virtual environment:
- ./venv/Scripts/activate
Install Dependencies
Install required Python packages:
- python -m pip install -r requirements.txt
Running the Program
Activate Virtual Environment (if not activated):
- ./venv/Scripts/activate
Run the Application:
- python application.py
Accessing the Web Application
Open your web browser and navigate to: http://localhost:5000
Troubleshooting
Python Installation Issues: Ensure you have administrative privileges and follow the recommended installation parameters.
Npcap Installation Issues: Follow the instructions provided with the Npcap installer to ensure proper installation and functionality.
