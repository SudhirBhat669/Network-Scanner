# Network-Scanner
Network Scanner for projects

# Network Scanner
![Image](https://github.com/user-attachments/assets/c2ba41e1-ccca-46e7-b4ea-9bfbb05c5e9f)
# Wireshark
![Image](https://github.com/user-attachments/assets/63c30fa1-e591-47f2-bfa3-8c783d4c03da)
# Graph
![Image](https://github.com/user-attachments/assets/09e37457-6722-42ea-8cc0-bc332d21fe9c)
# Trend
![Image](https://github.com/user-attachments/assets/57f2d9d6-5e59-45a3-a3bb-63f024666720)

# Network Scanner with ML & GUI Dashboard
A full-featured Python application for real-time local network scanning, machine learning-based anomaly detection, visualization, scheduled scans, email alerts, Wireshark integration, and HTML/PDF reporting, all packed into a Tkinter GUI dashboard.

# Objectives
Identify open ports in your local network.
Detect anomalies in services using ML.
Visualize scanned data in graphs and trends.
Schedule daily scans and export reports.
Monitor network with Wireshark integration.

# Outcomes
Understand network exposure through open ports.
Detect unusual network behavior using ML (KMeans & IsolationForest).
Automate daily security checks and visualize changes.
Generate professional reports and receive alerts.

# Key Concepts
TCP SYN scan using nmap
Open port detection
Clustering (KMeans)
Anomaly detection (IsolationForest)
Graph visualization (NetworkX + Matplotlib)
Time-series analysis (Seaborn)
GUI with Tkinter
Email alerts
Wireshark integration
HTML & PDF reporting

# Requirements
Create a file requirements.txt with
matplotlib
networkx
pandas
seaborn
fpdf
scikit-learn
tk
pip install -r requirements.txt

# Also install
Nmap
Wireshark

# GUI Dashboard Features
Button	Description
Run Network Scan	Performs a TCP SYN scan on your local network.
Run ML Analysis	Clusters services and detects port anomalies.
Generate Graph	Creates a network graph using IP ↔ Port relations.
Generate Trend Chart	Shows scan frequency trends over time.
Export HTML/PDF Report	Saves scan results in formatted reports.
Open Wireshark	Opens Wireshark for manual packet inspection.
Start Scheduled Scans	Starts background daily scans + ML + alerts.

# Email Alerts
Alerts will be sent when ML detects anomalies. Uses smtplib via Gmail SMTP with SSL.
Make sure your email provider supports third-party SMTP or generate an app password.

# Interview Questions 
Q1. What is the purpose of this project?
Q2. How is ML used in this project?
Q3. What does the TCP SYN scan do?
Q4. Why store results in SQLite?
Q5. What are some security risks with open ports?

# Sample Graphs
1. Network Graph
Maps each IP address to the ports it has open.
2. Time-Series Trend
Shows how many services are detected over time.

# Exported Reports
report.html – Interactive report
report.pdf – Print-ready summary
ml_results.csv – ML labeled dataset

#Future Enhancements
Auto-update Nmap database
Advanced protocol analysis with Scapy
Dashboard web-based version (Flask)
Slack/Discord bot alerts
Add login/authentication for GUI

# Run Now
python network_scanner_dashboard.py
