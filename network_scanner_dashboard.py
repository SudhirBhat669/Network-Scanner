import os
import subprocess
import sqlite3
import threading
import time
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import seaborn as sns
from fpdf import FPDF
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from tkinter import Tk, Label, Button, messagebox

# === CONFIG ===
NETWORK_RANGE = "192.168.0.102/24"
SCAN_INTERVAL = 86400  # 24 hours
DB_NAME = "scan_results.db"
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")
EMAIL_RECEIVER = "receiver@example.com"

# === DATABASE SETUP ===
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        port INTEGER,
        timestamp TEXT
    )''')
    conn.commit()
    conn.close()

# === SCAN FUNCTION ===
def run_scan():
    result = subprocess.check_output(['nmap', '-sS', NETWORK_RANGE], text=True)
    ip, current_ip = None, None
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    for line in result.splitlines():
        if "Nmap scan report" in line:
            ip = line.split()[-1]
            current_ip = ip
        elif "/tcp" in line and "open" in line:
            port = int(line.split("/")[0])
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("INSERT INTO scans (ip, port, timestamp) VALUES (?, ?, ?)", (current_ip, port, timestamp))
    conn.commit()
    conn.close()
    messagebox.showinfo("Scan Complete", "Network scan completed and saved to database.")

# === MACHINE LEARNING ANALYSIS ===
def run_ml_analysis():
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM scans", conn)
    conn.close()
    if df.empty:
        messagebox.showwarning("No Data", "No scan data available for analysis.")
        return

    # Clustering
    X = df[['port']]
    kmeans = KMeans(n_clusters=3)
    df['cluster'] = kmeans.fit_predict(X)

    # Anomaly Detection
    iso = IsolationForest(contamination=0.1)
    df['anomaly'] = iso.fit_predict(X)

    anomalies = df[df['anomaly'] == -1]
    if not anomalies.empty:
        send_email_alert(anomalies)

    df.to_csv("ml_results.csv", index=False)
    messagebox.showinfo("ML Analysis", "Machine Learning analysis complete.\nAnomalies found: {}".format(len(anomalies)))

# === EMAIL ALERTS ===
def send_email_alert(anomalies_df):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_USER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = "⚠️ Network Scanner Alert: Anomalies Detected"

        body = "Anomalies detected:\n\n" + anomalies_df.to_string()
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print(f"Failed to send email: {e}")

# === VISUALIZATION ===
def generate_graph():
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT ip, port FROM scans", conn)
    conn.close()
    G = nx.Graph()
    for _, row in df.iterrows():
        G.add_node(row["ip"])
        G.add_edge(row["ip"], row["port"])

    plt.figure(figsize=(10, 6))
    nx.draw(G, with_labels=True, node_color='lightblue', font_size=8)
    plt.title("Network Scan Graph")
    plt.savefig("graph.png")
    messagebox.showinfo("Graph", "Graph saved as graph.png")

# === TIME-SERIES VISUALIZATION ===
def generate_trend_chart():
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM scans", conn)
    conn.close()
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    trend = df.groupby(df['timestamp'].dt.date).size()

    plt.figure(figsize=(10, 5))
    sns.lineplot(x=trend.index, y=trend.values, marker='o')
    plt.xticks(rotation=45)
    plt.title("Scan Count Over Time")
    plt.xlabel("Date")
    plt.ylabel("Scans")
    plt.tight_layout()
    plt.savefig("trend.png")
    messagebox.showinfo("Trend Chart", "Time-series chart saved as trend.png")

# === REPORT EXPORT ===
def export_report():
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM scans", conn)
    conn.close()

    # HTML
    df.to_html("report.html", index=False)

    # PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    for index, row in df.iterrows():
        pdf.cell(200, 10, txt=f"{row['timestamp']} - {row['ip']}:{row['port']}", ln=True)
    pdf.output("report.pdf")
    messagebox.showinfo("Export", "Reports saved as HTML and PDF.")

# === SCHEDULE SCANS ===
def schedule_scan():
    def loop():
        while True:
            run_scan()
            run_ml_analysis()
            time.sleep(SCAN_INTERVAL)
    threading.Thread(target=loop, daemon=True).start()

# === WIRESHARK (OPTIONAL) ===
def open_wireshark():
    try:
        subprocess.Popen(["wireshark"])
    except Exception as e:
        messagebox.showerror("Wireshark Error", f"Failed to launch Wireshark: {e}")

# === GUI SETUP ===
def start_gui():
    init_db()
    window = Tk()
    window.title("Network Scanner Dashboard")
    window.geometry("400x500")

    Label(window, text="Network Scanner Dashboard", font=("Arial", 14)).pack(pady=10)

    Button(window, text="Run Network Scan", command=run_scan).pack(pady=5)
    Button(window, text="Run ML Analysis", command=run_ml_analysis).pack(pady=5)
    Button(window, text="Generate Graph", command=generate_graph).pack(pady=5)
    Button(window, text="Generate Trend Chart", command=generate_trend_chart).pack(pady=5)
    Button(window, text="Export HTML/PDF Report", command=export_report).pack(pady=5)
    Button(window, text="Open Wireshark", command=open_wireshark).pack(pady=5)
    Button(window, text="Start Scheduled Scans", command=schedule_scan).pack(pady=20)

    window.mainloop()

# === MAIN ===
if __name__ == "__main__":
    start_gui()
