import streamlit as st
import os
import hashlib
from dotenv import load_dotenv

# Load API keys from .env file
load_dotenv()
from threat_api import check_file_hash, check_ip_address
from agent import get_ai_response

# ---------------- CVE SCANNER TOOL ----------------
with st.expander("🛡️ CVE Vulnerability Scanner"):
    st.write("This tool will scan known vulnerabilities (CVE) from your inputs or uploaded files. (Coming soon)")

# ---------------- FILE HASH SCANNER ----------------
with st.expander("🧬 VirusTotal File Hash Checker"):
    uploaded_file = st.file_uploader("Upload a file to scan")
    if uploaded_file:
        file_bytes = uploaded_file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        st.write(f"SHA256: `{file_hash}`")
        vt_result = check_file_hash(file_hash)
        st.write("🔍 VirusTotal result:", vt_result)

# ---------------- ABUSEIPDB IP CHECKER ----------------
with st.expander("🎯 AbuseIPDB IP Threat Lookup"):
    ip = st.text_input("Enter an IP to check")
    if st.button("Check IP Threat"):
        if ip:
            result = check_ip_address(ip)
            st.write("📌 AbuseIPDB result:", result)

# ---------------- GPT AI ASSISTANT ----------------
with st.expander("🤖 AEGIS - Ask Anything"):
    user_input = st.text_input("💬 Ask AEGIS anything...")
    if st.button("Get Response"):
        if user_input:
            ai_reply = get_ai_response(user_input)
            st.write("🧠 AEGIS says:", ai_reply)
# ----------------- THREAT INTELLIGENCE DASHBOARD -----------------
import pandas as pd
import datetime
import matplotlib.pyplot as plt
import random

with st.expander("📊 Threat Intelligence Dashboard"):
    st.subheader("Overview")

    # Mock scan history data
    @st.cache_data
    def get_scan_history():
        severities = ["Low", "Medium", "High", "Critical"]
        return pd.DataFrame({
            "Timestamp": [datetime.datetime.now() - datetime.timedelta(hours=i*6) for i in range(10)],
            "ScanType": random.choices(["CVE", "VirusTotal", "AbuseIPDB"], k=10),
            "Severity": random.choices(severities, weights=[2, 3, 3, 2], k=10),
            "Detected": [random.choice(["Yes", "No"]) for _ in range(10)],
        })

    history_df = get_scan_history()
    st.dataframe(history_df, use_container_width=True)

    st.markdown("### Severity Distribution")
    severity_counts = history_df['Severity'].value_counts()

    fig, ax = plt.subplots()
    severity_counts.plot(kind='bar', color='skyblue', ax=ax)
    ax.set_ylabel("Count")
    ax.set_title("Severity Levels in Past Scans")
    st.pyplot(fig)

    st.markdown("### Quick Stats")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Scans", len(history_df))
    col2.metric("Critical Alerts", int((history_df['Severity'] == "Critical").sum()))
    col3.metric("Threats Detected", int((history_df['Detected'] == "Yes").sum()))
from fpdf import FPDF
import io
import os

with st.expander("🧾 Export Scan Reports"):
    st.write("Download your past scan results")

    # Export to CSV
    csv = history_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="⬇️ Download as CSV",
        data=csv,
        file_name='scan_report.csv',
        mime='text/csv'
    )

    # ✅ Export to PDF — FIXED
    def create_pdf(df, filename="temp_scan_report.pdf"):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="AEGIS Scan Report", ln=True, align='C')
        pdf.ln(10)
        for index, row in df.iterrows():
            line = f"{row['Timestamp']} | {row['ScanType']} | {row['Severity']} | Detected: {row['Detected']}"
            pdf.multi_cell(0, 10, txt=line)
        pdf.output(filename)  # Save to disk
        with open(filename, "rb") as f:
            return f.read()

    # Generate PDF binary
    pdf_data = create_pdf(history_df)

    st.download_button(
        label="📄 Download as PDF",
        data=pdf_data,
        file_name='scan_report.pdf',
        mime='application/pdf'
    )
import time
import os

with st.expander("📡 Real-Time Log Monitor + AI Alert"):
    st.subheader("Monitoring Log File in Real-Time")
    
    log_path = "sample_log.log"
    st.code(f"Watching: {os.path.abspath(log_path)}", language="bash")

    # Create mock log file if not exists
    if not os.path.exists(log_path):
        with open(log_path, "w") as f:
            f.write("Jul 17 12:00:01 suhas sshd[1000]: Started SSH daemon\n")

    show_logs = st.checkbox("📜 Show live logs", value=True)
    trigger_scan = st.button("🔄 Scan for Suspicious Activity")

    if trigger_scan:
        with open(log_path, "r") as f:
            logs = f.readlines()

        recent_logs = logs[-15:]
        display = "".join(recent_logs)
        
        if show_logs:
            st.code(display, language="shell")

        suspicious_keywords = ["Failed password", "invalid user", "denied", "attack", "unauthorized"]
        suspicious_lines = [line for line in recent_logs if any(keyword in line for keyword in suspicious_keywords)]

        if suspicious_lines:
            with st.spinner("🧠 Analyzing with GPT..."):
                ai_alert = get_ai_response(
                    "Analyze these log lines for cybersecurity threats:\n" + "".join(suspicious_lines[-10:])
                )
                st.error(f"🚨 AI Security Alert:\n\n{ai_alert}")
        else:
            st.success("✅ No suspicious activity found.")
