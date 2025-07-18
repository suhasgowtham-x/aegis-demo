import streamlit as st
import os
import time
import pandas as pd
import hashlib
import matplotlib.pyplot as plt
import random
from dotenv import load_dotenv
from fpdf import FPDF
from openai import OpenAI

from threat_api import check_file_hash, check_ip_address
from agent import get_ai_response

# Load environment variables
load_dotenv()
client = OpenAI()

# Setup Streamlit
st.set_page_config(page_title="AEGIS", layout="wide")
st.sidebar.title("🛡️ AEGIS Security Assistant")

# Sidebar module selector
app_mode = st.sidebar.selectbox("Choose a module", [
    "🛡️ CVE Vulnerability Scanner",
    "🧬 VirusTotal File Hash Checker",
    "🎯 AbuseIPDB IP Threat Lookup",
    "🤖 AEGIS - Ask Anything",
    "📡 Real-Time Log Monitor + AI Alert",
    "📊 Threat Intelligence Dashboard",
    "🧾 Export Scan Reports"
])

# 🔁 Shared Function for Dashboard + Export
@st.cache_data
def get_scan_history():
    severities = ["Low", "Medium", "High", "Critical"]
    return pd.DataFrame({
        "Timestamp": [pd.Timestamp.now() - pd.Timedelta(hours=i*6) for i in range(10)],
        "ScanType": random.choices(["CVE", "VirusTotal", "AbuseIPDB"], k=10),
        "Severity": random.choices(severities, weights=[2, 3, 3, 2], k=10),
        "Detected": [random.choice(["Yes", "No"]) for _ in range(10)],
    })

# CVE Log Scanner
if app_mode == "🛡️ CVE Vulnerability Scanner":
    st.title("🔍 CVE Log Scanner")
    file = st.file_uploader("Upload log file", type=["log", "txt"])
    if file:
        content = file.read().decode("utf-8")
        st.code(content[:1500], language="bash")
        with st.spinner("Analyzing with AI..."):
            prompt = f"Scan this log file for known vulnerabilities:\n{content}"
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You're a cybersecurity expert."},
                    {"role": "user", "content": prompt}
                ]
            )
            result = response.choices[0].message.content
            st.success("✅ Analysis Complete")
            st.text_area("🧠 AI Response", result, height=300)

# VirusTotal File Hash Checker
elif app_mode == "🧬 VirusTotal File Hash Checker":
    st.title("🧬 File Hash Malware Checker")
    file = st.file_uploader("Upload a file")
    if file:
        file_bytes = file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        st.write(f"SHA256: `{file_hash}`")
        result = check_file_hash(file_hash)
        if "error" in result:
            st.warning("⚠️ File not found in VirusTotal.")
        else:
            st.write("🔍 VirusTotal result:", result)

# AbuseIPDB IP Threat Lookup
elif app_mode == "🎯 AbuseIPDB IP Threat Lookup":
    st.title("🎯 IP Threat Intelligence")
    ip = st.text_input("Enter an IP to check")
    if st.button("Check IP Threat"):
        if ip:
            result = check_ip_address(ip)
            if "error" in result:
                st.error("❌ Authentication failed or key missing. Check your API key.")
            else:
                st.write("📌 AbuseIPDB result:", result)

# AEGIS Chat Assistant
elif app_mode == "🤖 AEGIS - Ask Anything":
    st.title("🤖 Ask AEGIS")
    user_input = st.text_input("💬 Ask AEGIS anything...")
    if st.button("Get Response"):
        if user_input:
            reply = get_ai_response(user_input, "cybersecurity")
            st.write("🧠 AEGIS says:", reply)

# Real-Time Log Monitor + AI Alert
elif app_mode == "📡 Real-Time Log Monitor + AI Alert":
    st.title("📡 Real-Time Log Monitor")

    log_path = "mock_logs/auth.log"
    abs_path = os.path.abspath(log_path)
    st.code(f"Watching: {abs_path}", language="bash")

    # Ensure folder and file exist
    os.makedirs("mock_logs", exist_ok=True)
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
                alert = get_ai_response("Analyze these log lines:\n" + "".join(suspicious_lines[-10:]), "cybersecurity")
                st.error(f"🚨 AI Security Alert:\n\n{alert}")
        else:
            st.success("✅ No suspicious activity found.")

# Threat Intelligence Dashboard
elif app_mode == "📊 Threat Intelligence Dashboard":
    st.title("📊 Dashboard")

    df = get_scan_history()
    st.dataframe(df)

    st.markdown("### Severity Distribution")
    fig, ax = plt.subplots()
    df['Severity'].value_counts().plot(kind='bar', color='skyblue', ax=ax)
    st.pyplot(fig)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Scans", len(df))
    col2.metric("Critical Alerts", int((df['Severity'] == "Critical").sum()))
    col3.metric("Threats Detected", int((df['Detected'] == "Yes").sum()))

# Export Scan Reports
elif app_mode == "🧾 Export Scan Reports":
    st.title("📤 Export Reports")

    df = get_scan_history()
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button("⬇️ Download CSV", csv, file_name="scan_report.csv", mime="text/csv")

    def create_pdf(data):
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="AEGIS Scan Report", ln=True, align='C')
        pdf.ln(10)
        for _, row in data.iterrows():
            line = f"{row['Timestamp']} | {row['ScanType']} | {row['Severity']} | Detected: {row['Detected']}"
            pdf.multi_cell(0, 10, txt=line)
        pdf.output("temp_report.pdf")
        with open("temp_report.pdf", "rb") as f:
            return f.read()

    pdf_bytes = create_pdf(df)
    st.download_button("📄 Download PDF", data=pdf_bytes, file_name="scan_report.pdf", mime="application/pdf")
