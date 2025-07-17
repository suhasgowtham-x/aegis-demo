import time
import streamlit as st

LOG_FILE = "sample_logs/auth.log"  # Replace with your real path on Linux

def tail_log(file_path, lines=10):
    with open(file_path, "r", encoding="utf-8") as f:
        return list(f.readlines())[-lines:]

def stream_log():
    st.subheader("📡 Real-Time Log Monitor")
    log_area = st.empty()
    while True:
        log_lines = tail_log(LOG_FILE)
        log_area.text("".join(log_lines))
        time.sleep(2)
