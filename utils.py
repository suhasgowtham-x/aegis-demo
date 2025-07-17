from datetime import datetime

def log_interaction(user_input, ai_response):
    with open("aegis_logs.txt", "a", encoding="utf-8") as log_file:
        log_file.write(f"\n[{datetime.now()}]\nUser: {user_input}\nAEGIS: {ai_response}\n")
