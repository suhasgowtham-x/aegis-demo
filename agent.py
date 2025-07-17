from openai import OpenAI
from utils import log_interaction
from dotenv import load_dotenv
import os

# 🔐 Load .env variables
load_dotenv()

# ✅ Load API Key from .env
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def get_ai_response(prompt, domain):
    """
    Get a response from the OpenAI Chat API for a given prompt and domain context.
    Logs the interaction after receiving the AI's reply.
    """
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": f"You are AEGIS, an expert assistant in {domain}. Always respond clearly and concisely."},
            {"role": "user", "content": prompt}
        ]
    )
    ai_reply = response.choices[0].message.content.strip()
    log_interaction(prompt, ai_reply)
    return ai_reply
