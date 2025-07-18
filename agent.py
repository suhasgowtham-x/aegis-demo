from openai import OpenAI
from dotenv import load_dotenv
import os

# ✅ Load environment variables
load_dotenv()

# ✅ Get API key from .env
api_key = os.getenv("OPENAI_API_KEY")

# ✅ Initialize the OpenAI client
client = OpenAI(api_key=api_key)  # Only valid with openai>=1.0.0

# ✅ Define function
def get_ai_response(prompt, domain):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": f"You are AEGIS, an expert assistant in {domain}. Respond clearly."},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content.strip()
