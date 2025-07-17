from openai import OpenAI
import os
from dotenv import load_dotenv

# ✅ Load .env
load_dotenv()

# ✅ Get key from env
api_key = os.getenv("OPENAI_API_KEY")

# ✅ Create the OpenAI client (CORRECT for v1+)
client = OpenAI(api_key=api_key)
from openai import OpenAI
import os
from dotenv import load_dotenv

# ✅ Load .env
load_dotenv()

# ✅ Get key from env
api_key = os.getenv("OPENAI_API_KEY")

# ✅ Create OpenAI client
client = OpenAI(api_key=api_key)

# ✅ Define the function
def get_ai_response(prompt, domain):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": f"You are AEGIS, an expert assistant in {domain}. Respond clearly."},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content.strip()
