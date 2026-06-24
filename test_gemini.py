import os
import google.generativeai as genai

# Load key from environment
api_key = os.getenv("GEMINI_API_KEY")
print("API key detected:", bool(api_key))

genai.configure(api_key=api_key)

# Use the full, correct model name from the list
model = genai.GenerativeModel("models/gemini-2.5-flash")

response = model.generate_content("Say 'Gemini API is working!'")

print(response.text)

