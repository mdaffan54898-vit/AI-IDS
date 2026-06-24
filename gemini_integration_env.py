import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# Get the Gemini API key from environment
API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise ValueError("Gemini API key not found. Please set it in the .env file.")

# Example Gemini Client initialization
class GeminiClient:
    def __init__(self, api_key):
        self.api_key = api_key

    def list_models(self):
        # Placeholder: replace this with real Gemini API call
        print("Listing models using API key:", self.api_key[:8], "…")

# Initialize client
gemini = GeminiClient(api_key=API_KEY)

# Example usage
if __name__ == "__main__":
    gemini.list_models()
