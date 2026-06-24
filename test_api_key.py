import requests, json

API_KEY = "AIzaSyC0SE_uRmBOVWOkG1YqIUeAIZssK_zTFkY"
url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={API_KEY}"

data = {
    "contents": [
        {"parts": [{"text": "Hello Gemini, write a short cybersecurity alert summary."}]}
    ]
}

resp = requests.post(url, json=data)
print("STATUS:", resp.status_code)
# Check if the response has content before trying to parse it as JSON
if resp.text:
    try:
        print(json.dumps(resp.json(), indent=2))
    except json.JSONDecodeError:
        print("Could not decode JSON, raw response:")
        print(resp.text)
else:
    print("Response was empty.")
