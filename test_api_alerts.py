#!/usr/bin/env python
"""Quick test script to verify /api/alerts returns key fields including Gemini recommendation."""
import requests
import json

API_URL = "http://127.0.0.1:8000/api/alerts?per_page=5"
try:
    r = requests.get(API_URL, timeout=5)
    r.raise_for_status()
    alerts = r.json()
    print(f"Fetched {len(alerts)} alert(s):")
    
    # Find the first alert that is not "Normal"
    attack_alert = None
    for alert in alerts:
        if alert.get('attack_type') != 'Normal':
            attack_alert = alert
            break

    if not attack_alert:
        print("\nNo non-Normal attack alerts found in the last 5 alerts to check for Gemini content.")
    else:
        print("\n--- Most Recent Attack Alert ---")
        print(json.dumps({
            'id': attack_alert.get('id'),
            'timestamp': attack_alert.get('timestamp'),
            'attack_type': attack_alert.get('attack_type'),
            'src_ip': attack_alert.get('src_ip'),
            'protocol': attack_alert.get('protocol'),
            'bytes_sent': attack_alert.get('bytes_sent'),
            'gemini_recommendation': attack_alert.get('gemini_recommendation'),
        }, indent=2))

        if attack_alert.get('protocol'):
            print("\n✅ Protocol field is present!")
        else:
            print("\n❌ Protocol field is missing or None!")
        
        if attack_alert.get('bytes_sent') is not None:
            print("✅ bytes_sent field is present!")
        else:
            print("❌ bytes_sent field is missing or None!")

        if attack_alert.get('gemini_recommendation'):
            print("✅ gemini_recommendation field is present!")
        else:
            print("❌ gemini_recommendation field is missing or None!")

except Exception as e:
    print(f"Error: {e}")
