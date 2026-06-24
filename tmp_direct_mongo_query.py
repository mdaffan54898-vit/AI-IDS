import os
from pymongo import MongoClient
from bson import ObjectId
import json

# --- Configuration ---
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
DB_NAME = 'ids_db'
COLLECTION_NAME = 'alerts'
ALERT_ID_TO_FIND = '68f7d12e4d2e4a306a6f2a73'
# --- End Configuration ---

def default_serializer(o):
    """Handle types that json.dumps can't serialize by default."""
    if isinstance(o, ObjectId):
        return str(o)
    if hasattr(o, 'isoformat'):
        return o.isoformat()
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

try:
    print(f"Connecting to MongoDB at {MONGO_URI}...")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]
    
    print(f"Searching for alert with _id: {ALERT_ID_TO_FIND}")
    alert = collection.find_one({'_id': ObjectId(ALERT_ID_TO_FIND)})
    
    if alert:
        print("\n--- Alert Found in MongoDB ---")
        # Use a custom serializer to handle ObjectId and datetime
        print(json.dumps(alert, indent=2, default=default_serializer))
        
        # Explicitly check for the field
        recommendation = alert.get('gemini_recommendation')
        if recommendation:
            print(f"\n✅ Found 'gemini_recommendation': '{recommendation}'")
        else:
            print(f"\n❌ 'gemini_recommendation' field is missing or null in the database.")
            
    else:
        print(f"\n❌ Alert with ID '{ALERT_ID_TO_FIND}' not found in the database.")

except Exception as e:
    print(f"\nAn error occurred: {e}")

finally:
    if 'client' in locals():
        client.close()
        print("\nConnection closed.")
