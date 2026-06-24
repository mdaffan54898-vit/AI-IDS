from pymongo import MongoClient
import os, json
MONGO_URI = os.getenv('MONGO_URI','mongodb://localhost:27017')
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client['ids_db']
collection = db['alerts']
for d in collection.find().sort('timestamp', -1).limit(10):
    features_list = d.get('features')
    protocol = d.get('protocol')
    bytes_sent = d.get('bytes_sent')
    if not protocol and features_list and len(features_list)>0:
        protocol = features_list[0].get('protocol')
    if bytes_sent is None and features_list and len(features_list)>0:
        bytes_sent = features_list[0].get('sbytes') or 0
    rec = {
        'id': str(d.get('_id')),
        'timestamp': d.get('timestamp'),
        'attack_type': d.get('attack_type'),
        'src_ip': features_list[0].get('src_ip') if features_list else None,
        'dst_ip': features_list[0].get('dst_ip') if features_list else None,
        'protocol': protocol,
        'bytes_sent': bytes_sent,
        'gemini_explanation': d.get('gemini_explanation') or d.get('explanation'),
        'gemini_recommendation': d.get('gemini_recommendation'),
        'gemini_rules': d.get('gemini_rules')
    }
    print(json.dumps(rec, default=str, indent=2))
