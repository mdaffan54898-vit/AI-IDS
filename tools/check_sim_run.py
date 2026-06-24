import requests, os, json
run_id='run_1761243375_ce95ce'
try:
    r = requests.get('http://127.0.0.1:8000/simulator/status', params={'run_id':run_id}, timeout=5)
    print('STATUS', r.status_code)
    print(r.text)
except Exception as e:
    print('Status request failed:', e)
# Try to connect to Mongo using default URI
from pymongo import MongoClient
uri = os.getenv('MONGO_URI','mongodb://localhost:27017')
print('Trying Mongo at', uri)
try:
    c = MongoClient(uri, serverSelectionTimeoutMS=2000)
    db = c.get_database('ids_db')
    col = db['alerts']
    cnt = col.count_documents({'simulator_run_id':run_id})
    print('Mongo synthetic alert count for', run_id, ':', cnt)
    docs = list(col.find({'simulator_run_id':run_id}).limit(5))
    for d in docs:
        d['_id']=str(d['_id'])
        print(json.dumps(d, default=str))
except Exception as e:
    print('Mongo query failed:', e)
