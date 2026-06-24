from pymongo import MongoClient
import json
c = MongoClient('mongodb://localhost:27017', serverSelectionTimeoutMS=2000)
db = c.get_database('ids_db')
col = db['alerts']
for d in col.find().sort('timestamp', -1).limit(10):
    d['_id']=str(d['_id'])
    print(json.dumps(d, default=str))
