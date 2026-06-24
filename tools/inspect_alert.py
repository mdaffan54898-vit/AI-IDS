import json
from pymongo import MongoClient
import os
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client['ids_db']
col = db['alerts']

d = col.find_one()
if not d:
    print('no-docs')
else:
    # convert ObjectId and any bytes
    def convert(v):
        try:
            import bson
            if isinstance(v, bson.objectid.ObjectId):
                return str(v)
        except Exception:
            pass
        if isinstance(v, bytes):
            try:
                return v.decode('utf-8')
            except Exception:
                return repr(v)
        return v

    out = {}
    for k, val in d.items():
        if k == '_id':
            out[k] = convert(val)
        else:
            out[k] = val
    print(json.dumps(out, default=str, indent=2))
