import time
from simulator.controller import start_run
from pymongo import MongoClient

rid = start_run('Exploits', 1, '10.0.0.X', True, 'qa_user', run_id=None)
print('started run', rid)
# wait for worker to run
time.sleep(2)
# check mongo
c = MongoClient('mongodb://localhost:27017', serverSelectionTimeoutMS=2000)
db = c['ids_db']
col = db['alerts']
print('count with simulator_run_id:', col.count_documents({'simulator_run_id':rid}))
for d in col.find({'simulator_run_id':rid}):
    print(d)
