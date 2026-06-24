from simulator.client import infer
from pymongo import MongoClient
row = {'src_ip':'10.0.0.5','dst_ip':'8.8.8.8','sbytes':123,'simulator_run_id':'test_run_123','synthetic':True,'user_selected_attack':'Exploits','simulator_user':'qa'}
try:
    r = infer(row, mock=True)
    print('infer returned:', r)
except Exception as e:
    print('infer exception:', e)
# query Mongo
c=MongoClient('mongodb://localhost:27017', serverSelectionTimeoutMS=5000)
db=c['ids_db']
col=db['alerts']
print('count with simulator_run_id=test_run_123:', col.count_documents({'simulator_run_id':'test_run_123'}))
for d in col.find({'simulator_run_id':'test_run_123'}).limit(5):
    print(d)
