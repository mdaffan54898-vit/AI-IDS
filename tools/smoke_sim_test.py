import requests
import time
import sys
from pymongo import MongoClient

API_BASE = 'http://127.0.0.1:8000'
MONGO_URI = 'mongodb://localhost:27017'
DB = 'ids_db'
COL = 'alerts'


def start_run(count=3, attack_label='Exploits'):
    url = f'{API_BASE}/simulator/start'
    payload = {'attack_label': attack_label, 'count': count, 'mock_gemini': True}
    r = requests.post(url, json=payload, timeout=10)
    r.raise_for_status()
    data = r.json()
    return data.get('run_id')


def poll_status(run_id, timeout=30):
    url = f'{API_BASE}/simulator/status'
    start = time.time()
    while time.time() - start < timeout:
        r = requests.get(url, params={'run_id': run_id}, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get('status') == 'stopped':
            return data
        time.sleep(0.5)
    raise TimeoutError('Simulator run did not finish in time')


def check_mongo_for_run(run_id):
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = client[DB]
    col = db[COL]
    count = col.count_documents({'simulator_run_id': run_id})
    return count


if __name__ == '__main__':
    try:
        rid = start_run()
        print('started', rid)
        poll_status(rid, timeout=20)
        cnt = check_mongo_for_run(rid)
        print('mongo count for run:', cnt)
        if cnt == 0:
            print('ERROR: no alerts found for run')
            sys.exit(3)
        print('SMOKE TEST OK')
    except Exception as e:
        print('SMOKE ERROR', e)
        sys.exit(2)
