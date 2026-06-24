import requests
import time
import sys

def post_start():
    url = 'http://127.0.0.1:8000/simulator/start'
    payload = {
        'attack_label': 'Exploits',
        'count': 3,
        'mock_gemini': True
    }
    try:
        r = requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print('POST exception:', e)
        return None
    print('POST', r.status_code)
    try:
        print(r.text)
    except Exception:
        pass
    if r.status_code == 201:
        return r.json().get('run_id')
    return None


def get_status(run_id):
    url = 'http://127.0.0.1:8000/simulator/status'
    try:
        r = requests.get(url, params={'run_id': run_id}, timeout=10)
        print('STATUS', r.status_code)
        print(r.text)
    except Exception as e:
        print('GET exception:', e)


if __name__ == '__main__':
    rid = post_start()
    if not rid:
        sys.exit(2)
    time.sleep(1)
    get_status(rid)
