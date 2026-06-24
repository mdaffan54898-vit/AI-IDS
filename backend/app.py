from fastapi import FastAPI, HTTPException, Query, Header
from starlette.middleware.cors import CORSMiddleware
from starlette.routing import Mount
from starlette.applications import Starlette
from backend.socketio_server import socketio_app
from pydantic import BaseModel
from typing import List, Optional
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime, timedelta
import os
import sys
try:
    import psutil
except Exception:
    psutil = None
import io
import csv
from fastapi.responses import StreamingResponse
from backend.socketio_server import socketio_app, sio
from simulator.api_routes import router as simulator_router

MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
DB_NAME = 'ids_db'
COLLECTION_NAME = 'alerts'

# Create FastAPI app and mount Socket.IO ASGI app at /socket.io
app = FastAPI(title='AI IDS Backend')

# Mount the Socket.IO ASGI app so the frontend socket.io client can connect to /socket.io
app.mount('/socket.io', socketio_app)

# Allow cross-origin requests from the local frontend only (prevents duplicate headers with Socket.IO)
origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

# Mount simulator API routes (simulator package)
try:
    app.include_router(simulator_router)
except Exception:
    # If simulator package is not present or errors out, continue without it
    pass

# Orchestration settings
IDS_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ids_inference.py')
PID_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.ids.pid')
API_KEY = os.getenv('API_KEY')  # optional

import subprocess
import signal
import time


def _check_api_key(x_api_key: str = Header(None)):
    if API_KEY:
        if not x_api_key or x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail='Invalid API key')


def _read_pid():
    try:
        with open(PID_FILE, 'r') as f:
            return int(f.read().strip())
    except Exception:
        return None


def _write_pid(pid: int):
    with open(PID_FILE, 'w') as f:
        f.write(str(pid))


def _clear_pid():
    try:
        os.remove(PID_FILE)
    except Exception:
        pass


def _is_process_running(pid: int):
    if not pid:
        return False
    # Prefer psutil when available (more reliable on Windows)
    try:
        if psutil:
            return psutil.pid_exists(pid)
    except Exception:
        pass
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]


class StartIDSRequest(BaseModel):
    interface: str
    packets: int = 0


class AlertOut(BaseModel):
    id: Optional[str]
    timestamp: datetime
    attack_type: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    gemini_explanation: Optional[str]
    gemini_recommendation: Optional[str]
    gemini_rules: Optional[dict]
    # Expose protocol and bytes so the frontend can display them directly
    protocol: Optional[str] = None
    bytes_sent: Optional[int] = None


@app.get('/api/alerts', response_model=List[AlertOut])
def get_alerts(page: int = Query(1, ge=1), per_page: int = Query(25, ge=1, le=200), attack_type: Optional[str] = None, since: Optional[str] = None, recent_hours: Optional[int] = None):
    import traceback
    skip = (page - 1) * per_page
    query = {}
    if attack_type:
        query['attack_type'] = attack_type
    # Support fetching only recent alerts to avoid loading full history on dashboard load
    try:
        if since:
            # accept ISO timestamps
            try:
                dt = datetime.fromisoformat(since)
            except Exception:
                # try alternate common format
                dt = datetime.strptime(since, '%d-%m-%Y')
            query['timestamp'] = {'$gte': dt}
        elif recent_hours and recent_hours > 0:
            cutoff = datetime.now() - timedelta(hours=int(recent_hours))
            query['timestamp'] = {'$gte': cutoff}
    except Exception:
        # If parsing fails, ignore time filter
        pass
    try:
        docs = list(collection.find(query).sort('timestamp', -1).skip(skip).limit(per_page))
        results = []
        for d in docs:
            # Derive a short recommendation string from rules if possible,
            # with a fallback to the top-level 'gemini_recommendation' field.
            rec_text = d.get('gemini_recommendation')
            gemini_rules = d.get('gemini_rules') or {}
            if not rec_text and isinstance(gemini_rules, dict):
                # Prefer explicit iptables/windows rules blocks when present
                iptables = gemini_rules.get('iptables')
                windows = gemini_rules.get('windows_firewall')
                text = gemini_rules.get('text') or gemini_rules.get('recommendation')
                if iptables:
                    # iptables may be a string or a list of strings — ensure we return a single string
                    if isinstance(iptables, list):
                        rec_text = '\n'.join(iptables)
                    else:
                        rec_text = str(iptables)
                elif windows:
                    if isinstance(windows, list):
                        rec_text = '\n'.join(windows)
                    else:
                        rec_text = str(windows)
                elif text:
                    # Generic textual recommendation stored under 'text' or 'recommendation'
                    if isinstance(text, list):
                        rec_text = '\n'.join(text)
                    else:
                        rec_text = str(text)

            # Extract protocol and bytes from top-level (if present) or from features[0] as fallback
            features_list = d.get('features') or []
            first_feat = features_list[0] if len(features_list) > 0 else {}
            protocol = d.get('protocol') or first_feat.get('protocol') or None
            # prefer any normalized top-level gemini_explanation too
            gemini_expl = d.get('gemini_explanation') or d.get('explanation')

            # normalize and coerce bytes_sent from several possible fields
            raw_bytes = None
            if d.get('bytes_sent') is not None:
                raw_bytes = d.get('bytes_sent')
            else:
                # common feature keys
                for k in ('sbytes', 'bytes_sent', 'bytes'):
                    if first_feat.get(k) is not None:
                        raw_bytes = first_feat.get(k)
                        break
            try:
                bytes_sent = int(raw_bytes) if raw_bytes is not None and raw_bytes != '' else None
            except Exception:
                bytes_sent = None

            # normalize src/dst ip with fallbacks (features first, then top-level) and treat 'unknown'/'n/a' as None
            def _clean_ip(val):
                if val is None:
                    return None
                try:
                    s = str(val).strip()
                except Exception:
                    return None
                if not s or s.lower() in ('unknown', 'n/a'):
                    return None
                return s

            src_ip = first_feat.get('src_ip') or first_feat.get('srcip') or d.get('src_ip')
            dst_ip = first_feat.get('dst_ip') or first_feat.get('dstip') or d.get('dst_ip')
            src_ip = _clean_ip(src_ip)
            dst_ip = _clean_ip(dst_ip)

            # Ensure protocol is a plain uppercased string or None
            protocol = str(protocol).upper() if protocol is not None else None

            rec = {
                'id': str(d.get('_id')),
                'timestamp': d.get('timestamp'),
                'attack_type': d.get('attack_type'),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol,
                'bytes_sent': bytes_sent,
                'gemini_explanation': gemini_expl,
                'gemini_recommendation': rec_text,
                'gemini_rules': gemini_rules
            }
            # DEBUG: log the normalized record so we can inspect what is being returned to clients
            try:
                print("DEBUG /api/alerts rec:", rec)
            except Exception:
                pass
            results.append(rec)
        return results
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")



@app.get('/api/alerts/{alert_id}')
def get_alert_detail(alert_id: str):
    # Normalize incoming id (strip whitespace and angle-brackets) then
    # accept either a string representation of ObjectId or a raw stored id
    def _normalize_id(i: str):
        if not isinstance(i, str):
            return i
        i = i.strip()
        if i.startswith('<') and i.endswith('>'):
            i = i[1:-1].strip()
        return i

    norm_id = _normalize_id(alert_id)
    try:
        oid = ObjectId(norm_id)
        doc = collection.find_one({'_id': oid})
    except Exception:
        # fallback: try direct lookup in case _id was stored as string
        doc = collection.find_one({'_id': norm_id})
    if not doc:
        raise HTTPException(status_code=404, detail='Alert not found')
    # Sanitize and return only safe fields for the AlertModal
    gemini_rules = doc.get('gemini_rules') or {}
    features = doc.get('features') or []
    first_feat = features[0] if len(features) > 0 else {}

    # helper to clean IPs
    def _clean_ip(val):
        if val is None:
            return None
        try:
            s = str(val).strip()
        except Exception:
            return None
        if not s or s.lower() in ('unknown', 'n/a'):
            return None
        return s

    src_ip = first_feat.get('src_ip') or first_feat.get('srcip') or doc.get('src_ip')
    dst_ip = first_feat.get('dst_ip') or first_feat.get('dstip') or doc.get('dst_ip')
    src_ip = _clean_ip(src_ip)
    dst_ip = _clean_ip(dst_ip)

    protocol = doc.get('protocol') or first_feat.get('protocol') or None
    protocol = str(protocol).upper() if protocol is not None else None

    # normalize bytes
    raw_bytes = doc.get('bytes_sent') if doc.get('bytes_sent') is not None else (first_feat.get('sbytes') or first_feat.get('bytes_sent') or first_feat.get('bytes'))
    try:
        bytes_sent = int(raw_bytes) if raw_bytes not in (None, '') else None
    except Exception:
        bytes_sent = None

    response = {
        'id': str(doc.get('_id')),
        'timestamp': doc.get('timestamp'),
        'attack_type': doc.get('attack_type'),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'bytes_sent': bytes_sent,
        'features': features,
        'gemini_explanation': doc.get('explanation'),
        'gemini_rules': gemini_rules
    }
    return response


@app.post('/api/alerts/{alert_id}/acknowledge')
def acknowledge_alert(alert_id: str):
    # Allow ObjId or string id
    def _normalize_id(i: str):
        if not isinstance(i, str):
            return i
        i = i.strip()
        if i.startswith('<') and i.endswith('>'):
            i = i[1:-1].strip()
        return i

    norm_id = _normalize_id(alert_id)
    try:
        oid = ObjectId(norm_id)
        res = collection.update_one({'_id': oid}, {'$set': {'acknowledged': True}})
    except Exception:
        res = collection.update_one({'_id': norm_id}, {'$set': {'acknowledged': True}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail='Alert not found')
    return {'status': 'ok'}


@app.post('/api/block-ip/{ip}')
def block_ip(ip: str):
    # For now, just record the blocking action in a collection
    db['blocked_ips'].insert_one({'ip': ip, 'timestamp': datetime.now()})
    return {'status': 'blocked', 'ip': ip}


@app.post('/api/alerts/{alert_id}/generate-rule')
def generate_rule(alert_id: str):
    # Accept both ObjectId and string ids
    def _normalize_id(i: str):
        if not isinstance(i, str):
            return i
        i = i.strip()
        if i.startswith('<') and i.endswith('>'):
            i = i[1:-1].strip()
        return i

    norm_id = _normalize_id(alert_id)
    try:
        oid = ObjectId(norm_id)
        doc = collection.find_one({'_id': oid})
    except Exception:
        doc = collection.find_one({'_id': norm_id})
    if not doc:
        raise HTTPException(status_code=404, detail='Alert not found')
    # Return stored gemini_rules if present
    return {'rules': doc.get('gemini_rules', {})}


@app.get('/api/metrics')
def get_metrics():
    now = datetime.now()
    last24_cutoff = now - timedelta(hours=24)
    # Total documents stored (used as total packets/alerts)
    total = collection.count_documents({})
    # Attacks = documents where attack_type != 'Normal'
    try:
        attacks = collection.count_documents({'attack_type': {'$ne': 'Normal'}})
    except Exception:
        attacks = 0
    # Normal = documents where attack_type == 'Normal'
    try:
        normal = collection.count_documents({'attack_type': 'Normal'})
    except Exception:
        normal = 0
    # Blocked IPs count (from blocked_ips collection)
    try:
        blocked = db['blocked_ips'].count_documents({})
    except Exception:
        blocked = 0
    # last 24 hours
    try:
        last24 = collection.count_documents({'timestamp': {'$gte': last24_cutoff}})
    except Exception:
        last24 = 0
    return {'totalPackets': total, 'attacks': attacks, 'normal': normal, 'blockedIPs': blocked, 'last24h': last24}


@app.post('/api/_emit-test')
def emit_test_alert():
    """Dev helper: emit a synthetic alert over Socket.IO so frontend can test live updates.

    This endpoint does NOT write to MongoDB. It's safe for development and can be removed in production.
    """
    try:
        payload = {
            'id': 'test-' + str(int(datetime.now().timestamp())),
            'timestamp': datetime.now().isoformat(),
            'attack_type': 'Test-Alert',
            'src_ip': '192.0.2.1',
            'dst_ip': '198.51.100.2',
            'protocol': 'TCP',
            'bytes_sent': 123,
            'gemini_explanation': 'This is a synthetic test alert emitted for frontend verification.',
            'gemini_recommendation': 'No action; test alert.'
        }
        # Fire-and-forget emission
        try:
            import asyncio
            asyncio.create_task(sio.emit('new_alert', payload))
        except Exception:
            # fallback to sync emit (best-effort)
            try:
                sio.start_background_task(lambda: sio.emit('new_alert', payload))
            except Exception:
                pass
        return {'status': 'emitted', 'payload': payload}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Failed to emit test alert: {e}')


@app.post('/api/start-ids')
def start_ids(request: StartIDSRequest, x_api_key: str = Header(None)):
    _check_api_key(x_api_key)

    pid = _read_pid()
    if pid and _is_process_running(pid):
        return {'status': 'already-running', 'pid': pid}

    # Start the ids_inference.py using the same Python interpreter that runs this process
    # You can override by setting the PYTHON_EXECUTABLE env var if needed.
    python_exe = os.getenv('PYTHON_EXECUTABLE') or sys.executable
    try:
        # Ensure logs directory exists
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, 'ids.log')
        
        # Use CREATE_NO_WINDOW on Windows to prevent console/redirection issues
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NO_WINDOW

        command = [
            python_exe,
            IDS_SCRIPT,
            '--interface',
            request.interface,
            '--packets',
            str(request.packets),
            # Start IDS in hold mode: do not begin capture until the dashboard
            # or operator explicitly enables it. This prevents automatic demo
            # processing immediately after starting the process.
            '--wait-for-start'
        ]

        with open(log_path, 'a') as log_file:
            proc = subprocess.Popen(
                command,
                stdout=log_file,
                stderr=log_file,
                creationflags=creationflags
            )

        # Wait briefly to detect immediate exit (common when misconfigured or missing files)
        time.sleep(0.5)
        if proc.poll() is not None:
            # Process exited quickly; surface recent logs to help diagnosis
            try:
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as lf:
                    lines = lf.readlines()[-300:]
                    recent = ''.join(lines)
            except Exception:
                recent = 'Could not read ids.log'
            raise HTTPException(status_code=500, detail=f'IDS process terminated immediately after start. Recent logs:\n{recent}')

        _write_pid(proc.pid)
        return {'status': 'started', 'pid': proc.pid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Failed to start IDS: {e}')


@app.post('/api/stop-ids')
def stop_ids(x_api_key: str = Header(None)):
    _check_api_key(x_api_key)

    pid = _read_pid()
    if not pid:
        return {'status': 'not-running'}
    if not _is_process_running(pid):
        _clear_pid()
        return {'status': 'not-running'}
    try:
        if sys.platform == "win32":
            # Use taskkill on Windows for a more reliable termination.
            # Capture stdout/stderr to prevent outputting to the backend console.
            subprocess.run(
                ['taskkill', '/PID', str(pid), '/T', '/F'], 
                check=True, 
                capture_output=True
            )
        else:
            # Use SIGTERM on Unix-like systems
            os.kill(pid, signal.SIGTERM)
        
        _clear_pid()
        return {'status': 'stopped', 'pid': pid}
    except subprocess.CalledProcessError:
        # This can happen if the process is already gone.
        # We can treat this as a success.
        _clear_pid()
        return {'status': 'stopped', 'pid': pid}
    except Exception as e:
        # If killing the process still fails, it might be a permissions issue.
        # Double-check before returning an error.
        if not _is_process_running(pid):
            _clear_pid()
            return {'status': 'stopped', 'pid': pid}
        raise HTTPException(status_code=500, detail=f'Failed to stop IDS: {e}')


@app.get('/api/ids-status')
def ids_status(x_api_key: str = Header(None)):
    _check_api_key(x_api_key)
    pid = _read_pid()
    running = False
    if pid and _is_process_running(pid):
        running = True
    return {'running': running, 'pid': pid}


@app.post('/api/enable-capture')
def enable_capture(x_api_key: str = Header(None)):
    """Create the capture enable flag so a waiting IDS process will begin capture."""
    _check_api_key(x_api_key)
    try:
        p = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'capture_enabled.flag')
        with open(p, 'w') as f:
            f.write(str(time.time()))
        return {'status': 'enabled', 'path': p}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/api/disable-capture')
def disable_capture(x_api_key: str = Header(None)):
    """Remove the capture enable flag; running IDS will not be signalled to start."""
    _check_api_key(x_api_key)
    try:
        p = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'capture_enabled.flag')
        try:
            os.remove(p)
        except FileNotFoundError:
            pass
        return {'status': 'disabled', 'path': p}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/api/interfaces')
def list_interfaces(x_api_key: str = Header(None)):
    """Return a list of network interface names available on the host."""
    _check_api_key(x_api_key)
    if psutil:
        try:
            raw = psutil.net_if_addrs()
            interfaces = []
            for name, addrs in raw.items():
                ips = []
                for a in addrs:
                    if a.family.name.startswith('AF_') and a.address:
                        ips.append(a.address)
                interfaces.append({'name': name, 'addrs': ips})
            return {'interfaces': interfaces}
        except Exception:
            pass
    # Fallback list - common names with empty addrs
    return {'interfaces': [{'name': 'Wi-Fi', 'addrs': []}, {'name': 'Ethernet', 'addrs': []}, {'name': 'Loopback', 'addrs': []}]}


def _query_reports(start_date: Optional[str], end_date: Optional[str], attack_type: Optional[str], src_ip: Optional[str], dst_ip: Optional[str]):
    query = {}
    # Parse simple YYYY-MM-DD or DD-MM-YYYY inputs by trying both formats
    def _try_parse(date_str):
        if not date_str:
            return None
        for fmt in ('%Y-%m-%d', '%d-%m-%Y'):
            try:
                return datetime.strptime(date_str, fmt)
            except Exception:
                continue
        return None

    sd = _try_parse(start_date)
    ed = _try_parse(end_date)
    if sd and ed:
        query['timestamp'] = {'$gte': sd, '$lte': ed}
    elif sd:
        query['timestamp'] = {'$gte': sd}
    elif ed:
        query['timestamp'] = {'$lte': ed}

    if attack_type:
        query['attack_type'] = attack_type
    if src_ip:
        # match either top-level src_ip or in features[0]
        query['$or'] = query.get('$or', []) + [{'src_ip': src_ip}, {'features.0.src_ip': src_ip}]
    if dst_ip:
        query['$or'] = query.get('$or', []) + [{'dst_ip': dst_ip}, {'features.0.dst_ip': dst_ip}]

    docs = list(collection.find(query).sort('timestamp', -1))
    results = []
    for d in docs:
        features = d.get('features') or []
        results.append({
            'id': str(d.get('_id')),
            'timestamp': d.get('timestamp'),
            'attack_type': d.get('attack_type'),
            'src_ip': (features[0].get('src_ip') if features else d.get('src_ip')),
            'dst_ip': (features[0].get('dst_ip') if features else d.get('dst_ip')),
            'protocol': d.get('protocol') or (features[0].get('protocol') if features else None),
            'bytes_sent': d.get('bytes_sent') or (features[0].get('sbytes') if features else 0),
            'gemini_explanation': d.get('gemini_explanation') or d.get('explanation') or '',
            'gemini_recommendation': d.get('gemini_recommendation') or ''
        })
    return results


@app.get('/api/reports')
def get_reports(startDate: Optional[str] = None, endDate: Optional[str] = None, attackType: Optional[str] = None, srcIP: Optional[str] = None, dstIP: Optional[str] = None):
    # Return JSON array of alerts matching filters
    results = _query_reports(startDate, endDate, attackType, srcIP, dstIP)
    return results


@app.get('/api/reports/download')
def download_report(format: Optional[str] = 'csv', startDate: Optional[str] = None, endDate: Optional[str] = None, attackType: Optional[str] = None, srcIP: Optional[str] = None, dstIP: Optional[str] = None):
    results = _query_reports(startDate, endDate, attackType, srcIP, dstIP)
    # CSV export
    if format == 'csv' or not format:
        def iter_csv():
            output = io.StringIO()
            writer = csv.writer(output)
            # header
            writer.writerow(['id', 'timestamp', 'attack_type', 'src_ip', 'dst_ip', 'protocol', 'bytes_sent', 'ai_analysis'])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            for r in results:
                writer.writerow([r.get('id'), r.get('timestamp'), r.get('attack_type'), r.get('src_ip'), r.get('dst_ip'), r.get('protocol'), r.get('bytes_sent'), r.get('gemini_explanation')])
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)
        return StreamingResponse(iter_csv(), media_type='text/csv', headers={'Content-Disposition': 'attachment; filename=report.csv'})

    # PDF export using reportlab if available
    if format == 'pdf':
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
        except Exception:
            raise HTTPException(status_code=500, detail='PDF generation requires reportlab library (pip install reportlab)')

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=letter)
        width, height = letter
        y = height - 40
        c.setFont('Helvetica-Bold', 14)
        c.drawString(40, y, 'AI IDS Report')
        y -= 30
        c.setFont('Helvetica', 10)
        for r in results:
            if y < 60:
                c.showPage()
                y = height - 40
                c.setFont('Helvetica', 10)
            line = f"{r.get('timestamp')} | {r.get('attack_type')} | {r.get('src_ip')} -> {r.get('dst_ip')} | {r.get('protocol')} | {r.get('bytes_sent')} bytes"
            c.drawString(40, y, line)
            y -= 14
            # include summary line (truncated)
            expl = (r.get('gemini_explanation') or '')
            if expl:
                expl = expl.replace('\n', ' ')[:200]
                c.drawString(60, y, expl)
                y -= 14
        c.save()
        buf.seek(0)
        return StreamingResponse(buf, media_type='application/pdf', headers={'Content-Disposition': 'attachment; filename=report.pdf'})

    raise HTTPException(status_code=400, detail='Unsupported format')
