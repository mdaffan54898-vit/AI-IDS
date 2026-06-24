from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import socketio
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import threading
import time
import joblib
import pandas as pd
from packet_capture import capture_packets
from feature_extraction import extract_features
from mongo_logging import log_alert
from gemini_integration import get_gemini_explanation
from twilio_alerts import send_sms_alert, send_whatsapp_alert

# Load models
try:
    model = joblib.load('xgboost_model_multi.pkl')
    le = joblib.load('label_encoder.pkl')
    expected_features = model.get_booster().feature_names
    print("Models loaded successfully")
except FileNotFoundError:
    print("Model files not found. Please run train_model.py first.")
    exit(1)

# FastAPI app
app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SocketIO
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins=["http://localhost:3000"])
socket_app = socketio.ASGIApp(sio, app)

# MongoDB
mongo_client = MongoClient("mongodb://localhost:27017")
db = mongo_client["ids_db"]
alerts_collection = db["alerts"]

# Global settings (in production, use database)
settings = {
    "twilio_sid": "",
    "twilio_token": "",
    "twilio_phone": "",
    "whatsapp_number": "",
    "gemini_key": "",
    "model": "multi-class",
    "alert_threshold": 10,
    "interface": "Wi-Fi",
    "num_packets": 100,
}

# IDS running flag
ids_running = False
ids_thread = None

def ids_loop():
    global ids_running
    while ids_running:
        try:
            packets = capture_packets(settings["interface"], settings["num_packets"])
            for pkt in packets:
                features_df = extract_features(pkt)
                pred_df = features_df.select_dtypes(include=[int, float]).reindex(columns=expected_features, fill_value=0)
                pred_class = model.predict(pred_df)[0]
                attack_type = le.inverse_transform([pred_class])[0]

                if attack_type != 'Normal':
                    # Build canonical alert fields
                    timestamp_iso = datetime.utcnow().isoformat() + 'Z'
                    src = features_df['src_ip'].iloc[0] if 'src_ip' in features_df.columns else 'unknown'
                    dst = features_df['dst_ip'].iloc[0] if 'dst_ip' in features_df.columns else 'unknown'
                    proto = features_df['protocol'].iloc[0] if 'protocol' in features_df.columns else 'TCP'
                    bytes_sent = int(features_df['sbytes'].iloc[0]) if 'sbytes' in features_df.columns else 0

                    # Try to get richer predictions (probabilities) if model supports it
                    try:
                        if hasattr(model, 'predict_proba'):
                            probs = model.predict_proba(pred_df)[0]
                            # build list of {label, probability}
                            preds = []
                            for idx, p in enumerate(probs):
                                try:
                                    label = le.inverse_transform([idx])[0]
                                except Exception:
                                    label = str(idx)
                                preds.append({"label": label, "probability": float(p)})
                            # sort desc
                            preds = sorted(preds, key=lambda x: x['probability'], reverse=True)
                        else:
                            preds = [{"label": attack_type, "probability": 1.0}]
                    except Exception:
                        preds = [{"label": attack_type, "probability": 1.0}]

                    # Get Gemini explanation
                    try:
                        gemini_result = get_gemini_explanation({"timestamp": timestamp_iso, "src_ip": src, "dst_ip": dst, "protocol": proto, "bytes_sent": bytes_sent})
                        explanation = gemini_result.get('explanation', '')
                        recommendation = gemini_result.get('recommendation', '')
                    except Exception as e:
                        explanation = f"Gemini error: {e}"
                        recommendation = ""

                    # Canonical alert object
                    alert_data = {
                        "id": str(datetime.utcnow().timestamp()).replace('.', '') ,
                        "timestamp": timestamp_iso,
                        "src_ip": src,
                        "dst_ip": dst,
                        "attack_type": attack_type,
                        "protocol": proto,
                        "bytes_sent": bytes_sent,
                        "gemini_explanation": explanation,
                        "gemini_recommendation": recommendation,
                        "predictions": preds,
                    }

                    # Persist to MongoDB and emit to websocket
                    try:
                        alerts_collection.insert_one(alert_data)
                        print("Alert persisted to MongoDB")
                    except Exception as e:
                        print(f"MongoDB insert error: {e}")

                    try:
                        sio.emit('new_alert', alert_data)
                    except Exception as e:
                        print(f"Socket emit error: {e}")

                    # Send alerts if Twilio configured
                    if settings["twilio_phone"] and settings["twilio_sid"]:
                        alert_message = f"⚠️ Intrusion Detected!\nAttack Type: {attack_type}\nSource IP: {src}\nDestination IP: {dst}\nProtocol: {proto}\nGemini Recommendation: {recommendation or 'N/A'}"
                        try:
                            send_sms_alert(alert_message)
                            send_whatsapp_alert(alert_message)
                        except Exception as e:
                            print(f"Twilio error: {e}")

            time.sleep(5)  # Poll every 5 seconds
        except Exception as e:
            print(f"IDS loop error: {e}")
            time.sleep(10)

@app.post("/api/start-ids")
def start_ids():
    global ids_running, ids_thread
    if not ids_running:
        ids_running = True
        ids_thread = threading.Thread(target=ids_loop)
        ids_thread.start()
        return {"message": "IDS started"}
    return {"message": "IDS already running"}

@app.post("/api/stop-ids")
def stop_ids():
    global ids_running, ids_thread
    ids_running = False
    if ids_thread:
        ids_thread.join()
    return {"message": "IDS stopped"}

@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    alerts = list(alerts_collection.find().sort("timestamp", -1).limit(limit))
    normalized = []
    for alert in alerts:
        # prefer explicit id field, fallback to _id
        alert_id = alert.get('id') or alert.get('_id')
        try:
            alert['id'] = str(alert_id)
        except Exception:
            alert['id'] = alert_id
        # remove internal _id for frontend cleanliness
        if '_id' in alert:
            del alert['_id']
        normalized.append(alert)
    return normalized

@app.get("/api/alert/{alert_id}")
def get_alert(alert_id: str):
    # Try to find by explicit id field first
    alert = alerts_collection.find_one({"id": alert_id})
    if not alert:
        # try ObjectId fallback
        try:
            alert = alerts_collection.find_one({"_id": ObjectId(alert_id)})
        except Exception:
            alert = None
    if alert:
        alert['id'] = str(alert.get('id') or alert.get('_id'))
        if '_id' in alert:
            del alert['_id']
        return alert
    raise HTTPException(status_code=404, detail="Alert not found")

@app.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    result = alerts_collection.update_one({"id": alert_id}, {"$set": {"acknowledged": True}})
    if result.modified_count == 0:
        # try fallback to ObjectId
        try:
            res2 = alerts_collection.update_one({"_id": ObjectId(alert_id)}, {"$set": {"acknowledged": True}})
            if res2.modified_count == 0:
                raise HTTPException(status_code=404, detail="Alert not found")
        except Exception:
            raise HTTPException(status_code=404, detail="Alert not found")
    return {"message": "Alert acknowledged"}

@app.post("/api/block-ip/{ip}")
def block_ip(ip: str):
    # Placeholder: Implement actual IP blocking (e.g., via iptables or firewall API)
    print(f"Blocking IP: {ip}")
    return {"message": f"IP {ip} blocked"}

@app.post("/api/generate-rule/{alert_id}")
def generate_rule(alert_id: str):
    # Placeholder: Generate detection rule based on alert
    print(f"Generating rule for alert: {alert_id}")
    return {"message": "Rule generated"}

@app.get("/api/metrics")
def get_metrics():
    total_alerts = alerts_collection.count_documents({})
    pipeline = [
        {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}}
    ]
    attack_breakdown = list(alerts_collection.aggregate(pipeline))
    return {
        "totalAlerts": total_alerts,
        "uniqueAttackTypes": len(attack_breakdown),
        "attackBreakdown": attack_breakdown
    }

@app.get("/api/reports")
def get_reports(start_date: str = None, end_date: str = None, attack_type: str = None):
    query = {}
    if start_date:
        query["timestamp"] = {"$gte": start_date}
    if end_date:
        query.setdefault("timestamp", {})["$lte"] = end_date
    if attack_type:
        # Assuming attack_type is stored
        query["attack_type"] = attack_type
    reports = list(alerts_collection.find(query).sort("timestamp", -1))
    for report in reports:
        report["_id"] = str(report["_id"])
    return reports

@app.post("/api/settings")
def update_settings(new_settings: dict):
    global settings
    settings.update(new_settings)
    return {"message": "Settings updated"}

@app.get("/api/settings")
def get_settings():
    return settings

# SocketIO events
@sio.event
async def connect(sid, environ):
    print(f"Client connected: {sid}")

@sio.event
async def disconnect(sid):
    print(f"Client disconnected: {sid}")

# Mount SocketIO
app.mount("/", socket_app)


@app.post('/api/dev/emit-sample')
def emit_sample_alerts(count: int = 10):
    import random
    from datetime import datetime
    attack_types = ["DoS", "Exploits", "Fuzzers", "Reconnaissance", "Generic"]
    protocols = ["TCP", "UDP", "ICMP"]

    for i in range(count):
        sample = {
            "id": f"sample-{int(datetime.utcnow().timestamp() * 1000)}-{i}",
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "src_ip": f"192.168.1.{random.randint(2, 200)}",
            "dst_ip": f"10.0.0.{random.randint(2, 200)}",
            "attack_type": random.choice(attack_types),
            "protocol": random.choice(protocols),
            "bytes_sent": random.randint(500, 20000),
            "gemini_explanation": "Auto-generated sample explanation",
            "gemini_recommendation": "Auto-generated sample recommendation",
            "predictions": [{"label": "Exploits", "probability": 0.7}, {"label": "DoS", "probability": 0.2}]
        }
        try:
            alerts_collection.insert_one(sample)
            # emit to websocket
            sio.emit('new_alert', sample)
        except Exception as e:
            print(f"Error emitting sample alert: {e}")

    return {"status": "ok", "count": count}