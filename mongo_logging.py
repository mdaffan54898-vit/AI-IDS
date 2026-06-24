from pymongo import MongoClient, errors
from datetime import datetime
import pandas as pd
import asyncio
from backend.socketio_server import emit_new_alert

MONGO_URI = "mongodb://localhost:27017"
DB_NAME = "ids_db"
COLLECTION_NAME = "alerts"


def _normalize_features(features):
    """Normalize features input into a list-of-records structure suitable for storing.

    Accepts pandas DataFrame, pandas Series, dict, or list of dicts.
    Returns a list of dict records.
    """
    # DataFrame
    if isinstance(features, pd.DataFrame):
        return features.to_dict(orient='records')

    # Series (single row)
    if isinstance(features, pd.Series):
        return [features.to_dict()]

    # dict (single record)
    if isinstance(features, dict):
        return [features]

    # list-like of dicts
    try:
        # If it's list-like and its elements are dict-like, return as-is
        if hasattr(features, '__iter__'):
            return list(features)
    except Exception:
        pass

    # Fallback: try to coerce into a single-record dict
    try:
        return [dict(features)]
    except Exception:
        return [{}]


def log_alert(
    features_df,
    predictions,
    explanation,
    attack_type=None,
    gemini_rules=None,
    severity=None,
    gemini_recommendation=None,
    confidence=None,
):
    """Log an alert document to MongoDB and emit a socket event.

    Returns the inserted id (string) on success, True on success if id not available,
    or False on failure (e.g., Mongo not reachable).
    """
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)  # 5s timeout
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]

        features_records = _normalize_features(features_df)

        # derive normalized values from the first feature record (best-effort)
        protocol_val = None
        bytes_val = 0
        src_val = None
        dst_val = None
        if features_records and isinstance(features_records, list) and len(features_records) > 0:
            fr = features_records[0]
            protocol_val = (
                fr.get('protocol') or fr.get('proto') or fr.get('transport') or None
            )
            try:
                bytes_val = int(
                    fr.get('sbytes') or fr.get('bytes_sent') or fr.get('bytes') or 0
                )
            except Exception:
                bytes_val = 0
            src_val = (
                fr.get('src_ip') or fr.get('srcip') or fr.get('src') or fr.get('source') or None
            )
            dst_val = (
                fr.get('dst_ip')
                or fr.get('dstip')
                or fr.get('dst')
                or fr.get('destination')
                or None
            )

        preds = [int(p) for p in predictions]
        gemini_confidence_val = int(confidence) if confidence is not None else None

        alert_doc = {
            "timestamp": datetime.now(),
            "features": features_records,
            "predictions": preds,
            "attack_type": attack_type,
            "severity": severity,
            "gemini_rules": gemini_rules,
            # textual outputs for UI
            "gemini_recommendation": gemini_recommendation,
            "gemini_explanation": explanation,
            "gemini_confidence": gemini_confidence_val,
            # normalize important top-level fields for the frontend convenience
            "protocol": protocol_val,
            "bytes_sent": bytes_val,
        }

        # Promote simulator metadata from the first feature record if present
        try:
            first = (
                features_records[0]
                if features_records and isinstance(features_records, list)
                else {}
            )
            for k in (
                'simulator_run_id',
                'simulator_user',
                'simulator_mode',
                'user_selected_attack',
                'synthetic',
            ):
                if k in first:
                    alert_doc[k] = first.get(k)
        except Exception:
            pass

        result = collection.insert_one(alert_doc)
        print("Alert logged to MongoDB successfully.")

        # Emit real-time notification to any connected Socket.IO clients (best-effort)
        try:
            src_ip_val = (
                src_val
                if src_val is not None
                else (features_records[0].get('src_ip') if features_records else None)
            )
            dst_ip_val = (
                dst_val
                if dst_val is not None
                else (features_records[0].get('dst_ip') if features_records else None)
            )
            gemini_expl = alert_doc.get('gemini_explanation') or alert_doc.get('explanation')
            gemini_rec = alert_doc.get('gemini_recommendation')
            if not gemini_rec:
                gr = alert_doc.get('gemini_rules')
                if isinstance(gr, dict) and gr.get('iptables'):
                    gemini_rec = gr.get('iptables')

            payload = {
                'id': str(result.inserted_id) if result and result.inserted_id else None,
                'timestamp': alert_doc.get('timestamp'),
                'attack_type': alert_doc.get('attack_type'),
                'src_ip': src_ip_val,
                'dst_ip': dst_ip_val,
                'protocol': alert_doc.get('protocol'),
                'bytes_sent': alert_doc.get('bytes_sent'),
                'gemini_explanation': gemini_expl,
                'gemini_recommendation': gemini_rec,
                'gemini_rules': alert_doc.get('gemini_rules'),
                'severity': alert_doc.get('severity'),
                'gemini_confidence': alert_doc.get('gemini_confidence'),
                'color': None,
            }
            sev = alert_doc.get('severity')
            if sev:
                mapping = {
                    'Critical': '#FF0000',
                    'High': '#FF8C00',
                    'Medium': '#FFD700',
                    'Low': '#32CD32',
                }
                payload['color'] = mapping.get(sev, '#808080')

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(emit_new_alert(payload))
            except RuntimeError:
                import threading

                def _run_emit():
                    try:
                        asyncio.run(emit_new_alert(payload))
                    except Exception:
                        pass

                threading.Thread(target=_run_emit, daemon=True).start()
        except Exception:
            # If emission fails, continue — logging already succeeded
            pass

        # Return the inserted id (if available) or True
        try:
            return str(result.inserted_id) if result and result.inserted_id else True
        except Exception:
            return True

    except errors.ServerSelectionTimeoutError:
        print("Warning: Could not connect to MongoDB. Skipping logging.")
        return False
    except Exception as e:
        print(f"Warning: log_alert failed: {e}")
        return False
