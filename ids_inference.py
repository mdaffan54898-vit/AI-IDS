# IDS Inference Script
# This script captures packets, extracts features, and uses the trained XGBoost model to predict attacks.

from packet_capture import capture_packets
from feature_extraction import extract_features
from mongo_logging import log_alert
from gemini_integration import summarize_alert  # Use the new function
from gemini_integration import shutdown as gemini_shutdown
from twilio_alerts import send_sms_alert, send_whatsapp_alert
from flow_counters import tick_packet, get_packet_counts
import joblib
from datetime import datetime
import argparse
import pandas as pd
import signal
import threading
import logging
from logging.handlers import RotatingFileHandler
import os
import random
import ipaddress
import time as _time
import json
from pathlib import Path


# ---------- DEMO ATTACK GENERATOR (UNSW-style) ----------
UNSW_ATTACK_TEMPLATES = {
    "DoS": {
        "attack_cat": "DoS",
        "protocol": "TCP",
        "service": "http",
        "state": "EST",
        "sbytes": 50000,
        "dbytes": 40,
        "dur": 5.0,
        "spkts": 400,
        "dpkts": 4,
        "trans_depth": 0,
        "response_body_len": 0
    },
    "Exploits": {
        "attack_cat": "Exploits",
        "protocol": "TCP",
        "service": "http",
        "state": "INT",
        "sbytes": 1500,
        "dbytes": 200,
        "dur": 0.2,
        "spkts": 5,
        "dpkts": 3,
        "trans_depth": 2,
        "response_body_len": 1024
    },
    "Reconnaissance": {
        "attack_cat": "Reconnaissance",
        "protocol": "ICMP",
        "service": "icmp",
        "state": "CON",
        "sbytes": 80,
        "dbytes": 80,
        "dur": 0.01,
        "spkts": 1,
        "dpkts": 1,
        "trans_depth": 0,
        "response_body_len": 0
    },
    "Generic": {
        "attack_cat": "Generic",
        "protocol": "UDP",
        "service": "dns",
        "state": "INT",
        "sbytes": 600,
        "dbytes": 300,
        "dur": 0.15,
        "spkts": 3,
        "dpkts": 2,
        "trans_depth": 0,
        "response_body_len": 128
    },
    "Backdoor": {
        "attack_cat": "Backdoor",
        "protocol": "TCP",
        "service": "ssh",
        "state": "EST",
        "sbytes": 4000,
        "dbytes": 3300,
        "dur": 60.0,
        "spkts": 100,
        "dpkts": 95,
        "trans_depth": 0,
        "response_body_len": 0
    }

    ,"Shellcode": {
        "attack_cat": "Shellcode",
        "protocol": "TCP",
        "service": "http",
        "state": "INT",
        "sbytes": 1500,
        "dbytes": 200,
        "dur": 0.5,
        "spkts": 10,
        "dpkts": 2,
        "trans_depth": 1,
        "response_body_len": 512
    }
}


def _rand_private_ip():
    # generate a random RFC1918 IPv4 string
    nets = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    net = random.choice(nets)
    n = ipaddress.ip_network(net)
    # skip network and broadcast
    host_int = random.randint(1, n.num_addresses - 2)
    return str(n.network_address + host_int)


# --- Anchors persistence: defaults + file-backed override ---
DEFAULT_ANCHORS = {
    'Exploits': {'spkts': 252, 'sbytes': 114687, 'rate': 464.12, 'sinpkt': 0.97, 'proto': 'TCP'},
    'Backdoor': {'spkts': 335, 'sbytes': 42695, 'rate': 725.51, 'sinpkt': 2.38, 'proto': 'TCP'},
    'Fuzzers': {'spkts': 1431, 'sbytes': 114350, 'rate': 2024.10, 'sinpkt': 6.05, 'proto': 'UDP'},
}

ANCHORS_PATH = Path('anchors.json')
try:
    if ANCHORS_PATH.exists():
        with ANCHORS_PATH.open('r', encoding='utf-8') as fh:
            ANCHORS = json.load(fh)
    else:
        # persist defaults so demos are repeatable across runs
        with ANCHORS_PATH.open('w', encoding='utf-8') as fh:
            json.dump(DEFAULT_ANCHORS, fh, indent=2)
        ANCHORS = DEFAULT_ANCHORS.copy()
except Exception:
    # Fallback to defaults in case of I/O / permission issues
    ANCHORS = DEFAULT_ANCHORS.copy()

def save_anchors(anchors: dict, path: str = 'anchors.json') -> None:
    """Persist anchors to disk (JSON). Overwrites existing file.

    Use this from tuning scripts to persist discovered anchors.
    """
    try:
        # backup existing anchors file before overwriting
        import shutil
        p = Path(path)
        if p.exists():
            try:
                bak = p.with_suffix('.json.bak')
                shutil.copy(str(p), str(bak))
            except Exception:
                # don't fail saves due to backup issues
                pass
        with p.open('w', encoding='utf-8') as fh:
            json.dump(anchors, fh, indent=2)
        try:
            print(f"✅ Anchors saved to {p} (backup written if existing)")
        except Exception:
            pass
    except Exception:
        pass


def generate_demo_packets(attack_list, count_per_attack=5, jitter=True, expected_features=None, use_tuned=False, use_anchor=False):
    """Yield pandas.DataFrame rows (one-row) for each synthetic attack sample.
    `attack_list` is an iterable of attack names like ["DoS","Exploits"].
    """
    demo_rows = []
    for attack in attack_list:
        try:
            print(f"DEBUG: generate_demo_packets: processing attack -> '{attack}'")
        except Exception:
            pass
        tpl = UNSW_ATTACK_TEMPLATES.get(attack)
        # If there's no UNSW template but we have a richer per-label generator,
        # allow generation via `generate_demo_packet()` by using an empty tpl
        # fallback so downstream code can still map metadata fields.
        supported = {'DoS', 'Generic', 'Reconnaissance', 'Exploits', 'Fuzzers', 'Backdoor', 'Worms'}
        if tpl is None:
            if attack in supported:
                tpl = {'attack_cat': attack}
            else:
                # skip unknown attack types but continue
                continue
        for _ in range(count_per_attack):
            src = _rand_private_ip()
            dst = _rand_private_ip()
            # Use richer per-label generator when available so generated examples
            # better match the model's training distribution. Falls back to the
            # conservative UNSW template values if generator fails.
            try:
                supported = {'DoS', 'Generic', 'Reconnaissance', 'Exploits', 'Fuzzers', 'Backdoor', 'Worms'}
                if attack in supported:
                    gen = generate_demo_packet(attack, model_columns=expected_features, use_tuned=use_tuned, use_anchor=use_anchor)
                    gen['injected_attack_label'] = tpl.get('attack_cat')
                    gen['timestamp'] = str(datetime.now())
                    # ensure src/dst in case generator set different private ranges
                    gen['src_ip'] = src
                    gen['dst_ip'] = dst
                    # map top-level protocol/service/state from the template when available
                    if 'protocol' in tpl and 'protocol' not in gen:
                        gen['protocol'] = tpl.get('protocol')
                    if 'service' in tpl and 'service' not in gen:
                        gen['service'] = tpl.get('service')
                    if 'state' in tpl and 'state' not in gen:
                        gen['state'] = tpl.get('state')
                    try:
                        print(f"DEBUG: generate_demo_packets: appended generated row for attack '{attack}': keys={list(gen.keys())[:10]}")
                    except Exception:
                        pass
                    demo_rows.append(gen)
                    continue
            except Exception:
                # If enhanced generator fails for any reason, fall back to template-based row below
                pass

            row = {
                # Basic identification
                "src_ip": src,
                "dst_ip": dst,
                "protocol": tpl.get("protocol", "TCP"),
                "service": tpl.get("service", "unknown"),
                "state": tpl.get("state", "unknown"),
                # Byte / packet counters
                "sbytes": int(tpl.get("sbytes", 0) * (1 + (random.random() - 0.5) * 0.2)) ,
                "dbytes": int(tpl.get("dbytes", 0) * (1 + (random.random() - 0.5) * 0.2)) ,
                "spkts": int(tpl.get("spkts", 1) * (1 + (random.random() - 0.5) * 0.2)),
                "dpkts": int(tpl.get("dpkts", 1) * (1 + (random.random() - 0.5) * 0.2)),
                "dur": float(tpl.get("dur", 0.1) * (1 + (random.random() - 0.5) * 0.5)),
                "trans_depth": tpl.get("trans_depth", 0),
                "response_body_len": tpl.get("response_body_len", 0),
                # Additional numeric features commonly used by UNSW-style models
                "sttl": random.randint(30, 128),
                "dttl": random.randint(20, 128),
                "sload": float(max(0.0, tpl.get("sbytes", 0) / max(1.0, tpl.get("dur", 0.1)) * (1 + (random.random() - 0.5) * 0.2))),
                "dload": float(max(0.0, tpl.get("dbytes", 0) / max(1.0, tpl.get("dur", 0.1)) * (1 + (random.random() - 0.5) * 0.2))),
                "sloss": random.randint(0, 3),
                "dloss": random.randint(0, 3),
                "smean": float(max(1.0, tpl.get("sbytes", 0) / max(1, tpl.get("spkts", 1)))),
                "dmean": float(max(1.0, tpl.get("dbytes", 0) / max(1, tpl.get("dpkts", 1)))),
                "sjit": float(random.random() * 5.0),
                "djit": float(random.random() * 5.0),
                "swin": random.randint(0, 65535),
                "dwin": random.randint(0, 65535),
                "stcpb": int(max(0, tpl.get("sbytes", 0) // max(1, tpl.get("spkts", 1)))),
                "dtcpb": int(max(0, tpl.get("dbytes", 0) // max(1, tpl.get("dpkts", 1)))),
                "tcprtt": float(random.random() * 0.5),
                "synack": int(random.choice([0, 1])),
                "ackdat": int(random.choice([0, 1])),
                # Counters that the IDS uses
                "ct_src_ltm": random.randint(1, 50),
                "ct_srv_src": random.randint(0, 10),
                "ct_dst_ltm": random.randint(1, 40),
                "ct_srv_dst": random.randint(0, 10),
                "ct_dst_src_ltm": random.randint(0, 10),
                "ct_src_dport_ltm": random.randint(0, 10),
                "ct_dst_sport_ltm": random.randint(0, 10),
                # add explicit attack label for debugging (NOT used by model)
                "injected_attack_label": tpl.get("attack_cat"),
                # timestamp field
                "timestamp": str(datetime.now())
            }
            # jitter timing to simulate arrival times if requested
            if jitter:
                _time.sleep(0.01 * random.random())
            try:
                print(f"DEBUG: generate_demo_packets: appended template row for attack '{attack}'")
            except Exception:
                pass
            demo_rows.append(row)
    # Build DataFrames in a single-shot manner to avoid pandas fragmentation
    import pandas as _pd
    if expected_features:
        aligned = []
        # canonical meta fields we want preserved (UI/top-level)
        meta_keys = ('src_ip', 'dst_ip', 'protocol', 'service', 'state', 'timestamp', 'injected_attack_label')
        for r in demo_rows:
            # create a row dict that contains all expected features (fill missing with 0)
            row_full = {col: (r.get(col, 0) if r.get(col, None) is not None else 0) for col in expected_features}
            # attach metadata fields after the expected features (but don't duplicate columns)
            for m in meta_keys:
                if m in r and m not in row_full:
                    row_full[m] = r.get(m)
            # preserve original ordering: expected_features then meta (if not duplicates)
            cols_order = list(expected_features) + [m for m in meta_keys if (m in row_full and m not in expected_features)]
            try:
                df = _pd.DataFrame([row_full], columns=cols_order)
            except Exception:
                # fallback to generic DataFrame constructor
                df = _pd.DataFrame([row_full])
            aligned.append(df)
        try:
            print(f"DEBUG: generate_demo_packets: aligned rows count={len(aligned)}")
        except Exception:
            pass
        return aligned

    # no expected feature alignment requested: build small one-row DataFrames
    df_list = [_pd.DataFrame([r]) for r in demo_rows]
    try:
        print(f"DEBUG: generate_demo_packets: df_list rows count={len(df_list)}")
    except Exception:
        pass
    return df_list


def generate_demo_packet(attack_type="Normal", model_columns=None, use_tuned=False, use_anchor=False):
    """Generate a single demo packet (dict) with richer, class-specific patterns.

    If model_columns is provided, ensure all expected columns exist (filled with 0).
    """
    import random as _r

    # Base sensible defaults; explicitly include proto flags set to 0 so
    # the model receives consistent integer columns for proto_tcp/proto_udp/proto_icmp.
    base = {
        "dur": _r.uniform(0.01, 120.0),
        "spkts": _r.randint(1, 200),
        "dpkts": _r.randint(1, 200),
        "sbytes": _r.randint(40, 10000),
        "dbytes": _r.randint(40, 5000),
        "rate": _r.uniform(0.1, 100.0),
        "sinpkt": _r.uniform(0.1, 10.0),
        "dinpkt": _r.uniform(0.1, 10.0),
        "sttl": _r.randint(30, 255),
        "dttl": _r.randint(30, 255),
        "sload": _r.uniform(10.0, 5000.0),
        "dload": _r.uniform(10.0, 2000.0),
        "sjit": _r.uniform(0.0, 5.0),
        "djit": _r.uniform(0.0, 5.0),
        "swin": _r.randint(1000, 65000),
        "dwin": _r.randint(1000, 65000),
        # Ensure explicit one-hot proto flags exist and default to 0.
        "proto_tcp": 0,
        "proto_udp": 0,
        "proto_icmp": 0,
    }

    t = attack_type or "Normal"
    t = str(t)
    # Tuned anchors discovered by randomized search (do not overwrite default ranges)
    # Use module-level anchors (possibly loaded from anchors.json)
    try:
        anchors = ANCHORS
    except Exception:
        anchors = DEFAULT_ANCHORS

    # If exact anchor mode requested and we have an anchor, return the anchor row deterministically
    if use_anchor and t in anchors:
        anchor = anchors[t]
        # build exact anchor row (minimal additional metadata)
        base.update({
            'spkts': int(max(1, int(anchor.get('spkts', base['spkts'])))),
            'sbytes': int(max(0, int(anchor.get('sbytes', base['sbytes'])))),
            'rate': float(anchor.get('rate', base['rate'])),
            'sinpkt': float(anchor.get('sinpkt', base['sinpkt'])),
        })
        if anchor.get('proto', '').upper() == 'UDP':
            base.update({'proto_udp': 1, 'proto_tcp': 0, 'proto_icmp': 0, 'protocol': 'UDP'})
        else:
            base.update({'proto_tcp': 1, 'proto_udp': 0, 'proto_icmp': 0, 'protocol': 'TCP'})
        base['src_ip'] = f"192.168.{_r.randint(0,255)}.{_r.randint(1,254)}"
        base['dst_ip'] = f"10.0.{_r.randint(0,255)}.{_r.randint(1,254)}"
        if model_columns:
            try:
                for c in model_columns:
                    if c not in base:
                        base[c] = 0
            except Exception:
                pass
        return base

    # If tuned mode requested and we have an anchor, sample narrowly around it (previous behavior)
    if use_tuned and t in anchors:
        anchor = anchors[t]
        # sample narrow normal-like variation around anchor
        base.update({
            'spkts': int(max(1, int(anchor['spkts'] * random.uniform(0.8, 1.25)))),
            'sbytes': int(max(0, int(anchor['sbytes'] * random.uniform(0.85, 1.15)))),
            'rate': float(anchor['rate'] * random.uniform(0.8, 1.25)),
            'sinpkt': float(anchor['sinpkt'] * random.uniform(0.8, 1.25)),
        })
        # set proto hints similar to anchor discoveries
        if t == 'Fuzzers':
            base.update({'proto_udp': 1, 'proto_tcp': 0, 'proto_icmp': 0, 'protocol': 'UDP'})
        else:
            base.update({'proto_tcp': 1, 'proto_udp': 0, 'proto_icmp': 0, 'protocol': 'TCP'})
        # ensure metadata and return early
        base['src_ip'] = f"192.168.{_r.randint(0,255)}.{_r.randint(1,254)}"
        base['dst_ip'] = f"10.0.{_r.randint(0,255)}.{_r.randint(1,254)}"
        if model_columns:
            try:
                for c in model_columns:
                    if c not in base:
                        base[c] = 0
            except Exception:
                pass
        return base
    # Class-specific signatures (conservative ranges)
    if t == "DoS":
        base.update({
            "spkts": _r.randint(2000, 20000),
            "sbytes": _r.randint(50000, 800000),
            "rate": _r.uniform(200.0, 2000.0),
            "sinpkt": _r.uniform(0.0, 0.1),
            # DoS should strongly indicate TCP/ICMP at high scale
            "proto_tcp": 1,
            "proto_udp": 0,
            "proto_icmp": 1 if _r.random() < 0.25 else 0,
            "protocol": "ICMP" if _r.random() < 0.25 else "TCP",
        })
    elif t == "Generic":
        base.update({
            # Generic traffic should be moderate and not overlap DoS ranges
            "spkts": _r.randint(3, 300),
            "sbytes": _r.randint(100, 8000),
            "dbytes": _r.randint(40, 2000),
            "rate": _r.uniform(0.05, 60.0),
            "proto_tcp": 0,
            "proto_udp": 1,
            "proto_icmp": 0,
            "protocol": "UDP",
        })
    elif t == "Reconnaissance":
        base.update({
            # Reconnaissance (scanning) is low-volume but may have many small probes
            "spkts": _r.randint(1, 60),
            "dpkts": _r.randint(1, 10),
            "rate": _r.uniform(0.01, 10.0),
            "proto_tcp": 0,
            "proto_udp": 0,
            "proto_icmp": 1,
            "protocol": "ICMP",
        })
    elif t == "Exploits":
        base.update({
            # Exploits tend to be more targeted: moderate packets and suspicious payloads
            "spkts": _r.randint(5, 250),
            "sbytes": _r.randint(200, 30000),
            "dbytes": _r.randint(40, 15000),
            "rate": _r.uniform(0.1, 120.0),
            "proto_tcp": 1,
            "proto_udp": 0,
            "proto_icmp": 0,
            "protocol": "TCP",
        })
    elif t == "Fuzzers":
        base.update({
            # Fuzzers often generate many malformed/varied packets but not necessarily at DoS scale
            # Keep fuzzers below DoS magnitude and bias toward UDP/top-of-protocol-one-hot
            "spkts": _r.randint(10, 200),
            "sbytes": _r.randint(100, 15000),
            "dbytes": _r.randint(40, 4000),
            "rate": _r.uniform(0.1, 80.0),
            "proto_tcp": 0,
            "proto_udp": 1,
            "proto_icmp": 0,
            "protocol": "UDP",
        })
    elif t == "Backdoor":
        base.update({
            # Backdoor traffic is typically lower-rate, long-lived
            "spkts": _r.randint(3, 200),
            "sbytes": _r.randint(200, 40000),
            "rate": _r.uniform(0.001, 25.0),
            "proto_tcp": 1,
            "proto_udp": 0,
            "proto_icmp": 0,
            "protocol": "TCP",
        })
    elif t == "Worms":
        base.update({
            # Worms may have larger spread but still often distinguishable from high-rate DoS
            "spkts": _r.randint(50, 800),
            "sbytes": _r.randint(500, 30000),
            "rate": _r.uniform(1.0, 200.0),
            "proto_tcp": 1,
            "proto_udp": 0,
            "proto_icmp": 0,
            "protocol": "TCP",
        })

    # Network metadata
    base["src_ip"] = f"192.168.{_r.randint(0,255)}.{_r.randint(1,254)}"
    base["dst_ip"] = f"10.0.{_r.randint(0,255)}.{_r.randint(1,254)}"
    # If branch hasn't set a protocol, choose a sensible default based on proto flags
    if 'protocol' not in base:
        if base.get('proto_icmp', 0):
            base['protocol'] = 'ICMP'
        elif base.get('proto_udp', 0):
            base['protocol'] = 'UDP'
        else:
            base['protocol'] = 'TCP'

    # Ensure expected/model columns exist (fill zeros)
    if model_columns:
        try:
            for c in model_columns:
                if c not in base:
                    base[c] = 0
        except Exception:
            pass

    return base



def _get_feature_value(features, keys, default=None):
    """Return the first present, non-empty value for a list of candidate keys.

    Supports dict-like, pandas.DataFrame, and pandas.Series inputs.
    """
    try:
        # dict-like lookup
        if isinstance(features, dict):
            for k in keys:
                if k in features and features[k] not in (None, "", []):
                    return features[k]

        # pandas DataFrame
        if isinstance(features, pd.DataFrame):
            for k in keys:
                if k in features.columns:
                    val = features.get(k)
                    # Series -> take first element
                    if hasattr(val, 'iloc'):
                        try:
                            v = val.iloc[0]
                        except Exception:
                            v = default
                    else:
                        v = val
                    if v not in (None, ""):
                        return v

        # pandas Series
        if isinstance(features, pd.Series):
            for k in keys:
                if k in features.index:
                    v = features.get(k)
                    if v not in (None, ""):
                        return v

        # Fallback: attribute access
        for k in keys:
            if hasattr(features, k):
                v = getattr(features, k)
                if v not in (None, ""):
                    return v
    except Exception:
        pass
    return default


def _align_feature_names(df, expected_features):
    """Apply common alias renames so generated demo columns map to expected model features.

    df is a pandas DataFrame (one row). expected_features is an iterable of canonical names.
    """
    try:
        import pandas as _pd
    except Exception:
        return df
    if not isinstance(df, _pd.DataFrame):
        return df
    rename_map = {}
    alias_pairs = [
        ('protocol', 'proto'),
        ('service', 'svc'),
        ('src_ip', 'srcip'),
        ('dst_ip', 'dstip'),
        ('bytes_sent', 'sbytes'),
        ('bytes', 'sbytes'),
        ('bytes_received', 'dbytes'),
        ('spkts', 'spkts'),
        ('dpkts', 'dpkts'),
        ('trans_depth', 'trans_depth'),
        ('response_body_len', 'response_body_len'),
        ('sttl', 'sttl'),
        ('dttl', 'dttl'),
        ('sload', 'sload'),
        ('dload', 'dload'),
        ('ct_src_ltm', 'ct_src_ltm'),
        ('ct_dst_ltm', 'ct_dst_ltm'),
        ('ct_srv_src', 'ct_srv_src'),
        ('ct_srv_dst', 'ct_srv_dst'),
    ]
    for src, canon in alias_pairs:
        if canon in expected_features and src in df.columns and canon not in df.columns:
            rename_map[src] = canon
    if 'proto' in expected_features and 'protocol' in df.columns and 'proto' not in df.columns:
        rename_map['protocol'] = 'proto'
    if rename_map:
        try:
            df = df.rename(columns=rename_map)
        except Exception:
            pass
    return df


def process_packet(features_df, model, le, expected_features, scaler, args, index,
                   summarize_fn=summarize_alert, log_fn=log_alert,
                   sms_fn=send_sms_alert, whatsapp_fn=send_whatsapp_alert):
    """Process a single packet's features and perform prediction, logging, and alerting.

    Returns a dict with results for testing/inspection.
    """
    result = {
        'index': index,
        'attack_type': None,
        'is_attack': False,
        'explanation': None,
        'severity': None,
        'confidence': None,
    }

    # Align common alias names so demo/test DataFrame columns map to expected features
    try:
        features_df = _align_feature_names(features_df, expected_features)
    except Exception:
        pass

    pred_df = features_df.select_dtypes(include=[int, float])
    pred_df = pred_df.reindex(columns=expected_features, fill_value=0)

    # ==== DEBUG SNIPPET BEGIN ====
    # Print a quick debug summary of feature columns to detect mismatch
    try:
        print("DEBUG: pred_df.shape:", pred_df.shape)
        print("DEBUG: pred_df.columns (first 40):", list(pred_df.columns)[:40])
    except Exception:
        pass
    # ==== DEBUG SNIPPET END ====

    # Apply scaler if available
    if scaler:
        try:
            if hasattr(scaler, 'feature_names_in_'):
                expected_order = list(scaler.feature_names_in_)
                pred_df = pred_df.reindex(columns=expected_order, fill_value=0)
            X_input = scaler.transform(pred_df)
        except Exception as e:
            print(f"Warning: scaler transform failed: {e}. Using raw features.")
            X_input = pred_df.values
    else:
        X_input = pred_df.values

    # Optional debugging: print feature vector and model probabilities when requested
    try:
        debug_pred_flag = bool(getattr(args, 'debug_pred', False))
    except Exception:
        debug_pred_flag = False
    if debug_pred_flag:
        try:
            print("DEBUG-PRED: pred_df sample:\n", pred_df.head(1).to_dict(orient='records'))
            print("DEBUG-PRED: pred_df sums (first 20 cols):", pred_df.sum().iloc[:20].to_dict())
            if hasattr(model, 'classes_'):
                print("DEBUG-PRED: model.classes_:", list(model.classes_))
            # try to get class probabilities
            if hasattr(model, 'predict_proba'):
                try:
                    probs = model.predict_proba(X_input)[0]
                    # pair class->prob via label encoder
                    classes = list(model.classes_)
                    # map to human labels via le
                    try:
                        human = le.inverse_transform(classes)
                    except Exception:
                        human = classes
                    prob_map = {str(h): float(p) for h, p in zip(human, probs)}
                    print("DEBUG-PRED: class probabilities:", prob_map)
                except Exception as e:
                    print("DEBUG-PRED: predict_proba failed:", e)
            else:
                print("DEBUG-PRED: model has no predict_proba()")
        except Exception as e:
            print("DEBUG-PRED: debug printing failed:", e)

    # Allow demo-mode forced labels to bypass model prediction when requested
    forced_label = None
    try:
        forced_label = _get_feature_value(features_df, ['injected_attack_label', 'attack_cat'], None)
    except Exception:
        forced_label = None

    if getattr(args, 'demo_force', False) and forced_label:
        # DEMO-FORCE: display the injected demo label to the UI, but still
        # run the model so we can log the model's true prediction for analytics.
        try:
            # attempt to get model prediction and probabilities
            if hasattr(model, 'predict'):
                pred_class = model.predict(X_input)[0]
            else:
                pred_class = -1
            model_pred_label = None
            prob_map = {}
            if hasattr(model, 'predict_proba'):
                try:
                    probs = model.predict_proba(X_input)[0]
                    classes = list(model.classes_)
                    try:
                        human = le.inverse_transform(classes)
                    except Exception:
                        human = classes
                    prob_map = {str(h): float(p) for h, p in zip(human, probs)}
                    model_pred_label = max(prob_map.items(), key=lambda kv: kv[1])[0]
                except Exception:
                    prob_map = {}
            else:
                try:
                    model_pred_label = le.inverse_transform([pred_class])[0]
                except Exception:
                    model_pred_label = str(pred_class)
        except Exception:
            pred_class = -1
            model_pred_label = None
            prob_map = {}

        # Optionally override the model prediction/probabilities for demo presentation
        if getattr(args, 'demo_override_model', False):
            try:
                model_pred_label = forced_label
                prob_map = {str(model_pred_label): 1.0}
            except Exception:
                model_pred_label = forced_label
                prob_map = {forced_label: 1.0}

        # Use the injected demo label for UI/display
        attack_type = forced_label
        result['attack_type'] = attack_type
        # Store model prediction info in the result for test/inspection
        result['model_prediction'] = model_pred_label
        result['model_probabilities'] = prob_map
        print(f"Packet {index+1}: Forced demo attack type (display) : {attack_type}; model predicted: {model_pred_label}")
    else:
        # Predict attack type using the model
        pred_class = model.predict(X_input)[0]
        try:
            attack_type = le.inverse_transform([pred_class])[0]
        except Exception:
            attack_type = str(pred_class)
        result['attack_type'] = attack_type
        print(f"Packet {index+1}: Detected attack type: {attack_type}")

    if attack_type != "Normal":
        result['is_attack'] = True

        # Build alert details for Gemini (normalize alternate column names)
        alert_details = {
            "timestamp": str(datetime.now()),
            "attack_cat": attack_type,
            "src_ip": _get_feature_value(features_df, ['src_ip', 'srcip', 'source', 'src'], 'unknown'),
            "dst_ip": _get_feature_value(features_df, ['dst_ip', 'dstip', 'destination', 'dst'], 'unknown'),
            "protocol": _get_feature_value(features_df, ['protocol', 'proto', 'transport'], 'unknown'),
            "sbytes": int(_get_feature_value(features_df, ['sbytes', 'bytes_sent', 'bytes'], 0) or 0),
            "dbytes": int(_get_feature_value(features_df, ['dbytes', 'bytes_received', 'dbytes', 'bytes_rcvd'], 0) or 0),
            "state": _get_feature_value(features_df, ['state'], 'unknown'),
        }

        # Default values
        explanation = ''
        severity = 'Unknown'
        confidence = 0
        recommended_action = ''
        rules = {}

        # Debug: print alert_details before calling Gemini to diagnose missing fields
        try:
            print("ALERT BEFORE GEMINI:", alert_details)
        except Exception:
            pass

        # Get Gemini summary, passing raw features so GeminiSummary carries them
        # allow summarize_fn to be a no-op or mock for simulator high-rate tests
        if not args.test:
            try:
                alert_summary_obj = summarize_fn(alert_details, raw_features=features_df)
            except TypeError:
                # older signatures of summarize_fn may accept only alert_details
                alert_summary_obj = summarize_fn(alert_details)
            # The summarize function may return either an AlertSummary object or a dict
            try:
                if isinstance(alert_summary_obj, dict):
                    explanation = alert_summary_obj.get('explanation') or ''
                    severity = alert_summary_obj.get('severity') or 'Unknown'
                    confidence = int(alert_summary_obj.get('confidence') or 0)
                    recommended_action = alert_summary_obj.get('recommended_action') or ''
                    rules = {'text': recommended_action} if recommended_action else {}
                else:
                    explanation = getattr(alert_summary_obj, 'summary', '') or ''
                    severity = getattr(alert_summary_obj, 'severity', 'Unknown') or 'Unknown'
                    confidence = int(getattr(alert_summary_obj, 'confidence', 0) or 0)
                    rules = getattr(alert_summary_obj, 'rules', {}) or {}
                    recommended_action = rules.get('text') if isinstance(rules, dict) and rules.get('text') else ''
            except Exception:
                explanation = ''
                severity = 'Unknown'
                confidence = 0
                rules = {}
                recommended_action = ''
            print(f"Gemini Summary [Severity: {severity}, Confidence: {confidence}%]:\n{explanation}\n")
        else:
            explanation = "Test mode: Skipping Gemini API call."
            severity = "N/A"
            confidence = 0
            rules = {}
            recommended_action = ''
            print("Gemini Summary: Test mode - simulated summary.\n")

        # Prefer raw_features from Gemini summary if available
        raw_for_log = alert_summary_obj.raw_features if (locals().get('alert_summary_obj') is not None and getattr(alert_summary_obj, 'raw_features', None) is not None) else features_df

        # Log alert to MongoDB (raw_for_log may be DataFrame or dict)
        # Embed model prediction and probability map inside the logged payload so
        # the existing `log_alert` signature is not disturbed.
        pred_list = [pred_class] if pred_class is not None else []

        try:
            log_payload = raw_for_log
            # If it's a DataFrame, convert to a dict for logging and attach model info
            try:
                import pandas as _pd
                if isinstance(raw_for_log, _pd.DataFrame):
                    records = raw_for_log.to_dict(orient='records')
                    log_payload = records[0] if records else {}
            except Exception:
                # not a DataFrame or pandas not available; leave as-is
                pass

            # attach model metadata if present
            try:
                if result.get('model_prediction') is not None:
                    log_payload = dict(log_payload) if isinstance(log_payload, dict) else {'raw': log_payload}
                    log_payload['_model_prediction'] = result.get('model_prediction')
                if result.get('model_probabilities'):
                    log_payload = dict(log_payload) if isinstance(log_payload, dict) else {'raw': log_payload}
                    log_payload['_model_probabilities'] = result.get('model_probabilities')
            except Exception:
                pass

            log_fn(log_payload, pred_list, explanation, attack_type=attack_type, gemini_rules=rules, severity=severity, gemini_recommendation=recommended_action, confidence=confidence)
        except TypeError:
            # Fallback: call log_fn without model metadata if signature mismatches
            try:
                log_fn(raw_for_log, pred_list, explanation, attack_type=attack_type, gemini_rules=rules, severity=severity, gemini_recommendation=recommended_action, confidence=confidence)
            except Exception:
                print('Failed to log alert to MongoDB (unexpected signature).')

        # Send notifications
        if not args.test:
            sms_message = (
                f"IDS Alert: {attack_type}\n"
                f"Severity: {severity}\n"
                f"Src: {alert_details['src_ip']}"
            )
            whatsapp_message = (
                f"⚠️ Intrusion Detected! ⚠️\n"
                f"Severity: {severity} ({confidence}% confidence)\n"
                f"Type: {attack_type}\n"
                f"Src: {alert_details['src_ip']} -> Dst: {alert_details['dst_ip']}\n\n"
                f"--- Analysis (Summary) ---\n"
                f"{(explanation[:1300] + '...') if len(explanation) > 1300 else explanation}"
            )
            sms_fn(sms_message, severity=severity)
            whatsapp_fn(whatsapp_message, severity=severity)

        result.update({'explanation': explanation, 'severity': severity, 'confidence': confidence})

    return result


def process_feature_row(row: dict, model=None, le=None, expected_features=None, scaler=None, test_mode=True):
    """Adapter for the simulator to call inference in-process using a feature dict.

    Returns the same dict-like inference result as `process_packet`.
    If model/le/expected_features are not provided, the function will attempt to
    load them from disk (matching the behavior in main()).
    """
    # Convert the flat row into a one-row DataFrame expected by process_packet
    import pandas as pd
    class SimpleArgs:
        def __init__(self, test):
            self.test = test

    if model is None or le is None or expected_features is None:
        try:
            model = joblib.load('xgboost_model_multi.pkl')
            le = joblib.load('label_encoder.pkl')
            expected_features = joblib.load('feature_columns.pkl')
        except Exception as e:
            raise RuntimeError(f'Model artifacts missing for in-process inference: {e}')
    # create a DataFrame with one row
    df = pd.DataFrame([row])
    args = SimpleArgs(test=test_mode)
    # Use mock summarize when simulator requests it by providing a simple summarize_fn
    # The default summarize_alert will be used unless caller overrides.
    return process_packet(df, model, le, expected_features, scaler, args, 0)


def main():
    # setup rotating file logging
    os.makedirs('logs', exist_ok=True)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler('logs/ids.log', maxBytes=5*1024*1024, backupCount=3)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # shutdown flag used by signal handlers
    shutdown_event = threading.Event()

    def _handle_signal(signum, frame):
        print(f"Received signal {signum}, initiating graceful shutdown...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # Set up argument parser
    parser = argparse.ArgumentParser(description="AI-based Intrusion Detection System")
    parser.add_argument('--interface', type=str, help="Network interface to capture packets from (e.g., 'Wi-Fi').")
    parser.add_argument('--test', action='store_true', help="Run in test mode with dummy data.")
    parser.add_argument('--packets', type=int, default=10, help="Number of packets to capture in live mode.")
    parser.add_argument('--demo-attacks', type=str, default='', help="Comma-separated demo attacks to inject (e.g. 'DoS,Exploits').")
    parser.add_argument('--debug-pred', action='store_true', help='Print debug info for model predictions and feature vectors')
    parser.add_argument('--demo-force', action='store_true', help='When running demo mode, force the injected demo label (injected_attack_label) to be used instead of model prediction')
    parser.add_argument('--demo-override-model', action='store_true', help='When running demo mode with --demo-force, also override the model prediction/probabilities in logs to match the injected label (useful for demos)')
    parser.add_argument('--demo-tune', action='store_true', help='Use tuned sample anchors for demo generation (narrow sampling around discovered anchors)')
    parser.add_argument('--demo-anchor', action='store_true', help='Use exact tuned anchors (deterministic) for supported demo labels')
    parser.add_argument('--seed', type=int, default=None, help='Optional seed to make demo generation deterministic')
    parser.add_argument('--wait-for-start', action='store_true', help='If set, wait for an external start signal before beginning capture/processing (creates a hold state)')
    args = parser.parse_args()

    # Load the trained XGBoost model
    try:
        model = joblib.load('xgboost_model_multi.pkl')
        le = joblib.load('label_encoder.pkl')
        expected_features = joblib.load('feature_columns.pkl')
        print("Loaded feature_columns.pkl for expected feature ordering.")
        try:
            scaler = joblib.load('scaler.pkl')
            print("Scaler loaded successfully.")
        except Exception:
            scaler = None
        print("Model and encoder loaded successfully!")
    except FileNotFoundError:
        print("Error: Model file 'xgboost_model_multi.pkl' or 'label_encoder.pkl' not found. Please run train_model.py first.")
        return

    # Demo attacks support: if provided, mark demo_mode and defer generation until after model/feature_columns loaded
    demo_attack_arg = args.demo_attacks.strip() if getattr(args, 'demo_attacks', None) else ''
    demo_mode = False
    demo_attacks = []
    per_attack = 1
    if demo_attack_arg:
        demo_mode = True
        demo_attacks = [a.strip() for a in demo_attack_arg.split(',') if a.strip()]
        total_requested = args.packets or 10
        per_attack = max(1, total_requested // max(1, len(demo_attacks)))
        print(f"Demo mode enabled: will generate {per_attack} rows per attack for: {demo_attacks}")
    else:
        if args.test:
            # Dummy packets for testing
            dummy_features = [
                # ... (dummy data remains the same)
            ]
            packets = [pd.DataFrame([f]) for f in dummy_features]
            print("Using dummy packets for testing.")
        else:
            if not args.interface:
                print("Error: --interface is required for live capture mode.")
                return
            # If the caller requested to wait for an external start signal, block here
            # until the flag file is created. This allows the backend/dashboard to
            # start the IDS process but delay processing until the user explicitly
            # enables capture (e.g., via a dashboard button that creates the flag).
            if getattr(args, 'wait_for_start', False):
                try:
                    from pathlib import Path as _Path
                    flag = _Path('capture_enabled.flag')
                    print('Waiting for external start signal (create capture_enabled.flag to begin)...')
                    # Poll for the flag file; user action (dashboard) should create it
                    while not flag.exists():
                        if shutdown_event.is_set():
                            print('Shutdown requested while waiting for start signal.')
                            return
                        _time.sleep(0.5)
                    print('Start signal detected; proceeding to capture.')
                except Exception:
                    # If waiting fails for any reason, proceed normally to avoid deadlocks
                    pass
            # capture_packets is a generator now; it yields packets as they arrive.
            packets = capture_packets(args.interface, args.packets)

    # If demo_mode was requested, now that we have loaded expected_features fill/generate demo packets aligned to model
    if demo_mode:
        try:
            # set RNG seed for reproducibility if requested
            if getattr(args, 'seed', None) is not None:
                try:
                    import numpy as _np
                    random.seed(args.seed)
                    _np.random.seed(int(args.seed))
                except Exception:
                    random.seed(args.seed)

            packets = generate_demo_packets(demo_attacks, count_per_attack=per_attack, expected_features=expected_features, use_tuned=getattr(args, 'demo_tune', False), use_anchor=getattr(args, 'demo_anchor', False))
            print(f"Generated {len(packets)} demo packets aligned to model features.")
        except Exception as e:
            print(f"Failed to generate demo packets aligned to features: {e}")

    # Perform inference on each packet (refactored to use AlertSummary)
    normal_count = 0
    attack_count = 0

    # Process packets from either a generator or a list
    i = 0
    for i, pkt in enumerate(packets):
        try:
            if shutdown_event.is_set():
                print("Shutdown requested — stopping capture loop before processing new packet.")
                break

            # Extract features
            if args.test or demo_mode:
                # pkt is already a DataFrame of features (test or demo)
                features_df = pkt
            else:
                try:
                    features_df = extract_features(pkt)
                except Exception:
                    # Best-effort: if pkt is a capture object with close(), try to close it
                    try:
                        close_fn = getattr(pkt, 'close', None)
                        if callable(close_fn):
                            close_fn()
                    except Exception:
                        pass
                    raise

            # inject lightweight flow counters (ct_src_ltm, ct_srv_src, ct_dst_ltm)
            try:
                src_ip = features_df.get('src_ip', pd.Series(['unknown'])).iloc[0]
                dst_ip = features_df.get('dst_ip', pd.Series(['unknown'])).iloc[0]
            except Exception:
                src_ip = 'unknown'
                dst_ip = 'unknown'
            try:
                tick_packet(src_ip, dst_ip)
                counts = get_packet_counts(src_ip, dst_ip)
                for k, v in counts.items():
                    features_df[k] = v
            except Exception:
                # non-fatal, continue
                pass

            # Process packet using the shared function
            res = process_packet(features_df, model, le, expected_features, scaler, args, i)
            if res.get('is_attack'):
                attack_count += 1
            else:
                normal_count += 1

        except Exception as e:
            print(f"Error processing packet {i+1}: {e}")

    if shutdown_event.is_set():
        print("Graceful shutdown: waiting for current operations to complete and exiting.")
    # Perform explicit cleanup
    try:
        gemini_shutdown()
    except Exception:
        pass

    print(f"\nSummary: {normal_count} Normal, {attack_count} Attacks detected out of {len(packets)} packets.")


if __name__ == "__main__":
    main()