"""Search for synthetic feature patterns that the model classifies as specific labels.

For each target label this script generates many random variants of a base
generated sample (using generate_demo_packet) and tracks the best candidate
that maximizes the model's probability for that label. If a top-1 match is
found, it reports the sample and stops searching for that label early.

Usage: python tune_labels_search.py
"""
import joblib
import random
import pandas as pd
from ids_inference import generate_demo_packet

MODEL_PATH = 'xgboost_model_multi.pkl'
LE_PATH = 'label_encoder.pkl'
FEAT_PATH = 'feature_columns.pkl'
SCALER_PATH = 'scaler.pkl'

def load_artifacts():
    model = joblib.load(MODEL_PATH)
    le = joblib.load(LE_PATH)
    feats = joblib.load(FEAT_PATH)
    try:
        scaler = joblib.load(SCALER_PATH)
    except Exception:
        scaler = None
    return model, le, feats, scaler


def score_row(row, feats, model, le, scaler):
    df = pd.DataFrame([row])
    pred_df = df.select_dtypes(include=[int, float])
    pred_df = pred_df.reindex(columns=feats, fill_value=0)
    if scaler:
        try:
            if hasattr(scaler, 'feature_names_in_'):
                pred_df = pred_df.reindex(columns=list(scaler.feature_names_in_), fill_value=0)
            X_input = scaler.transform(pred_df)
        except Exception:
            X_input = pred_df.values
    else:
        X_input = pred_df.values
    probs = model.predict_proba(X_input)[0]
    classes = list(model.classes_)
    try:
        human = le.inverse_transform(classes)
    except Exception:
        human = classes
    prob_map = {str(h): float(p) for h, p in zip(human, probs)}
    return prob_map


def search_for_label(label, model, le, feats, scaler, trials=2000):
    best_prob = 0.0
    best_row = None
    found_top1 = False
    for t in range(trials):
        row = generate_demo_packet(label, model_columns=feats)
        # random perturbations across fields that commonly affect classification
        # tune ranges conservatively per label
        # numeric fields
        row['spkts'] = int(max(1, random.randint(1, 5000)))
        row['sbytes'] = int(max(0, random.randint(40, 300000)))
        row['rate'] = float(random.uniform(0.01, 2500.0))
        row['sinpkt'] = float(random.uniform(0.0, 10.0))
        row['sload'] = float(max(0.0, row.get('sbytes', 0) / max(1.0, row.get('dur', 1.0))))
        # tweak some counters
        for c in ('ct_src_ltm','ct_srv_src','ct_dst_ltm','ct_srv_dst'):
            if c in row:
                row[c] = random.randint(0, 50)
        # randomly flip proto/service hints occasionally
        if random.random() < 0.15:
            row['proto_tcp'] = 1 - int(row.get('proto_tcp',0))
            row['proto_udp'] = 1 - int(row.get('proto_udp',0))
        # score
        try:
            prob_map = score_row(row, feats, model, le, scaler)
        except Exception:
            continue
        p = prob_map.get(label, 0.0)
        # check top-1
        top_label, top_prob = max(prob_map.items(), key=lambda x: x[1])
        if p > best_prob:
            best_prob = p
            best_row = (row.copy(), prob_map.copy())
        if top_label == label and top_prob > 0.0:
            found_top1 = True
            return True, (row.copy(), prob_map.copy())
    return found_top1, best_row


def main():
    model, le, feats, scaler = load_artifacts()
    labels = ['Exploits','Generic','Reconnaissance','Backdoor','Worms','Fuzzers']
    summary = {}
    for label in labels:
        print(f"Searching for label: {label} (this may take a while)")
        found, best = search_for_label(label, model, le, feats, scaler, trials=2000)
        if found:
            row, probs = best
            print(f"Found top-1 {label}! prob={probs.get(label):.4f}")
            print({k: row[k] for k in ('spkts','sbytes','rate','sinpkt') if k in row})
            summary[label] = {'found': True, 'prob': probs.get(label), 'sample': {k: row.get(k) for k in row}}
        else:
            if best is not None:
                row, probs = best
                print(f"No top-1 for {label}; best {label} prob={probs.get(label):.4f}")
                print({k: row[k] for k in ('spkts','sbytes','rate','sinpkt') if k in row})
                summary[label] = {'found': False, 'prob': probs.get(label), 'sample': {k: row.get(k) for k in row}}
            else:
                print(f"No candidates for {label}")
                summary[label] = {'found': False, 'prob': 0.0, 'sample': None}
    print("\nSearch summary:")
    for l, info in summary.items():
        print(f"{l}: found={info['found']}, top_prob={info['prob']}")

if __name__ == '__main__':
    main()
