"""Random search to find a generated sample that the model labels as a target class (Fuzzers).
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


def random_search(label='Fuzzers', trials=200):
    model, le, feats, scaler = load_artifacts()
    best = (None, 0.0, None)  # (row, fuzz_prob, probs)
    for t in range(trials):
        row = generate_demo_packet(label, model_columns=feats)
        # randomize targeted numeric fields across a wide range
        row['spkts'] = random.randint(1, 5000)
        row['sbytes'] = random.randint(40, 250000)
        row['rate'] = random.uniform(0.01, 2000.0)
        row['sinpkt'] = random.uniform(0.0, 10.0)
        row['sload'] = max(0.0, float(row.get('sbytes', 0)) / max(1.0, float(row.get('dur', 1.0))))
        # normalize/prepare df
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
        try:
            probs = model.predict_proba(X_input)[0]
            classes = list(model.classes_)
            try:
                human = le.inverse_transform(classes)
            except Exception:
                human = classes
            prob_map = {str(h): float(p) for h, p in zip(human, probs)}
            fuzz_prob = prob_map.get(label, 0.0)
            top_label = max(prob_map.items(), key=lambda x: x[1])
            if fuzz_prob > best[1]:
                best = (row.copy(), fuzz_prob, prob_map.copy())
            if top_label[0] == label:
                print(f"Found top-1 {label} at trial {t+1}: prob={fuzz_prob:.4f}")
                print("Sample:", {k: row[k] for k in ('spkts','sbytes','rate','sinpkt') if k in row})
                print("Prob map:", prob_map)
                return
        except Exception as e:
            # skip
            continue
    print("No top-1 found; best candidate:")
    if best[0] is not None:
        print(f"best fuzz_prob={best[1]:.4f}")
        print({k: best[0][k] for k in ('spkts','sbytes','rate','sinpkt') if k in best[0]})
        print(best[2])
    else:
        print("No valid candidates generated.")

if __name__ == '__main__':
    random_search(trials=200)
