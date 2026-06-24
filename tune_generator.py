"""Quick tuning helper: try amplifying numeric fields for a label and report model probabilities.

Usage: activate venv then run: python tune_generator.py

This script is for local tuning only and will not modify production code.
"""

import joblib
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


def amplify_and_score(label='Fuzzers', multipliers=(1,2,4,8,16,32)):
    model, le, feats, scaler = load_artifacts()
    print(f"Loaded model; will test label={label} multipliers={multipliers}")

    for m in multipliers:
        # generate base sample
        row = generate_demo_packet(label, model_columns=feats)
        # amplify a few numeric features commonly associated with fuzzing
        for k in ('spkts','sbytes','rate','sinpkt','sload'):
            if k in row:
                try:
                    row[k] = float(row[k]) * float(m)
                except Exception:
                    pass
        # ensure integer-ish fields are ints
        for k in ('spkts','dpkts'):
            if k in row:
                try:
                    row[k] = int(max(1, round(row[k])))
                except Exception:
                    pass
        # build DataFrame and align to expected features
        df = pd.DataFrame([row])
        # keep numeric only ordering similar to process_packet
        pred_df = df.select_dtypes(include=[int, float])
        pred_df = pred_df.reindex(columns=feats, fill_value=0)
        if scaler:
            try:
                if hasattr(scaler, 'feature_names_in_'):
                    pred_df = pred_df.reindex(columns=list(scaler.feature_names_in_), fill_value=0)
                X_input = scaler.transform(pred_df)
            except Exception as e:
                print(f"Scaler transform failed: {e}; using raw features")
                X_input = pred_df.values
        else:
            X_input = pred_df.values

        # get probabilities
        try:
            probs = model.predict_proba(X_input)[0]
            classes = list(model.classes_)
            try:
                human = le.inverse_transform(classes)
            except Exception:
                human = classes
            prob_map = {str(h): float(p) for h, p in zip(human, probs)}
            top_label = max(prob_map.items(), key=lambda x: x[1])
            print(f"mult={m}: top={top_label[0]} ({top_label[1]:.3f}) | {label} prob={prob_map.get(label,0):.4f}")
        except Exception as e:
            print(f"Failed to get predict_proba at multiplier {m}: {e}")

if __name__ == '__main__':
    amplify_and_score()
