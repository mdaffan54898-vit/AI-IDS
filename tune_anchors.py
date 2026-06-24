"""Tune anchors for IDS demo generation.

Usage examples:
    python tune_anchors.py --label Fuzzers --trials 200 --threshold 0.7 --topk 3 --seed 42
    python tune_anchors.py --label Fuzzers --trials 2000 --threshold 0.7 --topk 5 --save

This script imports generator utilities from `ids_inference.py` so it shares the same
alignment and generation logic. It does NOT call Gemini or logging.
"""
import argparse
import random
import json
import heapq
from pprint import pprint

import joblib
import pandas as pd

# Import helper utilities from ids_inference
try:
    from ids_inference import generate_demo_packet, save_anchors, ANCHORS, DEFAULT_ANCHORS
except Exception:
    # If import fails, we will fallback to reading anchors.json directly later
    generate_demo_packet = None
    save_anchors = None
    ANCHORS = None
    DEFAULT_ANCHORS = None


def load_model_artifacts():
    try:
        model = joblib.load('xgboost_model_multi.pkl')
        le = joblib.load('label_encoder.pkl')
        expected = joblib.load('feature_columns.pkl')
    except Exception as e:
        raise RuntimeError(f"Failed to load model artifacts: {e}")
    scaler = None
    try:
        scaler = joblib.load('scaler.pkl')
    except Exception:
        scaler = None
    return model, le, expected, scaler


def row_to_X(row, expected_features, scaler):
    # Build DataFrame aligned to expected features and return array or transformed X
    df = pd.DataFrame([{c: row.get(c, 0) for c in expected_features}])
    if scaler:
        try:
            # respect scaler.feature_names_in_ ordering if present
            if hasattr(scaler, 'feature_names_in_'):
                df = df.reindex(columns=list(scaler.feature_names_in_), fill_value=0)
            X = scaler.transform(df)
        except Exception:
            X = df.values
    else:
        X = df.values
    return X


def human_prob_map(model, le, X):
    # returns dict human_label->probabilities for the first row in X
    if not hasattr(model, 'predict_proba'):
        return {}
    probs = model.predict_proba(X)[0]
    try:
        classes = list(model.classes_)
        try:
            human = list(le.inverse_transform(classes))
        except Exception:
            # If inverse_transform fails, attempt to map via casting
            human = [str(c) for c in classes]
        return {str(h): float(p) for h, p in zip(human, probs)}
    except Exception:
        # fallback: use index-based keys
        return {str(i): float(p) for i, p in enumerate(probs)}


def mutate_base(base, mutate_keys, mmin=0.6, mmax=1.6):
    """Return a mutated copy of `base` altering numeric keys by a random factor
    sampled uniformly from [mmin, mmax]."""
    r = base.copy()
    for k in mutate_keys:
        if k not in r:
            continue
        v = r[k]
        try:
            factor = random.uniform(mmin, mmax)
            if isinstance(v, int):
                r[k] = max(0, int(v * factor))
            elif isinstance(v, float):
                r[k] = float(max(0.0, v * factor))
            else:
                # leave non-numeric alone
                pass
        except Exception:
            pass
    return r


def tune_label(label, trials, threshold, topk, seed=None, auto_save=False, mutate_min=0.6, mutate_max=1.6, extra_keys_str=''):
    if seed is not None:
        random.seed(seed)

    model, le, expected, scaler = load_model_artifacts()

    # validate label string mapping
    try:
        human_classes = list(le.inverse_transform(model.classes_))
    except Exception:
        human_classes = [str(c) for c in model.classes_]

    if str(label) not in human_classes:
        print(f"Warning: label '{label}' not found among model classes: {human_classes}")

    # mutate keys to focus on
    candidate_keys = ['spkts', 'sbytes', 'rate', 'sinpkt', 'sload', 'dload']
    # include any user-specified extra keys (comma-separated)
    if extra_keys_str:
        try:
            extras = [k.strip() for k in extra_keys_str.split(',') if k.strip()]
            for k in extras:
                if k not in candidate_keys:
                    candidate_keys.append(k)
        except Exception:
            pass

    # maintain a min-heap of topk candidates (by probability)
    heap = []  # (prob, candidate_row)

    # base generator availability
    have_gen = generate_demo_packet is not None

    for i in range(trials):
        # get a base candidate
        if have_gen:
            try:
                base = generate_demo_packet(label, model_columns=expected)
            except Exception:
                base = {}
        else:
            base = {}
        # If generator didn't provide useful fields, use some defaults
        base.setdefault('spkts', 50)
        base.setdefault('sbytes', 1000)
        base.setdefault('rate', 10.0)
        base.setdefault('sinpkt', 1.0)
        base.setdefault('proto_udp', 1)
        base.setdefault('proto_tcp', 0)

        # choose 1..min(4, n_keys) keys to mutate
        kcount = random.randint(1, min(4, len(candidate_keys)))
        keys = random.sample(candidate_keys, kcount)
        cand = mutate_base(base, keys, mmin=mutate_min, mmax=mutate_max)

        # Build X and get prob map
        X = row_to_X(cand, expected, scaler)
        try:
            prob_map = human_prob_map(model, le, X)
        except Exception as e:
            # skip this trial on failure
            print(f"Trial {i+1}: predict_proba failed: {e}")
            continue

        prob = float(prob_map.get(str(label), 0.0))
        top_label = max(prob_map.items(), key=lambda kv: kv[1])[0] if prob_map else None

        # record candidate
        entry = {'trial': i, 'prob': prob, 'top_label': top_label, 'row': {k: cand.get(k) for k in cand}}

        if len(heap) < topk:
            heapq.heappush(heap, (prob, entry))
        else:
            if prob > heap[0][0]:
                heapq.heapreplace(heap, (prob, entry))

        if prob >= threshold and top_label == str(label):
            print(f"Found acceptable candidate on trial {i+1} with prob={prob:.3f}")
            pprint(entry)
            if auto_save:
                # persist minimal anchor fields
                anchors = ANCHORS if ANCHORS is not None else {}
                anchors = anchors.copy() if isinstance(anchors, dict) else {}
                anchors[str(label)] = {
                    'spkts': int(cand.get('spkts', 0)),
                    'sbytes': int(cand.get('sbytes', 0)),
                    'rate': float(cand.get('rate', 0.0)),
                    'sinpkt': float(cand.get('sinpkt', 0.0)),
                    'proto': 'UDP' if cand.get('proto_udp', 0) else 'TCP'
                }
                if save_anchors:
                    save_anchors(anchors)
                else:
                    # fallback write directly
                    try:
                        with open('anchors.json', 'w', encoding='utf-8') as fh:
                            json.dump(anchors, fh, indent=2)
                        print('Anchors saved to anchors.json')
                    except Exception as e:
                        print('Failed to save anchors:', e)
            # do not early-return; we still collect top-k for review

    # present top-k results sorted descending
    best = sorted(heap, key=lambda x: -x[0])
    print('\nTop candidates:')
    for prob, entry in best:
        print(f"prob={prob:.4f} top_label={entry['top_label']} trial={entry['trial']}")
        pprint(entry['row'])
        print('---')

    return best


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--label', type=str, required=True, help='Target label to tune anchors for (human label, e.g. "Fuzzers").')
    parser.add_argument('--trials', type=int, default=2000, help='Number of randomized trials to run.')
    parser.add_argument('--threshold', type=float, default=0.7, help='Minimum predict_proba for acceptance (0..1).')
    parser.add_argument('--topk', type=int, default=5, help='Keep top-k candidate rows by target probability.')
    parser.add_argument('--seed', type=int, default=None, help='Optional RNG seed for reproducibility')
    parser.add_argument('--save', action='store_true', help='Persist discovered anchors into anchors.json via save_anchors()')
    parser.add_argument('--mutate-min', type=float, default=0.6, help='Lower bound for multiplicative mutation factor (e.g. 0.4).')
    parser.add_argument('--mutate-max', type=float, default=1.6, help='Upper bound for multiplicative mutation factor (e.g. 2.5).')
    parser.add_argument('--extra-keys', type=str, default='', help='Comma-separated additional numeric feature keys to mutate (e.g. "dpkts,dbytes,dur").')
    args = parser.parse_args()

    best = tune_label(
        args.label,
        args.trials,
        args.threshold,
        args.topk,
        seed=args.seed,
        auto_save=args.save,
        mutate_min=args.mutate_min,
        mutate_max=args.mutate_max,
        extra_keys_str=args.extra_keys,
    )
    print('\nDone.')
