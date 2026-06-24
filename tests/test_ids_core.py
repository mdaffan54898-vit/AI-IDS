import json
import os
from types import SimpleNamespace
import pandas as pd
import numpy as np
import pytest
import sys
from pathlib import Path

# ensure project root is importable when pytest runs from different CWDs
proj_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(proj_root))

from ids_inference import save_anchors, ANCHORS, generate_demo_packets, process_packet


def test_anchor_load_and_backup(tmp_path):
    # Use a temp path to avoid touching repo anchors
    p = tmp_path / "anchors.json"
    anchors_a = {"A": {"spkts": 1}}
    # first save creates file
    save_anchors(anchors_a, path=str(p))
    assert p.exists()
    # second save should create a .json.bak alongside it
    anchors_b = {"A": {"spkts": 2}}
    save_anchors(anchors_b, path=str(p))
    bak = p.with_suffix('.json.bak')
    assert bak.exists()
    # content should match latest saved anchors
    with p.open('r', encoding='utf-8') as fh:
        data = json.load(fh)
    assert data.get('A', {}).get('spkts') == 2


def test_inference_output_fields():
    # Mock a tiny model that predicts a non-Normal label index 1 -> 'Exploits'
    class DummyModel:
        classes_ = np.array([1])
        def predict(self, X):
            return np.array([1])
        def predict_proba(self, X):
            return np.array([[0.0, 1.0]])

    class DummyLE:
        def inverse_transform(self, arr):
            # map index 1 -> 'Exploits'
            return np.array(['Exploits' if a == 1 else 'Normal' for a in arr])

    expected_features = ['spkts', 'sbytes', 'dpkts', 'dur']
    # build a DataFrame row with required numeric features
    row = {'spkts': 10, 'sbytes': 2000, 'dpkts': 2, 'dur': 0.5, 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2'}
    df = pd.DataFrame([row])

    # args object
    args = SimpleNamespace(test=False, debug_pred=False, demo_force=False)

    # capture log payload
    logged = []
    def fake_log(payload, pred_list, explanation, **kwargs):
        logged.append((payload, pred_list, explanation, kwargs))

    def fake_summarize(details, raw_features=None):
        return {'explanation': 'ok', 'severity': 'High', 'confidence': 90, 'recommended_action': 'do'}

    res = process_packet(df, DummyModel(), DummyLE(), expected_features, scaler=None, args=args, index=0, summarize_fn=fake_summarize, log_fn=fake_log)

    assert 'attack_type' in res
    assert res['attack_type'] == 'Exploits'
    assert 'confidence' in res
    # ensure log_fn was called and payload contains src/dst
    assert len(logged) == 1
    payload = logged[0][0]
    assert 'src_ip' in payload or (isinstance(payload, dict) and payload.get('src_ip') == '10.0.0.1')


def test_demo_attack_alignment():
    expected_features = ['spkts', 'sbytes', 'dpkts', 'dur']
    packets = generate_demo_packets(['Exploits', 'Generic'], count_per_attack=1, expected_features=expected_features)
    # should return list of DataFrames
    assert isinstance(packets, list)
    assert len(packets) == 2
    for df in packets:
        assert isinstance(df, pd.DataFrame)
        # expected features should be present as columns
        for c in expected_features:
            assert c in df.columns
        # top-level metadata should be preserved
        assert any(k in df.columns for k in ('src_ip', 'dst_ip', 'protocol', 'injected_attack_label'))
