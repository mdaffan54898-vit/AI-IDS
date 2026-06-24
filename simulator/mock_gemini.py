def _first(*vals):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        return v
    return None


def _extract_from_features(features, key_candidates):
    # features may be a list of dicts; try first element then fallback
    if not features:
        return None
    try:
        first = features[0]
        for k in key_candidates:
            if k in first and first.get(k) not in (None, '', ' '):
                return first.get(k)
    except Exception:
        pass
    return None


def summarize_for_simulator(row: dict) -> dict:
    """Return a deterministic summary dict for simulator test mode.

    Extracts best-effort src/dst/protocol/bytes from either top-level row fields
    or the nested `features` list so the UI shows concrete values.
    """
    features = row.get('features') or []
    # Prefer normalized top-level fields when present, then fall back to common aliases
    src = _first(
        row.get('src_ip'),
        row.get('src'),
        row.get('srcip'),
        _extract_from_features(features, ['src_ip', 'srcip', 'source', 'src'])
    )
    dst = _first(
        row.get('dst_ip'),
        row.get('dst'),
        row.get('dstip'),
        _extract_from_features(features, ['dst_ip', 'dstip', 'destination', 'dst'])
    )
    proto = _first(
        row.get('protocol'),
        row.get('transport'),
        _extract_from_features(features, ['protocol', 'proto', 'transport'])
    )
    bytes_sent = _first(
        row.get('bytes_sent'),
        row.get('sbytes'),
        row.get('bytes'),
        _extract_from_features(features, ['sbytes', 'bytes_sent', 'bytes'])
    )
    attack = _first(row.get('user_selected_attack'), row.get('attack_label'), 'Unknown')

    # coerce/format a couple of fields
    try:
        bytes_sent_val = int(bytes_sent) if bytes_sent not in (None, '') else None
    except Exception:
        bytes_sent_val = None

    rec = (
        f"Simulated mitigation for {attack}: isolate {src or '<unknown>'} "
        f"and investigate connections to {dst or '<unknown>'}."
    )
    expl = (
        f"Simulated analysis: synthetic alert generated for {attack} from "
        f"{src or '<unknown>'} -> {dst or '<unknown>'}. "
        f"Protocol: {proto or 'unknown'}. "
        f"Bytes: {bytes_sent_val if bytes_sent_val is not None else 'unknown'}."
    )

    # Mirror the keys the rest of the system expects for LLM outputs
    return {
        'gemini_explanation': expl,
        'gemini_recommendation': rec,
        'explanation': expl,
        'severity': 'Test',
        'confidence': 0,
        'recommended_action': rec,
        'rules': {'text': rec},
        'src_ip': src,
        'dst_ip': dst,
        'protocol': proto,
        'bytes_sent': bytes_sent_val,
    }
