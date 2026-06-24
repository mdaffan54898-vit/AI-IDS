import time
import requests
from typing import Any, Dict
from simulator.config import cfg


def call_inference_inprocess(row: Dict[str, Any], mock: bool = False) -> Dict[str, Any]:
    """
    Try to call the local inference function if available as
    `ids_inference.process_feature_row`.

    `mock` controls whether the in-process call should run in test mode
    (which disables Gemini calls). Fall back to raising ImportError if not
    present.
    """
    try:
        import ids_inference as ids
        # expecting a helper function in ids_inference to accept raw dicts; fall
        # back to a packet wrapper if necessary
        if hasattr(ids, 'process_feature_row'):
            return ids.process_feature_row(row, test_mode=mock)
        raise ImportError('in-process inference function not found')
    except Exception:
        raise


def call_inference_http(url: str, row: Dict[str, Any]) -> Dict[str, Any]:
    headers = {'Content-Type': 'application/json'}
    for attempt in range(3):
        try:
            r = requests.post(url, json=row, headers=headers, timeout=10)
            r.raise_for_status()
            return r.json()
        except Exception:
            time.sleep(cfg.RETRY_BACKOFF_SECONDS * (attempt + 1))
    raise RuntimeError('Failed to call remote inference')


def infer(row: Dict[str, Any], mock: bool = False) -> Dict[str, Any]:
    """Infer using in-process adapter when available; otherwise fall back to DEV_INFER_URL.

    If `mock` is True, the in-process adapter will be invoked in test mode (skips Gemini).
    """
    # prefer in-process
    try:
        return call_inference_inprocess(row, mock=mock)
    except Exception:
        # If remote/dev inference URL is provided, try that next
        if cfg.DEV_INFER_URL:
            try:
                return call_inference_http(cfg.DEV_INFER_URL, row)
            except Exception:
                pass

        # Final fallback: create a deterministic simulated alert document directly
        # so simulator runs always generate DB entries with simulator metadata.
        try:
            from simulator.mock_gemini import summarize_for_simulator
            from mongo_logging import log_alert
            summary = summarize_for_simulator(row)
            # Build a minimal predictions list and call log_alert
            pred_class = [0]
            explanation = summary.get('explanation')
            gemini_rules = summary.get('rules') or {'text': summary.get('recommended_action')}
            gemini_recommendation = summary.get('recommended_action')
            severity = summary.get('severity')
            confidence = summary.get('confidence')
            # log_alert expects features (DataFrame/Series/dict) and will promote simulator fields
            res = log_alert(
                row,
                pred_class,
                explanation,
                attack_type=row.get('user_selected_attack'),
                gemini_rules=gemini_rules,
                severity=severity,
                gemini_recommendation=gemini_recommendation,
                confidence=confidence,
            )
            # return the logging result so callers can observe success/failure
            return {
                'status': 'simulated',
                'simulator_run_id': row.get('simulator_run_id'),
                'logged': bool(res),
            }
        except Exception:
            raise RuntimeError('Inference unavailable and fallback logging failed')
