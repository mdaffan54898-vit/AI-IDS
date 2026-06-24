import threading
import uuid
import time
from typing import Dict, Any, Optional
import random
from simulator.attack_catalog import load_catalog, get_by_label
from simulator.sampler import sample_row
from simulator.client import infer
from simulator.config import cfg

RUNS: Dict[str, Dict[str, Any]] = {}
RUN_LOCK = threading.Lock()


def start_run(
    attack_label: str,
    count: int,
    src_ip_template: str,
    mock_gemini: bool,
    simulator_user: str,
    run_id: Optional[str] = None,
) -> str:
    if cfg.SIMULATOR_SINGLE_INSTANCE:
        with RUN_LOCK:
            for r in RUNS.values():
                if r.get('status') == 'running':
                    raise RuntimeError('Another run is already active')
    rows = load_catalog()
    pool = get_by_label(rows, attack_label)
    if not pool:
        raise RuntimeError(f'No templates for label {attack_label}')
    if not run_id:
        run_id = f"run_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    state = {
        'run_id': run_id,
        'status': 'running',
        'rows_sent': 0,
        'rows_failed': 0,
        'start_time': time.time(),
        'last_error': None,
        'thread': None,
        'mock_gemini': mock_gemini,
    }
    RUNS[run_id] = state

    def worker():
        try:
            for i in range(count):
                # pick a template and sample
                tmpl = random.choice(pool)
                row = sample_row(tmpl, src_ip_template)
                # add metadata
                row['synthetic'] = True
                row['simulator_run_id'] = run_id
                row['simulator_user'] = simulator_user
                row['user_selected_attack'] = attack_label
                row['simulator_mode'] = 'mock_gemini' if mock_gemini else 'real_gemini'
                try:
                    # If mock_gemini is requested, create a deterministic simulated alert
                    # directly rather than relying on the ML pipeline. This guarantees
                    # the simulator run will produce alert documents with simulator metadata.
                    if mock_gemini:
                        try:
                            from simulator.mock_gemini import summarize_for_simulator
                            from mongo_logging import log_alert
                            summary = summarize_for_simulator(row)
                            pred_class = [0]
                            explanation = summary.get('explanation')
                            gemini_rules = summary.get('rules') or {
                                'text': summary.get('recommended_action')
                            }
                            gemini_recommendation = summary.get('recommended_action')
                            severity = summary.get('severity')
                            confidence = summary.get('confidence')
                            # log_alert will promote simulator metadata from the row
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
                            with RUN_LOCK:
                                if res:
                                    state['rows_sent'] += 1
                                else:
                                    state['rows_failed'] += 1
                        except Exception:
                            # fallback to normal infer path if something unexpected fails
                            try:
                                infer(row, mock=mock_gemini)
                                with RUN_LOCK:
                                    state['rows_sent'] += 1
                            except Exception:
                                with RUN_LOCK:
                                    state['rows_failed'] += 1
                    else:
                        # pass mock flag so in-process inference can disable Gemini if requested
                        try:
                            infer(row, mock=mock_gemini)
                            with RUN_LOCK:
                                state['rows_sent'] += 1
                        except Exception:
                            with RUN_LOCK:
                                state['rows_failed'] += 1
                except Exception as e:
                    with RUN_LOCK:
                        state['rows_failed'] += 1
                        state['last_error'] = str(e)
                    # continue on failures
                time.sleep(1)
            with RUN_LOCK:
                state['status'] = 'stopped'
        except Exception as e:
            with RUN_LOCK:
                state['status'] = 'failed'
                state['last_error'] = str(e)

    t = threading.Thread(target=worker, daemon=True)
    state['thread'] = t
    t.start()
    return run_id


def stop_run(run_id: str):
    state = RUNS.get(run_id)
    if not state:
        raise RuntimeError('Run not found')
    # For now we mark stopped; worker checks will naturally stop after finishing a row
    state['status'] = 'stopping'
    # no hard-kill implemented for simplicity


def status(run_id: str) -> Dict[str, Any]:
    state = RUNS.get(run_id)
    if not state:
        raise RuntimeError('Run not found')
    return {k: v for k, v in state.items() if k != 'thread'}


def purge(run_id: str) -> int:
    # Purge synthetic docs with simulator_run_id from Mongo. We'll attempt to import mongo helper.
    try:
        from mongo_logging import get_mongo_client
        client = get_mongo_client()
        db = client.get_default_database()
        res = db.alerts.delete_many({'simulator_run_id': run_id, 'synthetic': True})
        return res.deleted_count
    except Exception:
        raise RuntimeError('Purge not available (mongo helper missing)')
