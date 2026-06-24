import random
import copy
from typing import Dict, Any
from simulator.config import cfg


def jitter_value(val, pct):
    try:
        f = float(val)
    except Exception:
        return val
    jitter = f * pct
    return type(f)(max(0, f + random.uniform(-jitter, jitter)))


def sample_row(template: Dict[str, Any], src_ip_template: str = '10.0.0.X') -> Dict[str, Any]:
    row = copy.deepcopy(template)
    # jitter numeric fields
    for k in ('sbytes', 'dbytes'):
        if k in row and row[k] not in (None, ''):
            row[k] = int(jitter_value(row[k], cfg.DEFAULT_JITTER_SBYTES_PCT))
    for k in ('spkts', 'dpkts'):
        if k in row and row[k] not in (None, ''):
            base = int(row[k])
            row[k] = max(1, int(jitter_value(base, cfg.DEFAULT_JITTER_SPKTS_PCT)))
    if 'duration' in row and row['duration'] not in (None, ''):
        row['duration'] = max(0.0, jitter_value(row['duration'], cfg.DEFAULT_DURATION_PCT))
    if 'trans_depth' in row and row['trans_depth'] not in (None, ''):
        td = int(row['trans_depth'])
        row['trans_depth'] = max(0, td + random.randint(0, 1))
    # fill srcip
    if 'srcip' not in row or not row.get('srcip'):
        x = random.randint(1, 254)
        row['srcip'] = src_ip_template.replace('X', str(x))
    # ensure proper types
    for k in (
        'sbytes', 'dbytes', 'spkts', 'dpkts', 'duration', 'trans_depth'
    ):
        if k in row and row[k] is not None and row[k] != '':
            try:
                if '.' in str(row[k]):
                    row[k] = float(row[k])
                else:
                    row[k] = int(row[k])
            except Exception:
                pass
    return row
