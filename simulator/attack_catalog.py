import csv
from typing import List, Dict
from pathlib import Path

CATALOG_PATH = Path(__file__).resolve().parent / 'data' / 'unsw_catalog_top6.csv'


def load_catalog(path: Path = CATALOG_PATH) -> List[Dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Catalog not found: {path}")
    rows = []
    with path.open('r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows


def get_by_label(rows: List[Dict[str, str]], label: str) -> List[Dict[str, str]]:
    return [r for r in rows if r.get('label') == label]
