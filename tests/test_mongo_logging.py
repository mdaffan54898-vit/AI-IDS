import pytest
import pandas as pd
from unittest.mock import patch, MagicMock

from mongo_logging import log_alert


class DummyCollection:
    def __init__(self):
        self.inserted = []

    def insert_one(self, doc):
        self.inserted.append(doc)
        return MagicMock(inserted_id='dummy')


class DummyDB:
    def __init__(self):
        self.collection = DummyCollection()

    def __getitem__(self, name):
        return self.collection


class DummyClient:
    def __init__(self, *args, **kwargs):
        self.db = DummyDB()

    def __getitem__(self, name):
        return self.db


@patch('mongo_logging.MongoClient')
def test_log_alert_with_dataframe(mock_mongo_client):
    # Arrange
    mock_mongo_client.return_value = DummyClient()
    df = pd.DataFrame([{'src_ip': '1.2.3.4', 'dst_ip': '5.6.7.8', 'sbytes': 100}])

    # Act & Assert - should not raise
    log_alert(df, [1], 'Test explanation')


@patch('mongo_logging.MongoClient')
def test_log_alert_with_dict(mock_mongo_client):
    # Arrange
    mock_mongo_client.return_value = DummyClient()
    record = {'srcip': '10.0.0.5', 'dstip': '10.0.0.6', 'proto': 'UDP', 'sbytes': 123, 'synthetic': True, 'simulator_run_id': 'test_run_1', 'simulator_user': 'qa'}

    # Act
    res = log_alert(record, [2], 'Dict explanation', attack_type='Test', gemini_rules={'text': 'r'}, severity='Low', gemini_recommendation='rec', confidence=5)

    # Assert: returned success
    assert res is not False

    # Verify the inserted document contains promoted/normalized fields
    db = mock_mongo_client.return_value['ids_db']
    # DummyDB holds the collection in attribute 'collection' per DummyDB implementation above
    coll = db.collection
    assert len(coll.inserted) == 1
    doc = coll.inserted[0]
    assert doc.get('protocol') == 'UDP'
    assert doc.get('bytes_sent') == 123
    assert doc.get('simulator_run_id') == 'test_run_1'
    assert doc.get('simulator_user') == 'qa'
    assert doc.get('gemini_recommendation') == 'rec'
    assert doc.get('gemini_explanation') == 'Dict explanation'
