import pandas as pd
from unittest.mock import MagicMock

import ids_inference


def make_dummy_model(pred_value=1):
    m = MagicMock()
    m.predict.return_value = [pred_value]
    return m


def make_dummy_le(inv_label='Exploits'):
    le = MagicMock()
    le.inverse_transform.return_value = [inv_label]
    return le


class DummySummary:
    def __init__(self, summary='ok', severity='High', confidence=90, raw_features=None):
        self.summary = summary
        self.severity = severity
        self.confidence = confidence
        self.rules = {}
        self.raw_features = raw_features


def test_process_packet_uses_raw_features_and_logs():
    # Arrange
    df = pd.DataFrame([{'src_ip': '1.1.1.1', 'dst_ip': '2.2.2.2', 'sbytes': 123}])
    model = make_dummy_model(pred_value=1)
    le = make_dummy_le('Exploits')
    expected_features = ['sbytes']
    scaler = None

    summary_obj = DummySummary(summary='attack', severity='Critical', confidence=95, raw_features={'src_ip': '1.1.1.1'})
    mock_summarize = MagicMock(return_value=summary_obj)

    mock_log = MagicMock()
    mock_sms = MagicMock()
    mock_wa = MagicMock()

    class Args:
        test = False

    # Act
    res = ids_inference.process_packet(df, model, le, expected_features, scaler, Args(), 0,
                                       summarize_fn=mock_summarize, log_fn=mock_log,
                                       sms_fn=mock_sms, whatsapp_fn=mock_wa)

    # Assert
    assert res['is_attack'] is True
    mock_summarize.assert_called_once()
    # Ensure log called with the raw_features provided by the summary object
    mock_log.assert_called_once()
    called_args = mock_log.call_args[0]
    assert called_args[0] == summary_obj.raw_features


def test_process_packet_in_test_mode_no_external_calls():
    # Arrange
    df = pd.DataFrame([{'src_ip': '9.9.9.9', 'dst_ip': '8.8.8.8', 'sbytes': 200}])
    model = make_dummy_model(pred_value=1)
    le = make_dummy_le('Exploits')
    expected_features = ['sbytes']
    scaler = None

    mock_summarize = MagicMock()
    mock_log = MagicMock()
    mock_sms = MagicMock()
    mock_wa = MagicMock()

    class Args:
        test = True

    # Act
    res = ids_inference.process_packet(df, model, le, expected_features, scaler, Args(), 0,
                                       summarize_fn=mock_summarize, log_fn=mock_log,
                                       sms_fn=mock_sms, whatsapp_fn=mock_wa)

    # Assert
    assert res['is_attack'] is True
    # In test mode, summarize shouldn't be called
    mock_summarize.assert_not_called()
    # log should be called with original df
    mock_log.assert_called_once()
    assert mock_log.call_args[0][0].equals(df)