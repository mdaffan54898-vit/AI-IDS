import json

from simulator import mock_gemini


def test_summarize_prefers_top_level_fields():
    row = {
        'src_ip': '1.1.1.1',
        'dst_ip': '2.2.2.2',
        'protocol': 'UDP',
        'bytes_sent': 512,
        'user_selected_attack': 'TestAttack'
    }
    summary = mock_gemini.summarize_for_simulator(row)
    assert summary['src_ip'] == '1.1.1.1'
    assert summary['dst_ip'] == '2.2.2.2'
    assert summary['protocol'] == 'UDP'
    assert summary['bytes_sent'] == 512
    assert 'gemini_explanation' in summary and 'gemini_recommendation' in summary


def test_summarize_falls_back_to_features_list():
    row = {
        'features': [
            {'src_ip': '3.3.3.3', 'dst_ip': '4.4.4.4', 'protocol': 'TCP', 'sbytes': 128}
        ],
        'attack_label': 'FeatureAttack'
    }
    summary = mock_gemini.summarize_for_simulator(row)
    assert summary['src_ip'] == '3.3.3.3'
    assert summary['dst_ip'] == '4.4.4.4'
    assert summary['protocol'] == 'TCP'
    assert summary['bytes_sent'] == 128
    assert 'gemini_explanation' in summary and 'gemini_recommendation' in summary
