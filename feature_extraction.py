import pandas as pd
import numpy as np

# List of numeric features from your training data
NUMERIC_FEATURES = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
    'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean',
    'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl',
    'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 
    'ct_srv_dst', 'is_sm_ips_ports'
]

# Expected one-hot columns (kept small for safety)
EXPECTED_ONEHOTS = [
    'proto_tcp','proto_udp','proto_icmp',
    'service_http','service_ftp','service_dns','service_ssh','service_smtp',
    'service_dhcp','service_irc','service_pop3','service_radius','service_snmp',
    'service_ssl','service_ftp-data',
    'state_CON','state_FIN','state_INT','state_REQ','state_RST'
]

def pkt_layer(proto: str):
    """Map a transport protocol string to a pyshark layer attribute name.

    Returns the layer name or None.
    """
    if not proto:
        return None
    p = proto.lower()
    if p == 'tcp':
        return 'tcp'
    if p == 'udp':
        return 'udp'
    if p == 'icmp':
        return 'icmp'
    return None


def _safe_layer_attr(packet, layer_name, attr, default=0):
    """Safely get attribute from a packet layer object.

    Example: _safe_layer_attr(packet, 'tcp', 'srcport', 0)
    """
    if not layer_name:
        return default
    layer_obj = getattr(packet, layer_name, None)
    if layer_obj is None:
        return default
    return getattr(layer_obj, attr, default)


def extract_features(packet):
    """
    Extracts features from a single pyshark packet and returns a DataFrame
    matching the model's expected feature schema (after one-hot encoding).
    """

    features = {}

    try:
        # Basic identifiers
        features['src_ip'] = getattr(getattr(packet, 'ip', None), 'src', 'unknown') if hasattr(packet, 'ip') else 'unknown'
        features['dst_ip'] = getattr(getattr(packet, 'ip', None), 'dst', 'unknown') if hasattr(packet, 'ip') else 'unknown'
        # Determine transport protocol robustly: prefer transport_layer, else check for known layers
        proto = getattr(packet, 'transport_layer', None)
        if not proto or not isinstance(proto, str):
            # Check for explicit layer attributes on the packet object (pyshark convenience)
            if hasattr(packet, 'tcp'):
                proto = 'TCP'
            elif hasattr(packet, 'udp'):
                proto = 'UDP'
            elif hasattr(packet, 'icmp'):
                proto = 'ICMP'
            else:
                # Fallback to highest_layer which sometimes contains protocol names
                proto = getattr(packet, 'highest_layer', None) or 'UNKNOWN'
        features['protocol'] = proto.upper() if isinstance(proto, str) else 'UNKNOWN'

        # Timing / sizes
        # sniff_timestamp is a string in pyshark; coerce to float where possible
        try:
            features['dur'] = float(packet.sniff_timestamp) if hasattr(packet, 'sniff_timestamp') else 0.0
        except Exception:
            features['dur'] = 0.0

        # Try several fields to determine packet payload/frame length. Use best-effort
        length_val = 0
        try:
            # Common property in pyshark packets
            length = getattr(packet, 'length', None)
            if length is not None:
                length_val = int(length)
            else:
                # Try frame_info.len
                frame_info = getattr(packet, 'frame_info', None)
                if frame_info is not None and getattr(frame_info, 'len', None) is not None:
                    length_val = int(getattr(frame_info, 'len'))
                else:
                    # Try IP total length
                    ip_layer = getattr(packet, 'ip', None)
                    if ip_layer is not None and getattr(ip_layer, 'len', None) is not None:
                        length_val = int(getattr(ip_layer, 'len'))
        except Exception:
            length_val = 0
        features['spkts'] = 1
        features['dpkts'] = 1
        features['sbytes'] = length_val
        features['dbytes'] = length_val
        features['rate'] = float(features['sbytes'] + features['dbytes'])
        features['sload'] = features['rate']
        features['dload'] = features['rate']

        # TTL
        features['sttl'] = int(getattr(getattr(packet, 'ip', None), 'ttl', 64)) if hasattr(packet, 'ip') else 64
        features['dttl'] = features['sttl']

        # TCP/UDP specific
        layer_name = pkt_layer(features['protocol'])
        sport = 0
        dport = 0
        if layer_name and hasattr(packet, layer_name):
            layer_obj = getattr(packet, layer_name)
            # pyshark exposes srcport/dstport for tcp/udp
            try:
                sport = int(getattr(layer_obj, 'srcport', 0) or 0)
            except Exception:
                sport = 0
            try:
                dport = int(getattr(layer_obj, 'dstport', 0) or 0)
            except Exception:
                dport = 0
            # window size/time etc
            try:
                features['swin'] = int(getattr(layer_obj, 'window_size_value', 0) or 0)
            except Exception:
                features['swin'] = 0
            try:
                features['tcprtt'] = float(getattr(layer_obj, 'time_delta', 0) or 0)
            except Exception:
                features['tcprtt'] = 0.0
        else:
            features['swin'] = 0
            features['tcprtt'] = 0.0

        # Some placeholders/defaults
        features['stcpb'] = 0
        features['dtcpb'] = 0
        features['dwin'] = features.get('swin', 0)
        features['synack'] = 0
        features['ackdat'] = 0
        features['trans_depth'] = 1
        features['response_body_len'] = 0

        # Extra UNSW placeholders
        for col in NUMERIC_FEATURES:
            if col not in features:
                # default numeric 0 (except dur/spkts/dpkts/sbytes/dbytes which were set)
                if col in ['dur','spkts','dpkts','sbytes','dbytes']:
                    continue
                features[col] = 0

        # Service detection (simple port map)
        service_map = {
            80: 'http', 21: 'ftp', 22: 'ssh', 25: 'smtp', 53: 'dns',
            67: 'dhcp', 68: 'dhcp', 110: 'pop3', 161: 'snmp',
            443: 'ssl', 6667: 'irc', 1812: 'radius'
        }
        detected_service = 'other'
        for p in (sport, dport):
            if p in service_map:
                detected_service = service_map[p]
                break

        # One-hot proto/service/state
        for p in ['tcp', 'udp', 'icmp']:
            features[f'proto_{p}'] = 1 if features['protocol'] == p else 0

        for svc in ['http','ftp','dns','ssh','smtp','dhcp','irc','pop3','radius','snmp','ssl','ftp-data']:
            features[f'service_{svc}'] = 1 if detected_service == svc else 0

        # State heuristic: if TCP layer present, assume CON (connection) else REQ
        state = 'CON' if layer_name == 'tcp' else 'REQ'
        for s in ['CON','FIN','INT','REQ','RST']:
            features[f'state_{s}'] = 1 if state == s else 0

    except Exception as e:
        # don't fail the pipeline on unexpected parsing errors
        print(f"[WARN] Error parsing packet: {e}")

    # Build DataFrame and ensure columns exist in a stable order
    df = pd.DataFrame([features])

    # Ensure numeric columns exist
    for col in NUMERIC_FEATURES:
        if col not in df.columns:
            df[col] = 0

    # Ensure expected one-hot columns exist
    for col in EXPECTED_ONEHOTS:
        if col not in df.columns:
            df[col] = 0

    # Ensure src/dst/protocol columns exist
    for col in ('src_ip','dst_ip','protocol'):
        if col not in df.columns:
            df[col] = 'unknown' if col == 'protocol' or 'ip' in col else 0

    # Keep column order stable (optional)
    cols = ['src_ip','dst_ip','protocol'] + NUMERIC_FEATURES + EXPECTED_ONEHOTS
    # Filter to only columns that exist (defensive)
    cols = [c for c in cols if c in df.columns]
    df = df[cols]

    return df