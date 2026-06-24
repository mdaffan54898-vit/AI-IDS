# gemini_integration.py
import os
import google.generativeai as genai
from typing import Dict, Generator, List, Any
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# -------------------------------
# Initialize Gemini API
# -------------------------------
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    raise ValueError("GEMINI_API_KEY not set in environment! Please set it before running.")

genai.configure(api_key=api_key)

# Full model name
MODEL_NAME = "models/gemini-2.5-flash"
model = genai.GenerativeModel(MODEL_NAME)

# -------------------------------
# Classes & Functions
# -------------------------------
SEVERITY_COLOR_MAP = {
    "Critical": "#FF0000",  # Red
    "High": "#FF8C00",      # Orange
    "Medium": "#FFD700",    # Yellow
    "Low": "#32CD32",       # Green
    "Unknown": "#808080"    # Grey
}

SEVERITY_PRIORITY = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Unknown": 0
}

class AlertSummary:
    """
    Structured object representing a summarized alert.
    Includes severity, confidence, color, and generated firewall rules.
    """
    def __init__(self, alert_type: str, source_ip: str, destination_ip: str,
                 summary: str, severity: str, confidence: float, rules: Dict, raw_features=None):
        self.type = alert_type
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.summary = summary
        self.severity = severity
        self.confidence = confidence  # 0-100 float
        self.rules = rules
        self.color = SEVERITY_COLOR_MAP.get(severity, "#808080")  # default grey
        self.priority = SEVERITY_PRIORITY.get(severity, 0)
        # raw_features may be a pandas DataFrame, dict, or list of dicts
        self.raw_features = raw_features

    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "summary": self.summary,
            "severity": self.severity,
            "confidence": self.confidence,
            "rules": self.rules,
            # recommended_action is a short single-line action the UI can show (best-effort)
            "recommended_action": self._recommended_action(),
            # Only include raw_features if it's already serializable (dict/list).
            "raw_features": self.raw_features if not hasattr(self.raw_features, 'to_dict') else None,
            "color": self.color,
            "priority": self.priority
        }

    def _recommended_action(self) -> str:
        """Return a succinct recommended action string. Prefer explicit rules from Gemini;
        fallback to deterministic iptables/netsh commands when missing.
        """
        # If rules contains an iptables string, prefer that
        try:
            if isinstance(self.rules, dict):
                ipt = self.rules.get('iptables') if 'iptables' in self.rules else None
                win = self.rules.get('windows_firewall') if 'windows_firewall' in self.rules else None
                if ipt and isinstance(ipt, str) and len(ipt.strip()) > 0:
                    return ipt.strip()
                if win and isinstance(win, str) and len(win.strip()) > 0:
                    return win.strip()
        except Exception:
            pass

        # Fallback deterministic rules
        src = self.source_ip or '0.0.0.0'
        # iptables drop
        iptables_cmd = f"sudo iptables -A INPUT -s {src} -j DROP"
        # Windows netsh equivalent (block by IP using advfirewall)
        netsh_cmd = f"netsh advfirewall firewall add rule name=\"Block {src}\" dir=in action=block remoteip={src}"
        # Prefer iptables (common for server), but return both concatenated for UI clarity
        return f"{iptables_cmd}    ||    {netsh_cmd}"

def generate_alert_summary(alert_log: str) -> Dict:
    """
    Generates a summary, severity, confidence, and firewall rules for a log.
    Returns a dictionary.
    """
    # Backwards-compatible wrapper kept for callers that expect a dict-based summary
    # This implementation will call the newer textual mitigation prompt builder and
    # return a dict with keys: explanation, recommended_action, severity, confidence
    try:
        # If callers passed a raw log string, wrap into a small alert dict for the prompt
        alert = {"timestamp": "", "attack_cat": "", "src_ip": "", "dst_ip": "", "protocol": "", "sbytes": 0, "dbytes": 0}
        # If the caller passed a dict, use it directly; otherwise attempt to parse JSON
        parsed = None
        if isinstance(alert_log, dict):
            parsed = alert_log
        else:
            try:
                parsed = json.loads(alert_log)
            except Exception:
                parsed = None

        if isinstance(parsed, dict):
            alert.update(parsed)

        # DEBUG: show the normalized alert dict that will be used to build the prompt
        try:
            print("ALERT used to build prompt:", alert)
        except Exception:
            pass

        prompt = _build_prompt_for_textual_mitigation(alert)
        # DEBUG: print the exact prompt sent to Gemini for diagnosis
        try:
            print("\n===== PROMPT SENT TO GEMINI =====")
            print(prompt)
            print("=================================\n")
        except Exception:
            pass

        response = model.generate_content(prompt)
        text = getattr(response, 'text', '') or ''
        clean = text.strip().replace('```json', '').replace('```', '').strip()
        result = json.loads(clean)
        return {
            'explanation': result.get('explanation', clean),
            'recommended_action': result.get('recommended_action', ''),
            'severity': result.get('severity', 'Unknown'),
            'confidence': int(result.get('confidence', 0))
        }
    except Exception:
        # fallback
        return {
            'explanation': alert_log,
            'recommended_action': '',
            'severity': 'Unknown',
            'confidence': 0
        }


def _build_prompt_for_textual_mitigation(alert: Dict[str, Any]) -> str:
    """
    Build a prompt that asks Gemini to return:
      - short explanation (1-3 sentences)
      - recommended mitigation steps in plain English (do NOT return firewall commands)
      - severity and confidence
    Return a single compact JSON object with keys:
      "explanation", "recommended_action", "severity", "confidence"
    """
    src = alert.get("src_ip", "unknown")
    dst = alert.get("dst_ip", "unknown")
    attack = alert.get("attack_cat", alert.get("attack_type", "Unknown"))
    protocol = alert.get("protocol", "unknown")
    sbytes = alert.get("sbytes", alert.get("bytes_sent", 0))
    dbytes = alert.get("dbytes", alert.get("bytes_received", 0))
    timestamp = alert.get("timestamp", "")
    extra = alert.get("extra", "")

    prompt = f"""
You are a senior network security analyst. Analyze this IDS alert and return a JSON object ONLY.
1) Provide a short explanation (1-2 sentences) of what likely happened.
2) Provide a clear, prioritized set of mitigation and investigation *steps* in plain English (no runnable firewall commands). Include what to check in logs, short containment actions (e.g., "isolate host from network", "block on perimeter firewall via admin console"), and who/what to notify (e.g., "notify SOC, on-call network engineer"). Keep it actionable and concise.
3) Provide a severity label (Critical/High/Medium/Low).
4) Provide an integer confidence (0-100).

Return exactly one JSON object, minified or pretty, with keys:
  "explanation": string,
  "recommended_action": string,
  "severity": string,
  "confidence": number

Alert:
timestamp: {timestamp}
attack_category: {attack}
src_ip: {src}
dst_ip: {dst}
protocol: {protocol}
bytes_sent: {sbytes}
bytes_received: {dbytes}
extra: {extra}
"""
    return prompt.strip()
    

def summarize_alert(alert: Dict, raw_features=None) -> AlertSummary:
    """
    Takes an alert dictionary and returns a structured AlertSummary object.
    """
    # Format the dictionary into a string for the prompt
    # Use the textual mitigation generator which returns explanation/recommended_action/severity/confidence
    gen = generate_alert_summary(alert if isinstance(alert, dict) else str(alert))
    explanation = gen.get('explanation') or ''
    recommended_action = gen.get('recommended_action') or ''
    severity = gen.get('severity') or 'Unknown'
    confidence = int(gen.get('confidence') or 0)

    # Map textual recommendation into the rules slot as well for backwards compatibility (keep empty dict)
    rules = {'text': recommended_action} if recommended_action else {}

    return AlertSummary(
        alert_type=alert.get("attack_cat", alert.get('attack_type', "Unknown")),
        source_ip=alert.get("src_ip", "Unknown"),
        destination_ip=alert.get("dst_ip", "Unknown"),
        summary=explanation,
        severity=severity,
        confidence=confidence,
        rules=rules,
        raw_features=raw_features
    )

def process_live_alerts(alerts_stream: List[Dict]) -> List[AlertSummary]:
    """
    Processes a list or stream of live alerts and returns AlertSummary objects sorted by priority.
    """
    summarized = [summarize_alert(alert) for alert in alerts_stream]
    # Sort descending by priority first, then by confidence
    summarized.sort(key=lambda x: (x.priority, x.confidence), reverse=True)
    return summarized


def shutdown():
    """Attempt to gracefully close or clear Gemini client resources.

    The google.generativeai client may not expose a close API; this function
    attempts best-effort cleanup and releases the `model` reference.
    """
    global model
    try:
        # If the SDK exposes a close method in later versions, call it.
        close_fn = getattr(model, 'close', None)
        if callable(close_fn):
            close_fn()
    except Exception:
        pass
    finally:
        model = None

