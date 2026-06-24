import os
import time
from twilio.rest import Client
from threading import Lock

# Configuration via environment variables (safe defaults for development)
TWILIO_ENABLED = os.getenv('TWILIO_ENABLED', 'false').lower() in ('1', 'true', 'yes')
TWILIO_SID = os.getenv('TWILIO_SID', "AC0b53529069ead3811e1ce90065084b08")
TWILIO_TOKEN = os.getenv('TWILIO_TOKEN', "ea56cda4762b99848c0953a88c7dd265")
SMS_FROM = os.getenv('SMS_FROM', "+16818811579")
SMS_TO = os.getenv('SMS_TO', "+916383252194")
WHATSAPP_FROM = os.getenv('WHATSAPP_FROM', "whatsapp:+14155238886")
WHATSAPP_TO = os.getenv('WHATSAPP_TO', "whatsapp:+918870051135")

# Minimum severity required to send notifications. Severity is expected to be one of
# ['Low','Medium','High','Critical'] (case-insensitive). Default is 'High' for safety.
SEVERITY_LEVEL = os.getenv('TWILIO_MIN_SEVERITY', 'High').lower()
SEVERITY_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

# Cooldown (seconds) per destination to avoid notification storms. Default 60s.
NOTIFY_COOLDOWN = int(os.getenv('TWILIO_COOLDOWN_SECONDS', '60'))

# In-memory cooldown tracker (destination -> last_sent_ts)
_last_sent = {}
_last_sent_lock = Lock()

client = None
if TWILIO_ENABLED:
    try:
        client = Client(TWILIO_SID, TWILIO_TOKEN)
    except Exception as e:
        print("Warning: Failed to initialize Twilio client:", e)


def _can_send(dest):
    """Return True if we can send to dest based on cooldown."""
    now = time.time()
    with _last_sent_lock:
        last = _last_sent.get(dest)
        if last is None or (now - last) >= NOTIFY_COOLDOWN:
            _last_sent[dest] = now
            return True
        return False


def _severity_ok(severity):
    if not severity:
        return False
    try:
        return SEVERITY_RANK.get(severity.lower(), 0) >= SEVERITY_RANK.get(SEVERITY_LEVEL, 3)
    except Exception:
        return False


def send_sms_alert(message, severity='High'):
    """Send SMS alert if notifications are enabled, severity threshold met, and cooldown allows it.

    Args:
        message (str): The SMS body.
        severity (str): Severity label (Low/Medium/High/Critical).
    """
    if not TWILIO_ENABLED:
        print("Twilio disabled (TWILIO_ENABLED=false). SMS suppressed.")
        return
    if not _severity_ok(severity):
        print(f"SMS suppressed: severity '{severity}' below threshold '{SEVERITY_LEVEL}'.")
        return
    dest = SMS_TO
    if not _can_send(dest):
        print(f"SMS suppressed by cooldown for {dest}.")
        return
    if client is None:
        print("Twilio client not initialized; cannot send SMS.")
        return
    try:
        client.messages.create(body=message, from_=SMS_FROM, to=SMS_TO)
        print("SMS alert sent!")
    except Exception as e:
        print("SMS send failed:", e)


def send_whatsapp_alert(message, severity='High'):
    """Send WhatsApp alert with same gating as SMS."""
    if not TWILIO_ENABLED:
        print("Twilio disabled (TWILIO_ENABLED=false). WhatsApp suppressed.")
        return
    if not _severity_ok(severity):
        print(f"WhatsApp suppressed: severity '{severity}' below threshold '{SEVERITY_LEVEL}'.")
        return
    dest = WHATSAPP_TO
    if not _can_send(dest):
        print(f"WhatsApp suppressed by cooldown for {dest}.")
        return
    if client is None:
        print("Twilio client not initialized; cannot send WhatsApp message.")
        return
    try:
        client.messages.create(body=message, from_=WHATSAPP_FROM, to=WHATSAPP_TO)
        print("WhatsApp alert sent!")
    except Exception as e:
        print("WhatsApp send failed:", e)