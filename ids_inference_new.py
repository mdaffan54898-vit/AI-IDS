# IDS Inference Script
# This script captures packets, extracts features, and uses the trained XGBoost model to predict attacks.

from packet_capture import capture_packets
from feature_extraction import extract_features
from mongo_logging import log_alert
from gemini_integration import get_gemini_explanation
from twilio_alerts import send_sms_alert, send_whatsapp_alert
import joblib
from datetime import datetime

def main():
    interface = input("Enter network interface (e.g., 'Wi-Fi'): ").strip()
    try:
        num_packets = int(input("Enter number of packets to capture: "))
    except ValueError:
        print("Invalid number.")
        return

    try:
        model = joblib.load('xgboost_model_multi.pkl')
        le = joblib.load('label_encoder.pkl')
        expected_features = model.get_booster().feature_names
        print("Model and encoder loaded successfully!")
    except FileNotFoundError:
        print("Model not found. Run train_model.py first.")
        return

    packets = capture_packets(interface, num_packets)
    if not packets:
        print("No packets captured.")
        return

    normal_count = 0
    attack_count = 0

    for i, pkt in enumerate(packets):
        try:
            features_df = extract_features(pkt)
            pred_df = features_df.select_dtypes(include=[int, float])
            pred_df = pred_df.reindex(columns=expected_features, fill_value=0)

            pred_class = model.predict(pred_df)[0]
            attack_type = le.inverse_transform([pred_class])[0]

            print(f"Packet {i+1}: Detected attack type: {attack_type}")
            if attack_type == "Normal":
                normal_count += 1
            else:
                attack_count += 1
                alert_summary = {
                    "timestamp": str(datetime.now()),
                    "src_ip": features_df['src_ip'].iloc[0],
                    "dst_ip": features_df['dst_ip'].iloc[0],
                    "protocol": features_df['protocol'].iloc[0],
                    "attack_type": attack_type,
                    "bytes_sent": features_df['sbytes'].iloc[0],
                    "connections": features_df.get('trans_depth', [1]).iloc[0]
                }

                # Gemini explanation
                gemini_result = get_gemini_explanation(alert_summary)
                print("Alert Explanation:", gemini_result['explanation'])
                print("Recommended Action:", gemini_result['recommendation'])

                # MongoDB logging
                log_alert(features_df, [pred_class], gemini_result['recommendation'])

                # Twilio alerts
                alert_message = f"ALERT: {attack_type} detected!\nSrc: {alert_summary['src_ip']}\nDst: {alert_summary['dst_ip']}\nRecommendation: {gemini_result['recommendation']}"
                send_sms_alert(alert_message)
                send_whatsapp_alert(alert_message)

        except Exception as e:
            print(f"Error processing packet {i+1}: {e}")

    print(f"\nSummary: {normal_count} Normal, {attack_count} Attacks out of {len(packets)} packets.")

if __name__ == "__main__":
    main()