# AI-Powered Intrusion Detection System (AI-IDS)

## Overview

AI-Powered Intrusion Detection System (AI-IDS) is a real-time cybersecurity solution designed to detect, classify, and analyze malicious network activities using Machine Learning and Explainable AI.

The system captures live network traffic, extracts relevant features, classifies attacks using an XGBoost model trained on the UNSW-NB15 dataset, and enriches alerts with AI-generated explanations and mitigation recommendations. Detected threats are streamed to a React dashboard in real time and stored in MongoDB for analysis and auditing.

## Key Features

* Real-time network packet monitoring
* Machine Learning-based attack detection
* Multi-class attack classification
* AI-generated threat explanations
* Real-time dashboard visualization
* MongoDB alert logging
* WebSocket-based live notifications
* REST API using FastAPI
* Historical alert analysis

## Attack Categories Detected

* Analysis
* Backdoor
* DoS
* Exploits
* Fuzzers
* Generic
* Reconnaissance
* Shellcode
* Worms
* Normal Traffic

## System Architecture

Network Traffic
→ Packet Capture
→ Feature Extraction
→ XGBoost Model Inference
→ Attack Classification
→ AI Alert Enrichment (Gemini)
→ MongoDB Logging
→ Real-Time Dashboard

## Tech Stack

### Backend

* Python
* FastAPI
* Uvicorn
* XGBoost
* Scikit-Learn
* Pandas
* NumPy
* Socket.IO

### Frontend

* React.js
* Axios
* Chart.js
* Socket.IO Client

### Database

* MongoDB

### AI Integration

* Google Gemini API

### Dataset

* UNSW-NB15

## Performance

| Metric          | Score |
| --------------- | ----- |
| Accuracy        | 83.3% |
| Macro Precision | 76.0% |
| Macro Recall    | 59.0% |
| Macro F1-Score  | 61.0% |

## Project Modules

* Packet Capture Module
* Feature Extraction Engine
* XGBoost Detection Model
* AI Explanation Service
* Alert Logging System
* Real-Time Notification Server
* React Dashboard

## Future Enhancements

* SHAP-based Explainable AI
* Advanced threat intelligence integration
* Cloud deployment support
* Automated incident response
* SIEM integration
* Improved detection for minority attack classes


