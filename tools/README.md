# Tools README

This folder contains developer tools to exercise the simulator and inspect alerts.

Prerequisites
- Python virtualenv in `.venv` (activate with PowerShell):

```powershell
& ".\.venv\Scripts\Activate.ps1"
```

Smoke test (start a short simulator run, wait for completion, assert Mongo insertion)

```powershell
# activate venv then run smoke test
& ".\.venv\Scripts\Activate.ps1"
python .\tools\smoke_sim_test.py
```

Quick start (POST /simulator/start then inspect status)

```powershell
& ".\.venv\Scripts\Activate.ps1"
python .\tools\sim_test_post.py
# (optionally) repeat to poll and inspect output
```

Dump recent alerts (prints last N documents)

```powershell
& ".\.venv\Scripts\Activate.ps1"
python .\tools\dump_alerts.py
```

Direct controller test (call start_run directly inside the codebase)

```powershell
& ".\.venv\Scripts\Activate.ps1"
python .\tools\run_start_direct.py
```

Notes
- The smoke test assumes the backend is running on `http://127.0.0.1:8000` and MongoDB is available at `mongodb://localhost:27017`.
- If you change the code, restart uvicorn so the API uses the updated modules.
- The smoke test and other scripts are intended for development; do not run them concurrently against production data.
