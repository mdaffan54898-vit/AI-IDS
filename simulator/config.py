import os
from dataclasses import dataclass


@dataclass
class SimulatorConfig:
    DEV_INFER_URL: str | None = os.getenv('DEV_INFER_URL')
    SIMULATOR_SINGLE_INSTANCE: bool = (
        os.getenv('SIMULATOR_SINGLE_INSTANCE', 'true').lower() == 'true'
    )
    SIMULATOR_MOCK_GEMINI: bool = (
        os.getenv('SIMULATOR_MOCK_GEMINI', 'false').lower() == 'true'
    )
    DEFAULT_JITTER_SBYTES_PCT: float = float(os.getenv('SIM_JITTER_SBYTES_PCT', '0.10'))
    DEFAULT_JITTER_SPKTS_PCT: float = float(os.getenv('SIM_JITTER_SPKTS_PCT', '0.10'))
    DEFAULT_DURATION_PCT: float = float(os.getenv('SIM_JITTER_DURATION_PCT', '0.20'))
    RETRY_BACKOFF_SECONDS: int = int(os.getenv('SIM_RETRY_BACKOFF_SECONDS', '1'))


cfg = SimulatorConfig()
