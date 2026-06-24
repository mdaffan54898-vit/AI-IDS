from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from simulator.controller import start_run, stop_run, status, purge

router = APIRouter(prefix='/simulator')


class StartRequest(BaseModel):
    run_id: Optional[str] = None
    attack_label: str
    intensity: Optional[str] = 'low'
    src_ip_template: Optional[str] = '10.0.0.X'
    count: int = 10
    duration_seconds: Optional[int] = None
    jitter_config: Optional[dict] = None
    mock_gemini: bool = False
    simulator_user: Optional[str] = 'qa_user'


class StopRequest(BaseModel):
    run_id: str


class StartResponse(BaseModel):
    run_id: str
    status: str
    message: Optional[str]


class PurgeRequest(BaseModel):
    run_id: str
    confirm: bool


class StopResponse(BaseModel):
    run_id: str
    status: str


class StatusResponse(BaseModel):
    run_id: str
    status: str
    rows_sent: Optional[int]
    rows_failed: Optional[int]
    start_time: Optional[float]
    last_error: Optional[str]


class PurgeResponse(BaseModel):
    run_id: str
    deleted: int


@router.post('/start', response_model=StartResponse, status_code=201)
async def api_start(payload: StartRequest):
    """Start a simulator run. Returns generated run_id and status.

    The endpoint starts a background thread that emits synthetic feature rows.
    """
    try:
        run_id = start_run(
            payload.attack_label,
            payload.count,
            payload.src_ip_template,
            payload.mock_gemini,
            payload.simulator_user,
            payload.run_id,
        )
        return {'run_id': run_id, 'status': 'started', 'message': None}
    except Exception as e:
        # Return a 400 with the error message to help clients debug
        raise HTTPException(status_code=400, detail=str(e))


@router.post('/stop', response_model=StopResponse)
async def api_stop(payload: StopRequest):
    try:
        stop_run(payload.run_id)
        return {'run_id': payload.run_id, 'status': 'stopping'}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get('/status', response_model=StatusResponse)
async def api_status(run_id: str):
    try:
        s = status(run_id)
        # ensure keys match the response model shape
        return {
            'run_id': s.get('run_id') or run_id,
            'status': s.get('status'),
            'rows_sent': s.get('rows_sent'),
            'rows_failed': s.get('rows_failed'),
            'start_time': s.get('start_time'),
            'last_error': s.get('last_error')
        }
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post('/purge', response_model=PurgeResponse)
async def api_purge(payload: PurgeRequest):
    if not payload.confirm:
        raise HTTPException(status_code=400, detail='confirm=true required')
    try:
        deleted = purge(payload.run_id)
        return {'run_id': payload.run_id, 'deleted': deleted}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
