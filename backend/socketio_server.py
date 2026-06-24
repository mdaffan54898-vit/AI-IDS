import socketio

# Create a Socket.IO server with asyncio support
# Explicitly allow the local frontend origins to avoid origin rejections
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    logger=True,
    engineio_logger=True,
)

# Export the ASGI app as `socketio_app` so callers can import it exactly as
# recommended (from .socketio_server import socketio_app)
socketio_app = socketio.ASGIApp(sio)


async def emit_new_alert(alert_payload: dict):
    """Emit a 'new_alert' event to all connected clients.

    This helper is async-friendly; callers can import and await it or use
    asyncio.create_task when calling from sync code.
    """
    try:
        # Log for debugging so backend logs show emission
        print(f"[socketio] emitting new_alert -> {alert_payload.get('id')} severity={alert_payload.get('severity')}")
        await sio.emit('new_alert', alert_payload)
    except Exception as e:
        # best-effort: ignore emission errors but print debug
        print(f"[socketio] emit failed: {e}")
