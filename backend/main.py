import asyncio
import contextlib
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from api.auth import router as auth_router
from api.alerts import router as alerts_router
from api.events import router as events_router
from api.hosts import router as hosts_router
from api.incidents import router as incidents_router
from api.response import router as response_router
from api.users import router as users_router
from database.database import init_db
from database.users import ensure_bootstrap_admin
from collectors.ingest_api import router as collectors_router
from api.ai import router as ai_router
from ai.analyzer import analyze_pending

log = logging.getLogger("xdr.ai")


async def ai_loop(interval_seconds: int) -> None:
    """Periodically score closed host/time windows with the AI model."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            await asyncio.to_thread(analyze_pending)
        except Exception:  # keep the API alive if one analysis run fails
            log.exception("AI analysis run failed")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    ensure_bootstrap_admin(
        os.environ.get("XDR_BOOTSTRAP_ADMIN_USERNAME"),
        os.environ.get("XDR_BOOTSTRAP_ADMIN_PASSWORD"),
    )
    task = None
    if os.environ.get("XDR_AI_ENABLED", "1") != "0":
        task = asyncio.create_task(ai_loop(int(os.environ.get("XDR_AI_INTERVAL_SECONDS", "60"))))
    yield
    if task is not None:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="XDR Platform API", version="0.1.0", lifespan=lifespan)

dashboard_path = Path(__file__).resolve().parents[1] / "frontend" / "xdr-dashboard"
app.mount(
    "/dashboard",
    StaticFiles(directory=dashboard_path, html=True),
    name="dashboard",
)


@app.get("/", include_in_schema=False)
def dashboard_home() -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")


@app.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(events_router)
app.include_router(auth_router)
app.include_router(collectors_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(hosts_router)
app.include_router(response_router)
app.include_router(users_router)
app.include_router(ai_router)