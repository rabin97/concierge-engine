import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from app.agents.guard.service import GuardBlocked
from app.api.routes import router

UI_FILE = Path(__file__).resolve().parent.parent / "ui" / "index.html"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

app = FastAPI(
    title="AI Household Concierge Engine",
    version="0.1.0",
    description="Prompt -> validated task tree -> durable workflow -> WhatsApp/email notifications",
)
app.include_router(router)


@app.exception_handler(GuardBlocked)
def guard_blocked(_: Request, exc: GuardBlocked):
    """Friendly message only; never which rule fired. request_id lets support find the decision log."""
    return JSONResponse(status_code=400, content={"detail": exc.message, "guard_request_id": exc.decision.request_id})


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui")


@app.get("/ui", include_in_schema=False)
def ui():
    """Local test console. Same origin as the API, so no CORS setup is needed."""
    return FileResponse(UI_FILE)
