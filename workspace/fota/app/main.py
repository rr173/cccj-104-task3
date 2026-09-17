from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import config
from .db import SessionLocal, init_db
from .routers import admin, device


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if config.SEED_DEMO:
        from .seed import seed_if_empty

        db = SessionLocal()
        try:
            seed_if_empty(db)
        finally:
            db.close()
    yield


app = FastAPI(title="FOTA service for intermittently-connected terminals", lifespan=lifespan)
app.include_router(device.router)
app.include_router(admin.router)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
