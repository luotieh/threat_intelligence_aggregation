from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import config, enrich, exports, health, indicators, push, sync
from app.db import init_db

app = FastAPI(title="Threat Intel Hub", version="0.1.0")
templates = Jinja2Templates(directory="app/templates")

app.include_router(health.router)
app.include_router(indicators.router)
app.include_router(sync.router)
app.include_router(push.router)
app.include_router(enrich.router)
app.include_router(exports.router)
app.include_router(config.router)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/config", response_class=HTMLResponse)
def config_page(request: Request):
    return templates.TemplateResponse("config.html", {"request": request})
