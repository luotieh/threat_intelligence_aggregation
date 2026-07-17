import hashlib
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api import config, enrich, exports, health, indicators, push, sync
from app.db import init_db

STATIC_DIR = Path("app/static")


def asset_version(name: str) -> str:
    """按文件内容算缓存串。

    手写版本号必然被忘记改:config.js 曾长期钉在 ?v=20260709a,前端改了也发不出去,
    浏览器拿着旧 JS 配新 HTML,事件绑定全断。内容变则串变,不用记得改。
    """
    try:
        return hashlib.sha256((STATIC_DIR / name).read_bytes()).hexdigest()[:12]
    except OSError:
        return "dev"

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
    return templates.TemplateResponse(
        "config.html", {"request": request, "config_js_v": asset_version("config.js")}
    )
