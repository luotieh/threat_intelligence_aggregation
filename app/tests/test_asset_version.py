"""静态资源缓存串。

历史故障:config.html 把 config.js 钉在手写的 ?v=20260709a 上。前端改了没人记得改
版本号,浏览器一直用缓存里的旧 JS 配新 HTML —— 旧 JS 给已删除的按钮绑 onclick 抛
TypeError,脚本中断,后面所有事件绑定全失效(表现为"点按钮没反应")。
"""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

from app import main
from app.main import app, asset_version


def test_version_changes_when_file_changes(tmp_path, monkeypatch):
    js = tmp_path / "config.js"
    js.write_text("console.log(1)")
    monkeypatch.setattr(main, "STATIC_DIR", tmp_path)

    first = asset_version("config.js")
    js.write_text("console.log(2)")
    second = asset_version("config.js")

    assert first != second, "内容变了缓存串必须变,否则浏览器发不到新代码"


def test_version_stable_for_same_content(tmp_path, monkeypatch):
    js = tmp_path / "config.js"
    js.write_text("console.log(1)")
    monkeypatch.setattr(main, "STATIC_DIR", tmp_path)

    assert asset_version("config.js") == asset_version("config.js")


def test_missing_asset_does_not_break_page(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "STATIC_DIR", tmp_path)
    assert asset_version("nope.js") == "dev"


def test_config_page_embeds_current_js_hash():
    client = TestClient(app)

    html = client.get("/config").text

    m = re.search(r'/static/config\.js\?v=([0-9a-f]+)', html)
    assert m, "config.js 必须带内容哈希的缓存串"
    assert m.group(1) == asset_version("config.js")


def test_config_page_has_no_hardcoded_version():
    """防回归:任何写死的版本串都会再次导致发不出新前端。"""
    html = TestClient(app).get("/config").text
    assert "v=20260709a" not in html
