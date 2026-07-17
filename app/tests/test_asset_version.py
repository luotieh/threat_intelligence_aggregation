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


def _panel_of(html: str, needle: str) -> str:
    """needle 所在元素归属哪个 panel-*(面板之间靠 .active 切换,非活动面板不可见)。"""
    cur = None
    for line in html.splitlines():
        m = re.search(r'id="panel-([a-z]+)"', line)
        if m:
            cur = m.group(1)
        if needle in line:
            return cur
    return ""


def test_run_log_detail_renders_in_the_same_panel_as_its_button():
    """详情曾被写进概览面板里默认折叠的 #output —— 按钮在推送面板,点了等于什么都没有。"""
    html = TestClient(app).get("/config").text

    assert _panel_of(html, 'id="run-log"') == "push"
    assert _panel_of(html, 'id="run_log_out"') == "push"
    assert _panel_of(html, 'id="run_log_line"') == "push"


def test_run_log_output_is_not_inside_a_collapsed_details():
    html = TestClient(app).get("/config").text

    line = next(ln for ln in html.splitlines() if 'id="run_log_out"' in ln)
    assert "<details" not in line, "运行日志详情不能藏在折叠区里"


def test_run_log_js_writes_to_the_visible_element():
    js = (main.STATIC_DIR / "config.js").read_text()

    handler = js.split('$("run-log").onclick')[1].split("};")[0]
    assert "runLogOut(" in handler, "详情必须写进 run_log_out"
    assert "fmtRun" in handler
