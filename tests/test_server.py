"""Tests for src/server.py. The server runs on 127.0.0.1 with a system-chosen port. No model, no internet."""

import http.client
import json
from pathlib import Path

import pytest

from src.server import COOKIE_NAME, CSP, LocalServer, PageState, PageStateError
from src.stage_content import StagesFile
from tests.test_frames import chain_pack, stage3
from tests.test_lecturer import ATTACK_PLAN, STAGE1, STAGE2

TOKEN = "test-token-1234567890"
SECRET_TEXT = "Servers were taken over"  # text of stage 1, must not leak without the token


def make_file():
    return StagesFile(topic="CVE-0000-0000", plan=ATTACK_PLAN, stages=[STAGE1, STAGE2, stage3(chain_pack())])


@pytest.fixture
def app():
    server = LocalServer(PageState(make_file()), port=0, token=TOKEN)
    server.start()
    yield server
    server.stop()


def request(app, path="/", *, method="GET", cookie=True, host=None, origin=None, token_cookie=TOKEN):
    conn = http.client.HTTPConnection("127.0.0.1", app.port, timeout=5)
    conn.putrequest(method, path, skip_host=True)
    conn.putheader("Host", host or f"127.0.0.1:{app.port}")
    if cookie:
        conn.putheader("Cookie", f"{COOKIE_NAME}={token_cookie}")
    if origin:
        conn.putheader("Origin", origin)
    conn.endheaders()
    response = conn.getresponse()
    body = response.read()
    conn.close()
    return response, body


# ---- who may talk to the server --------------------------------------------------


def test_server_listens_on_127_0_0_1_only(app):
    assert app._httpd.server_address[0] == "127.0.0.1"


@pytest.mark.parametrize("path", ["/", "/api/state", "/static/app.js", "/static/mermaid.min.js", "/nothing"])
def test_every_path_needs_the_token(app, path):
    response, body = request(app, path, cookie=False)
    assert response.status == 403 and SECRET_TEXT.encode() not in body


def test_wrong_cookie_is_refused(app):
    response, _ = request(app, "/api/state", token_cookie="wrong")
    assert response.status == 403


def test_token_in_the_address_becomes_a_cookie_and_is_redirected_away(app):
    response, _ = request(app, f"/?token={TOKEN}", cookie=False)
    assert response.status == 302 and response.getheader("Location") == "/"
    cookie = response.getheader("Set-Cookie")
    assert f"{COOKIE_NAME}={TOKEN}" in cookie
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_wrong_token_in_the_address_is_refused(app):
    response, _ = request(app, "/?token=wrong", cookie=False)
    assert response.status == 403 and response.getheader("Set-Cookie") is None


def test_token_in_the_address_is_only_accepted_on_the_start_page(app):
    response, _ = request(app, f"/api/state?token={TOKEN}", cookie=False)
    assert response.status == 403


@pytest.mark.parametrize("host", ["evil.example", "evil.example:80", "127.0.0.1", "127.0.0.1:1", "0.0.0.0"])
def test_a_foreign_host_header_is_refused_even_with_the_token(app, host):
    response, body = request(app, "/api/state", host=host)
    assert response.status == 403 and SECRET_TEXT.encode() not in body


def test_localhost_name_with_the_right_port_is_accepted(app):
    response, _ = request(app, "/api/state", host=f"localhost:{app.port}")
    assert response.status == 200


def test_a_foreign_origin_is_refused_and_our_own_is_accepted(app):
    assert request(app, "/api/state", origin="http://evil.example")[0].status == 403
    assert request(app, "/api/state", origin="null")[0].status == 403
    assert request(app, "/api/state", origin=f"http://127.0.0.1:{app.port}")[0].status == 200


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
def test_only_get_is_allowed(app, method):
    response, _ = request(app, "/api/state", method=method)
    assert response.status == 405 and response.getheader("Allow") == "GET"


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_other_methods_without_the_token_get_403_not_405(app, method):
    assert request(app, "/api/state", method=method, cookie=False)[0].status == 403


# ---- what it sends -----------------------------------------------------------------


def test_every_response_carries_the_security_headers(app):
    for path, cookie in (("/", True), ("/api/state", True), ("/nothing", True), ("/api/state", False)):
        response, _ = request(app, path, cookie=cookie)
        assert response.getheader("Content-Security-Policy") == CSP
        assert response.getheader("X-Content-Type-Options") == "nosniff"
        assert response.getheader("Cache-Control") == "no-store"
        assert response.getheader("Referrer-Policy") == "no-referrer"


def test_csp_allows_scripts_only_from_this_server():
    assert "script-src 'self'" in CSP and "default-src 'none'" in CSP
    assert "unsafe-eval" not in CSP and "script-src 'self' 'unsafe" not in CSP
    assert "connect-src 'self'" in CSP and "frame-ancestors 'none'" in CSP


def test_page_and_scripts_are_served_with_their_content_types(app):
    page, body = request(app, "/")
    assert page.status == 200 and page.getheader("Content-Type").startswith("text/html")
    assert b'src="/static/mermaid.min.js"' in body and b"http://" not in body and b"https://" not in body
    assert request(app, "/static/app.js")[0].getheader("Content-Type").startswith("text/javascript")
    assert request(app, "/static/style.css")[0].getheader("Content-Type").startswith("text/css")


def test_the_vendored_mermaid_file_is_served_unchanged(app):
    response, body = request(app, "/static/mermaid.min.js")
    vendored = Path(__file__).resolve().parents[1] / "web" / "vendor" / "mermaid.min.js"
    assert response.status == 200 and body == vendored.read_bytes()


@pytest.mark.parametrize(
    "path",
    ["/static/../src/server.py", "/static/%2e%2e/src/server.py", "/../CLAUDE.md", "/web/index.html",
     "/static/vendor/mermaid.min.js", "/static/", "/static/app.js/", "/etc/passwd"],
)
def test_only_the_fixed_list_of_files_is_served(app, path):
    response, body = request(app, path)
    assert response.status == 404 and b"CLAUDE" not in body and b"class LocalServer" not in body


def test_page_code_has_no_inline_script_and_loads_nothing_from_outside():
    web = Path(__file__).resolve().parents[1] / "web"
    html = (web / "index.html").read_text(encoding="utf-8")
    js = (web / "app.js").read_text(encoding="utf-8")
    css = (web / "style.css").read_text(encoding="utf-8")
    assert "<script>" not in html and "onclick" not in html.lower()
    for text in (html, js, css):
        assert "//cdn" not in text and "https://" not in text.replace("^https?:\\/\\/", "")
    assert "eval(" not in js and "new Function" not in js


# ---- the state endpoint -------------------------------------------------------------


def state_json(app):
    response, body = request(app, "/api/state")
    assert response.status == 200
    assert response.getheader("Content-Type").startswith("application/json")
    return json.loads(body)


def test_nothing_is_shown_until_the_first_next(app):
    data = state_json(app)
    assert data["revealed"] == 0 and data["stages"] == [] and data["written"] == 3 and data["planned"] == 4


def test_next_adds_one_stage_at_a_time_in_order(app):
    for expected in (1, 2, 3):
        app.state.reveal_next()
        data = state_json(app)
        assert data["revealed"] == expected
        assert [s["stage_number"] for s in data["stages"]] == list(range(1, expected + 1))


def test_stage_3_is_sent_with_its_frames_and_chain(app):
    for _ in range(3):
        app.state.reveal_next()
    stage3_data = state_json(app)["stages"][2]
    assert stage3_data["diagram"] is None
    assert [f["step"] for f in stage3_data["frames"]] == [1, 2, 3]
    assert [c["step"] for c in stage3_data["chain"]] == [1, 2, 3]


def test_unrevealed_stages_are_not_sent(app):
    app.state.reveal_next()
    assert "Input is evaluated by the logger" not in json.dumps(state_json(app))


# ---- terminal-side state ------------------------------------------------------------


def test_reveal_next_stops_at_the_last_written_stage():
    state = PageState(make_file())
    assert [state.reveal_next() is not None for _ in range(4)] == [True, True, True, False]
    assert state.revealed == 3


def test_repeat_needs_a_stage_that_is_already_shown():
    state = PageState(make_file())
    with pytest.raises(PageStateError, match="none yet"):
        state.repeat(1)
    state.reveal_next()
    state.reveal_next()
    with pytest.raises(PageStateError, match="1 to 2"):
        state.repeat(3)
    with pytest.raises(PageStateError):
        state.repeat(0)


def test_repeat_sets_the_focus_and_fires_again_for_the_same_stage():
    state = PageState(make_file())
    state.reveal_next()
    state.repeat(1)
    first = state.snapshot()["focus"]
    state.repeat(1)
    second = state.snapshot()["focus"]
    assert first["stage"] == second["stage"] == 1 and second["seq"] == first["seq"] + 1


def test_repeat_does_not_reveal_anything():
    state = PageState(make_file())
    state.reveal_next()
    state.repeat(1)
    assert state.revealed == 1


# ---- ports and startup --------------------------------------------------------------


def test_busy_default_port_falls_back_to_a_free_one():
    first = LocalServer(PageState(make_file()), port=0)
    try:
        second = LocalServer(PageState(make_file()), port=first.port)
        try:
            assert second.port != first.port and second._httpd.server_address[0] == "127.0.0.1"
        finally:
            second._httpd.server_close()
    finally:
        first._httpd.server_close()


def test_each_session_gets_its_own_long_random_token():
    a = LocalServer(PageState(make_file()), port=0)
    b = LocalServer(PageState(make_file()), port=0)
    try:
        assert a.token != b.token and len(a.token) >= 32
        assert a.url() == f"http://127.0.0.1:{a.port}/?token={a.token}"
    finally:
        a._httpd.server_close()
        b._httpd.server_close()


def test_the_server_does_not_log_the_request_line(app, capsys):
    request(app, f"/?token={TOKEN}", cookie=False)
    captured = capsys.readouterr()
    assert TOKEN not in captured.out + captured.err


def test_a_wide_diagram_scrolls_sideways_in_its_box_instead_of_shrinking():
    web = Path(__file__).resolve().parents[1] / "web"
    css = (web / "style.css").read_text(encoding="utf-8")
    js = (web / "app.js").read_text(encoding="utf-8")
    diagram_rule = css.split(".diagram {", 1)[1].split("}", 1)[0]
    assert "overflow-x: auto" in diagram_rule
    assert ".diagram svg { max-width: none;" in css
    assert js.count("useMaxWidth: false") == 2  # flowchart and sequence


def test_the_page_shows_each_stage_glossary_with_text_content_only():
    js = (Path(__file__).resolve().parents[1] / "web" / "app.js").read_text(encoding="utf-8")
    assert "glossaryEl(stage.glossary)" in js and '"New terms"' in js
    assert "entry.term" in js and js.count(".innerHTML =") == 1  # the only assignment is Mermaid's SVG


def test_stage_glossary_is_sent_to_the_page(app):
    for _ in range(3):
        app.state.reveal_next()
    assert all("glossary" in stage for stage in state_json(app)["stages"])
