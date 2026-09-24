"""Tests for src/sources/http_cache.py. No internet: a fake downloader and a local test server."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from src.sources import http_cache
from src.sources.http_cache import FetchError, build_url, download_json, fetch_json_cached

URL = "https://example.test/data"


class FakeDownloader:
    def __init__(self, payload=None, fail=False):
        self.payload = payload if payload is not None else {"ok": True}
        self.fail = fail
        self.calls = 0

    def __call__(self, url):
        self.calls += 1
        if self.fail:
            raise FetchError("network down")
        return self.payload


def test_build_url_adds_query_parameters():
    assert build_url(URL, {"cveId": "CVE-2021-44228"}) == URL + "?cveId=CVE-2021-44228"
    assert build_url(URL) == URL


def test_first_call_downloads_second_call_uses_cache(tmp_path):
    dl = FakeDownloader()
    first = fetch_json_cached(URL, cache_dir=tmp_path, downloader=dl, now=1000)
    second = fetch_json_cached(URL, cache_dir=tmp_path, downloader=dl, now=1100)
    assert dl.calls == 1
    assert first.from_cache is False and second.from_cache is True
    assert second.data == {"ok": True}


def test_expired_cache_downloads_again(tmp_path):
    dl = FakeDownloader()
    fetch_json_cached(URL, cache_dir=tmp_path, ttl_seconds=60, downloader=dl, now=1000)
    fetch_json_cached(URL, cache_dir=tmp_path, ttl_seconds=60, downloader=dl, now=1061)
    assert dl.calls == 2


def test_network_failure_falls_back_to_stale_cache(tmp_path):
    fetch_json_cached(URL, cache_dir=tmp_path, ttl_seconds=60, downloader=FakeDownloader(), now=1000)
    result = fetch_json_cached(
        URL, cache_dir=tmp_path, ttl_seconds=60, downloader=FakeDownloader(fail=True), now=5000
    )
    assert result.stale is True and result.from_cache is True
    assert result.data == {"ok": True}


def test_network_failure_without_cache_raises(tmp_path):
    with pytest.raises(FetchError):
        fetch_json_cached(URL, cache_dir=tmp_path, downloader=FakeDownloader(fail=True))


def test_stale_fallback_can_be_disabled(tmp_path):
    fetch_json_cached(URL, cache_dir=tmp_path, ttl_seconds=60, downloader=FakeDownloader(), now=1000)
    with pytest.raises(FetchError):
        fetch_json_cached(
            URL, cache_dir=tmp_path, ttl_seconds=60, downloader=FakeDownloader(fail=True),
            allow_stale=False, now=5000,
        )


def test_different_parameters_are_cached_separately(tmp_path):
    dl = FakeDownloader()
    fetch_json_cached(URL, {"cveId": "A"}, cache_dir=tmp_path, downloader=dl, now=1)
    fetch_json_cached(URL, {"cveId": "B"}, cache_dir=tmp_path, downloader=dl, now=1)
    assert dl.calls == 2


def test_corrupt_cache_file_is_ignored(tmp_path):
    dl = FakeDownloader()
    fetch_json_cached(URL, cache_dir=tmp_path, downloader=dl, now=1000)
    for file in tmp_path.glob("*.json"):
        file.write_text("{not json", encoding="utf-8")
    fetch_json_cached(URL, cache_dir=tmp_path, downloader=dl, now=1001)
    assert dl.calls == 2


# ---- download_json against a tiny local server (no internet) ------------------


class _Handler(BaseHTTPRequestHandler):
    responses: list = []  # list of (status, body) served in order; the last one repeats

    def do_GET(self):
        status, body = _Handler.responses[min(_Handler.hits, len(_Handler.responses) - 1)]
        _Handler.hits += 1
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, *args):
        pass


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setattr(http_cache, "_sleep", lambda seconds: None)  # do not really wait
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    _Handler.hits = 0
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}/"
    httpd.shutdown()


def test_download_json_parses_a_good_response(server):
    _Handler.responses = [(200, json.dumps({"a": 1}))]
    assert download_json(server) == {"a": 1}


def test_download_json_retries_after_a_server_error(server):
    _Handler.responses = [(503, "{}"), (200, json.dumps({"a": 2}))]
    assert download_json(server) == {"a": 2}
    assert _Handler.hits == 2


def test_download_json_does_not_retry_a_404(server):
    _Handler.responses = [(404, "{}")]
    with pytest.raises(FetchError):
        download_json(server)
    assert _Handler.hits == 1


def test_download_json_rejects_a_body_that_is_not_json(server):
    _Handler.responses = [(200, "<html>oops</html>")]
    with pytest.raises(FetchError):
        download_json(server)


def test_download_json_gives_up_after_the_retries(server):
    _Handler.responses = [(500, "{}")]
    with pytest.raises(FetchError):
        download_json(server, retries=2)
    assert _Handler.hits == 3
