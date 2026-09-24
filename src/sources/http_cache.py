"""Fetch JSON over HTTP with retries and a small on-disk cache.

Only the standard library is used. The cache exists for two reasons: NVD limits
how many requests a client may send, and re-running the agent on the same topic
should not repeat network calls.
"""

from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

USER_AGENT = "soc-learning-agent/0.1 (personal learning project)"

# <repo root>/.cache  (this file lives in <repo root>/src/sources/)
DEFAULT_CACHE_DIR = Path(__file__).resolve().parents[2] / ".cache"

RETRY_STATUS = {403, 429, 500, 502, 503, 504}  # NVD signals rate limiting with 403 or 429

_sleep = time.sleep  # replaced in tests


class FetchError(Exception):
    """A resource could not be fetched or was not valid JSON."""


@dataclass(frozen=True)
class FetchResult:
    data: Any
    fetched_at: str  # ISO 8601, UTC
    from_cache: bool
    stale: bool = False  # True when the network failed and old cached data was used


Downloader = Callable[[str], Any]  # takes a full URL, returns parsed JSON


def build_url(url: str, params: dict[str, str] | None = None) -> str:
    if not params:
        return url
    return f"{url}?{urllib.parse.urlencode(params)}"


def download_json(url: str, timeout: float = 30.0, retries: int = 2) -> Any:
    """GET a URL and parse the body as JSON. Retries on rate limits and server errors."""
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read()
            try:
                return json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise FetchError(f"response from {url} is not valid JSON: {exc}") from exc
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in RETRY_STATUS or attempt == retries:
                break
            _sleep(6 * (attempt + 1) if exc.code in (403, 429) else 2**attempt)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            if attempt == retries:
                break
            _sleep(2**attempt)
    raise FetchError(f"could not fetch {url}: {last_error}")


def _cache_path(cache_dir: Path, full_url: str) -> Path:
    return cache_dir / (hashlib.sha256(full_url.encode("utf-8")).hexdigest()[:32] + ".json")


def _read_cache(path: Path) -> dict | None:
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
        entry["fetched_ts"], entry["fetched_at"], entry["data"]  # required keys
        return entry
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _write_cache(path: Path, entry: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(entry), encoding="utf-8")
    tmp.replace(path)


def fetch_json_cached(
    url: str,
    params: dict[str, str] | None = None,
    *,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    ttl_seconds: float = 86_400,
    downloader: Downloader = download_json,
    allow_stale: bool = True,
    now: float | None = None,
) -> FetchResult:
    """Return JSON for a URL, using the cache while it is fresh.

    If the network fails and an older cached copy exists, that copy is returned
    with stale=True (unless allow_stale is False).
    """
    full_url = build_url(url, params)
    path = _cache_path(cache_dir, full_url)
    now_ts = time.time() if now is None else now
    cached = _read_cache(path)

    if cached is not None and now_ts - cached["fetched_ts"] < ttl_seconds:
        return FetchResult(cached["data"], cached["fetched_at"], from_cache=True)

    try:
        data = downloader(full_url)
    except FetchError:
        if cached is not None and allow_stale:
            return FetchResult(cached["data"], cached["fetched_at"], from_cache=True, stale=True)
        raise

    fetched_at = datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat(timespec="seconds")
    _write_cache(path, {"url": full_url, "fetched_ts": now_ts, "fetched_at": fetched_at, "data": data})
    return FetchResult(data, fetched_at, from_cache=False)
