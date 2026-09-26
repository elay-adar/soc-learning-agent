"""Secondary sources: a fixed allowlist of two security vendors (D-027, D-029, D-030).

A secondary source is never official. It may be read only to explain a mechanism or an
execution flow that no official source documents in enough detail. Everything here uses the
standard library. Two rules are enforced in code: only https pages on an allowlisted domain
are fetched, and a redirect that leaves the allowlist is refused.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urlparse

from src.sources.http_cache import USER_AGENT, FetchError

# The final list (D-030). A subdomain counts, a look-alike such as crowdstrike.com.evil.example does not.
SECONDARY_DOMAINS = ("crowdstrike.com", "picussecurity.com")

MAX_PAGE_BYTES = 2_000_000
MAX_TEXT_CHARS = 20_000

PageDownloader = Callable[[str], str]  # takes a full URL, returns the page as HTML text


def is_secondary_url(url: str) -> bool:
    """True for an https URL on an allowlisted domain (no credentials in the URL)."""
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    return (
        parts.scheme == "https"
        and parts.username is None
        and any(host == d or host.endswith("." + d) for d in SECONDARY_DOMAINS)
    )


class _RefuseOffAllowlistRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_secondary_url(newurl):
            raise FetchError(f"redirect to {newurl!r} refused: it leaves the secondary-source allowlist")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_page(url: str, timeout: float = 30.0) -> str:
    """GET one allowlisted page and return its HTML text. Raises FetchError otherwise."""
    if not is_secondary_url(url):
        raise FetchError(
            f"{url!r} is not an https page on the secondary-source allowlist ({', '.join(SECONDARY_DOMAINS)})"
        )
    opener = urllib.request.build_opener(_RefuseOffAllowlistRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
    try:
        with opener.open(request, timeout=timeout) as response:
            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type.lower():
                raise FetchError(f"{url} is not an HTML page (Content-Type: {content_type or 'none'})")
            body = response.read(MAX_PAGE_BYTES + 1)
    except FetchError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FetchError(f"could not fetch {url}: {exc}") from exc
    return body[:MAX_PAGE_BYTES].decode("utf-8", errors="replace")


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "noscript", "svg", "head", "nav", "footer", "form", "iframe"}
    _BREAK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag in self._BREAK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1
        elif tag in self._BREAK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip_depth:
            self.parts.append(data)


def html_to_text(html: str, max_chars: int = MAX_TEXT_CHARS) -> str:
    """Visible text of a page, with scripts, styles and navigation removed and length capped."""
    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    lines = (" ".join(line.split()) for line in "".join(parser.parts).splitlines())
    text = "\n".join(line for line in lines if line)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n[text cut: page is longer than the limit]"
    return text
