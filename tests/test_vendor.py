"""The vendored Mermaid file must be exactly the pinned release. No network."""

import hashlib
from pathlib import Path

VENDOR = Path(__file__).resolve().parents[1] / "web" / "vendor"
PINNED_VERSION = "11.17.2"
PINNED_SHA256 = "581ed7d74bd9048d0e3a91363927d72ef22942d7722546b27f7cc29e35390eb8"


def test_mermaid_file_matches_the_pinned_hash():
    digest = hashlib.sha256((VENDOR / "mermaid.min.js").read_bytes()).hexdigest()
    assert digest == PINNED_SHA256, "mermaid.min.js changed: see web/vendor/README.md before updating"


def test_mermaid_file_is_the_pinned_version():
    text = (VENDOR / "mermaid.min.js").read_text(encoding="utf-8")
    assert f'"{PINNED_VERSION}"' in text


def test_license_is_kept_next_to_the_file():
    assert "MIT License" in (VENDOR / "LICENSE").read_text(encoding="utf-8")


def test_readme_records_the_same_version_and_hash():
    readme = (VENDOR / "README.md").read_text(encoding="utf-8")
    assert PINNED_SHA256 in readme and PINNED_VERSION in readme
