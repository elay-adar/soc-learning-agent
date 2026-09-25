# Vendored Mermaid

The local page draws diagrams with Mermaid. The library is stored here so the page works offline
and never loads code from the network (spec section 7, D-023).

| Item | Value |
|---|---|
| Package | `mermaid` from npm |
| Version | 11.17.2 (pinned) |
| License | MIT, see `LICENSE` |
| File | `mermaid.min.js` (single-file browser bundle, `dist/mermaid.min.js` in the package) |
| SHA-256 | `581ed7d74bd9048d0e3a91363927d72ef22942d7722546b27f7cc29e35390eb8` |

## How it was checked (2026-09-25)

The file was downloaded from `https://cdn.jsdelivr.net/npm/mermaid@11.17.2/dist/mermaid.min.js`.
It was then compared byte for byte with `dist/mermaid.min.js` inside the official npm tarball
`https://registry.npmjs.org/mermaid/-/mermaid-11.17.2.tgz`. The tarball's SHA-512 matched the
`dist.integrity` value published by the npm registry
(`sha512-V6K3C8EBdEsPFZXSKMJe6ppQOENxuHARr9GvHX4hh47lAbhMRD9qf4oEK7LoaRQxULMa80/qt5gHO73aCleBBg==`).
`LICENSE` is identical to the one in the tarball.

## Updating

Never edit `mermaid.min.js`. To change the version, download the new file, repeat the check above,
update the version and hash in this file and in `tests/test_vendor.py`, and add a new entry to
`decisions.md`. `tests/test_vendor.py` fails if the file's hash differs from the pinned one.
