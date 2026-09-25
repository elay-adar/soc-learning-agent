# Test fixtures

- `kev_sample.json`: real entries and header from the official CISA KEV catalog (public data),
  trimmed to two well-known entries.
- `attack_bundle_sample.json`: real technique objects from MITRE ATT&CK Enterprise (public data),
  trimmed. The `x-mitre-collection` object is a minimal stand-in that only carries the version.
  Includes a revoked technique (T1066), a deprecated one (T1153) and a non-technique object.
- `nvd_synthetic_*.json`: SYNTHETIC. Shaped like NVD API 2.0 responses but built by hand,
  with fictional IDs (CVE-2099-xxxx) and a fictional vendor. They test the parser, not real data.
- `nvd_synthetic_injection.json`: SYNTHETIC, like the others, but the English description carries a hostile
  prompt-injection payload (fake instructions, a fake closing marker, a made-up URL). Used to check that fetched text stays data.
