"""Manual check for Part A: fetch facts from official sources and show them.

Examples (run from the repo root):
    .venv\\Scripts\\python.exe scripts\\fetch_facts.py CVE-2021-44228
    .venv\\Scripts\\python.exe scripts\\fetch_facts.py --technique T1558.003
    .venv\\Scripts\\python.exe scripts\\fetch_facts.py CVE-2021-44228 --technique T1190

No model is used, so this costs no usage from the subscription. The point is to
compare what it prints with the official pages, one field at a time.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.facts import CveNotFoundError, collect_facts  # noqa: E402
from src.schemas import FieldStatus  # noqa: E402
from src.sources.attack import fetch_attack_index  # noqa: E402
from src.sources.http_cache import DEFAULT_CACHE_DIR, FetchError  # noqa: E402


def show_cve(cve_id: str, cache_dir: Path, save: bool) -> int:
    try:
        result = collect_facts(cve_id, cache_dir=cache_dir)
    except CveNotFoundError as exc:
        print(f"Not found: {exc}")
        return 1
    except (ValueError, FetchError) as exc:
        print(f"Could not collect facts: {exc}")
        return 1

    pack = result.pack
    print(f"\n=== {pack.topic} ===")
    print(f"Exploitation status: {pack.exploitation_status.value}")
    if pack.exploitation_evidence:
        print(f"  evidence: {pack.exploitation_evidence.value}")
        print(f"  source:   {pack.exploitation_evidence.source_url}")

    print("\nTriage card:")
    for name, item in pack.triage_fields.items():
        if item.status == FieldStatus.VALUE:
            print(f"  {name}: {item.item.value}")
            print(f"      source: {item.item.source_url}")
        else:
            print(f"  {name}: ({item.status.value})")

    print("\nOfficial descriptions:")
    for description in pack.weakness_mechanism:
        print(f"  - {description.value}")
        print(f"      source: {description.source_url}")

    if result.notes:
        print("\nNotes:")
        for note in result.notes:
            print(f"  ! {note}")

    if save:
        out = REPO_ROOT / "sessions" / f"{pack.topic}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(pack.model_dump_json(indent=2), encoding="utf-8")
        print(f"\nSaved partial Knowledge Pack to {out}")
    return 0


def show_technique(technique_id: str, cache_dir: Path) -> int:
    print("\nLoading ATT&CK data (the first run downloads about 50 MB and can take a minute)...")
    try:
        index, _ = fetch_attack_index(cache_dir=cache_dir)
    except (ValueError, FetchError) as exc:
        print(f"Could not load ATT&CK data: {exc}")
        return 1
    technique = index.find(technique_id)
    if technique is None:
        print(f"{technique_id}: no active technique with this id in ATT&CK {index.version}")
        return 1
    kind = "sub-technique" if technique.is_subtechnique else "technique"
    print(f"\n=== {technique.technique_id}: {technique.name} ({kind}, ATT&CK {index.version}) ===")
    print(f"Tactics: {', '.join(technique.tactics) or '(none listed)'}")
    print(f"Source:  {technique.url}")
    text = technique.description
    print(f"\n{text[:600]}{'...' if len(text) > 600 else ''}")
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Fetch official facts for a CVE and/or an ATT&CK technique.")
    parser.add_argument("cve_id", nargs="?", help="for example CVE-2021-44228")
    parser.add_argument("--technique", help="ATT&CK technique id, for example T1558.003")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--no-save", action="store_true", help="do not write the Knowledge Pack file")
    args = parser.parse_args(argv)

    if not args.cve_id and not args.technique:
        parser.error("give a CVE id, a --technique id, or both")

    code = 0
    if args.cve_id:
        code |= show_cve(args.cve_id, args.cache_dir, save=not args.no_save)
    if args.technique:
        code |= show_technique(args.technique, args.cache_dir)
    return code


if __name__ == "__main__":
    sys.exit(main())
