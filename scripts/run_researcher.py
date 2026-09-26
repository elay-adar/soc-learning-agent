"""Manual run of the Researcher agent (Milestone 2 part B, technique path D-033).

Examples (run from the repo root):
    .venv\\Scripts\\python.exe scripts\\run_researcher.py CVE-2021-44228            (dry run)
    .venv\\Scripts\\python.exe scripts\\run_researcher.py CVE-2021-44228 --confirm  (live run)
    .venv\\Scripts\\python.exe scripts\\run_researcher.py T1558.003 --source-url <page> --confirm

A technique id (no CVE) needs at least one --source-url: an https page on crowdstrike.com or
picussecurity.com that you choose. The agent reads only those pages, plus ATT&CK.

Without --confirm nothing calls the model: the script only shows the settings and the
locked-down tool list it would use. With --confirm it runs the agent for real, which counts
against the Claude subscription's usage limits (no API key is used or allowed).
The result is saved to sessions/<CVE or technique id>.researcher.json (git-ignored) so it can be checked
against the official pages, field by field.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.facts import CveNotFoundError, CveRejectedError, TechniqueNotFoundError  # noqa: E402
from src.researcher import (  # noqa: E402
    AgentRunError,
    ApiKeyPresentError,
    ResearcherFailedError,
    SourceUrlError,
    TurnLimitError,
    check_source_urls,
    run_researcher,
    topic_type_of,
)
from src.researcher_tools import ALLOWED_TOOL_NAMES, TECHNIQUE_ALLOWED_TOOL_NAMES  # noqa: E402
from src.schemas import ExploitationStatus, FieldStatus, TopicType  # noqa: E402
from src.settings import SettingsError, load_settings  # noqa: E402
from src.sources.attack import normalize_technique_id  # noqa: E402
from src.sources.http_cache import DEFAULT_CACHE_DIR, FetchError  # noqa: E402
from src.sources.nvd import normalize_cve_id  # noqa: E402


def print_pack(run) -> None:
    pack = run.pack
    print(f"\n=== {pack.topic} ===")
    if pack.exploitation_status == ExploitationStatus.NOT_APPLICABLE:
        print("Exploitation status: not applicable (a technique has no incident to document)")
    else:
        print(f"Exploitation status (set by code from KEV): {pack.exploitation_status.value}")

    print("\nTriage card (set by code):")
    for name, item in pack.triage_fields.items():
        if item.status == FieldStatus.VALUE:
            print(f"  {name}: {item.item.value}\n      source: {item.item.source_url}")
        else:
            print(f"  {name}: ({item.status.value})")

    def show(title, entries):
        print(f"\n{title}: {len(entries)}")
        for value in entries:
            src = value.source_url or "-"
            print(f"  [{value.tag.value}] {value.value}\n      source: {src}")

    print("\n--- Added by the agent ---")
    show("Mechanism entries (includes the official descriptions from code)", pack.weakness_mechanism)
    print(f"\nAttack steps: {len(pack.attack_steps)}")
    for step in pack.attack_steps:
        print(
            f"  {step.number}. [{step.action.tag.value}] {step.action.value} "
            f"(ATT&CK: {step.mitre_technique or '-'})\n      source: {step.action.source_url or '-'}"
        )
    show("Incidents", [i.impact for i in pack.incidents])
    show("Detection items", [d.content for d in pack.detection_items])
    show("Response items", [r.content for r in pack.response_items])
    print(f"\nSource conflicts: {len(pack.conflicts)}")

    m = run.metrics
    print("\n--- Run metrics ---")
    print(f"Turns: {m.turns}   tool calls: {m.tool_calls}   validation attempts: {m.attempts}")
    print(f"Duration: {m.duration_ms / 1000:.1f}s   reported cost: {m.cost_usd}   usage: {m.usage}")
    print(f"Triage fields with a source: {m.fields_with_source}   unknown or n/a: {m.fields_without_source}")
    print("URLs returned by tools this run:")
    for url in sorted(run.tool_urls):
        print(f"  {url}")
    for note in run.notes:
        print(f"  ! {note}")


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Run the Researcher agent for one CVE or one ATT&CK technique.")
    parser.add_argument("topic", help="a CVE id (CVE-2021-44228) or an ATT&CK technique id (T1558.003)")
    parser.add_argument(
        "--source-url",
        action="append",
        default=[],
        help="technique runs only: a crowdstrike.com or picussecurity.com page to read (repeatable)",
    )
    parser.add_argument("--confirm", action="store_true", help="really run the agent (uses subscription usage)")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    args = parser.parse_args(argv)

    try:
        topic_type = topic_type_of(args.topic)
        if topic_type == TopicType.TECHNIQUE:
            topic = normalize_technique_id(args.topic)
        else:
            topic = normalize_cve_id(args.topic)
        source_urls = check_source_urls(topic_type, args.source_url)
        settings = load_settings().researcher
    except (ValueError, SettingsError) as exc:  # SourceUrlError is a ValueError
        print(f"Cannot start: {exc}")
        return 1

    print(f"Topic: {topic} ({topic_type.value})")
    for url in source_urls:
        print(f"Source page: {url}")
    print(f"Model: {settings.model}   effort: {settings.effort}")
    print(f"Turn cap: {settings.max_turns}   corrections allowed: {settings.max_schema_retries}")
    print("Tools the agent can use (everything else is off):")
    for name in TECHNIQUE_ALLOWED_TOOL_NAMES if topic_type == TopicType.TECHNIQUE else ALLOWED_TOOL_NAMES:
        print(f"  {name}")

    if not args.confirm:
        print("\nDry run: no model was called. Add --confirm to run the agent for real.")
        return 0

    print("\nRunning the agent. This counts against your subscription usage...")
    try:
        run = asyncio.run(
            run_researcher(topic, settings, cache_dir=args.cache_dir, source_urls=source_urls)
        )
    except ApiKeyPresentError as exc:
        print(f"Stopped: {exc}")
        return 1
    except (CveNotFoundError, CveRejectedError, TechniqueNotFoundError, SourceUrlError, FetchError) as exc:
        print(f"Could not collect the facts: {exc}")
        return 1
    except (TurnLimitError, AgentRunError) as exc:
        print(f"The agent run failed: {type(exc).__name__}: {exc}")
        return 1
    except ResearcherFailedError as exc:
        print(f"The agent's output never passed validation: {exc}")
        for i, error in enumerate(exc.errors, 1):
            print(f"  attempt {i}: {error}")
        return 1

    print_pack(run)
    out = REPO_ROOT / "sessions" / f"{run.pack.topic}.researcher.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(run.pack.model_dump_json(indent=2), encoding="utf-8")
    print(f"\nSaved Knowledge Pack to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
