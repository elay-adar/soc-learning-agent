"""Manual run of the Planner and the Lecturer for stages 1 and 2 (Milestone 3).

Examples (run from the repo root):
    .venv\\Scripts\\python.exe scripts\\run_stages.py CVE-2021-44228            (dry run)
    .venv\\Scripts\\python.exe scripts\\run_stages.py CVE-2021-44228 --confirm  (live run)

It reads the Knowledge Pack saved by scripts/run_researcher.py (sessions/<CVE>.researcher.json),
so run the Researcher first. Without --confirm nothing calls the model. With --confirm it makes
one Planner call and one Lecturer call per stage (plus corrections), which counts against the
Claude subscription's usage limits (no API key is used or allowed).

Saved (git-ignored):
    sessions/<CVE>.stages.json      the plan and the stages
    sessions/<CVE>.stage<N>.mmd     each diagram, ready to paste into https://mermaid.live
The script also prints five random documented claims next to the Pack entries they cite, for the
manual "five claims trace to the Pack" check.
"""

from __future__ import annotations

import argparse
import asyncio
import random
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from pydantic import ValidationError  # noqa: E402

from src.orchestrate import run_stages  # noqa: E402
from src.researcher import AgentRunError, ApiKeyPresentError, TurnLimitError  # noqa: E402
from src.schemas import KnowledgePack  # noqa: E402
from src.settings import SettingsError, load_settings  # noqa: E402
from src.single_call import SingleCallFailedError  # noqa: E402
from src.sources.nvd import normalize_cve_id  # noqa: E402
from src.stages_config import StagesConfigError, load_stages_config  # noqa: E402
from src.trace import sample_claims  # noqa: E402

SESSIONS = REPO_ROOT / "sessions"


def show_metrics(name, m) -> None:
    print(
        f"  {name}: turns {m.turns}, attempts {m.attempts}, {m.duration_ms / 1000:.1f}s, "
        f"reported cost {m.cost_usd}, usage {m.usage}"
    )


def show_result(run, pack, seed: int | None = None) -> None:
    plan = run.file.plan
    print(f"\n=== Stage plan: {plan.stage_count} stages ===")
    for s in plan.stages:
        print(f"  {s.number}. [{s.key}] {s.subject}  (depth {s.depth.value}, diagram {s.diagram.value})")
    for note in run.not_built:
        print(f"  ! stage '{note}' is planned but not built yet (later milestone)")

    for stage in run.file.stages:
        print(f"\n=== Stage {stage.stage_number}: {stage.title} ===")
        for block in stage.blocks:
            source = f"\n      source: {block.source_url}" if block.source_url else ""
            print(f"  [{block.tag.value}] {block.value}{source}")
        print(f"\n  Diagram ({stage.diagram.type.value}):")
        for line in stage.diagram.mermaid.splitlines():
            print(f"    {line}")

    claims, skipped = sample_claims(
        run.file.stages, pack, count=5, rng=random.Random(seed), with_counts=True
    )
    print(f"\n=== Trace check: {len(claims)} random documented claims ({skipped} other blocks not sampled) ===")
    for n, claim in enumerate(claims, 1):
        print(f"\n  {n}. (stage {claim.stage_number}) {claim.text}\n     cites: {claim.source_url}")
        if not claim.matches:
            print("     ! no Pack entry carries this URL")
        if claim.matches:
            print(f"     closest Pack entries ({len(claim.matches)} of {claim.same_url_total} under this URL):")
        for label, value in claim.matches:
            print(f"     Pack {label}: {value}")

    print("\n--- Run metrics ---")
    show_metrics("Planner", run.planner_metrics)
    for stage, m in zip(run.file.stages, run.stage_metrics):
        show_metrics(f"Stage {stage.stage_number}", m)


def save(run) -> None:
    topic = run.file.topic
    SESSIONS.mkdir(parents=True, exist_ok=True)
    out = SESSIONS / f"{topic}.stages.json"
    out.write_text(run.file.model_dump_json(indent=2), encoding="utf-8")
    print(f"\nSaved plan and stages to {out}")
    for stage in run.file.stages:
        mmd = SESSIONS / f"{topic}.stage{stage.stage_number}.mmd"
        mmd.write_text(stage.diagram.mermaid.strip() + "\n", encoding="utf-8")
        print(f"Saved diagram {stage.stage_number} to {mmd} (paste it into https://mermaid.live)")


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Plan and write stages 1 and 2 for one CVE.")
    parser.add_argument("cve_id", help="for example CVE-2021-44228")
    parser.add_argument("--confirm", action="store_true", help="really call the model (uses subscription usage)")
    parser.add_argument("--seed", type=int, default=None, help="seed for the random claim sample")
    args = parser.parse_args(argv)

    try:
        cve_id = normalize_cve_id(args.cve_id)
        settings = load_settings()
        config = load_stages_config()
    except (ValueError, SettingsError, StagesConfigError) as exc:
        print(f"Cannot start: {exc}")
        return 1

    pack_path = SESSIONS / f"{cve_id}.researcher.json"
    try:
        pack = KnowledgePack.model_validate_json(pack_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"No Knowledge Pack at {pack_path}. Run scripts/run_researcher.py {cve_id} --confirm first.")
        return 1
    except ValidationError as exc:
        print(f"The saved Knowledge Pack is not valid: {exc}")
        return 1

    p, l = settings.planner, settings.lecturer
    print(f"Topic: {pack.topic}   exploitation status: {pack.exploitation_status.value}")
    print(f"Planner:  model {p.model}, effort {p.effort}, corrections allowed {p.max_schema_retries}")
    print(f"Lecturer: model {l.model}, effort {l.effort}, corrections allowed {l.max_schema_retries}")
    print("No tools are available to either role. Stages built so far: overview, why_possible.")

    if not args.confirm:
        print("\nDry run: no model was called. Add --confirm to run for real.")
        return 0

    print("\nRunning. This counts against your subscription usage...")
    try:
        run = asyncio.run(run_stages(pack, p, l, config))
    except ApiKeyPresentError as exc:
        print(f"Stopped: {exc}")
        return 1
    except (TurnLimitError, AgentRunError) as exc:
        print(f"The run failed: {type(exc).__name__}: {exc}")
        return 1
    except SingleCallFailedError as exc:
        print(f"The output never passed validation: {exc}")
        for i, error in enumerate(exc.errors, 1):
            print(f"  attempt {i}: {error}")
        return 1

    show_result(run, pack, args.seed)
    save(run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
