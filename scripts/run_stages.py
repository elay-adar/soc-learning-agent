"""Manual run of the Planner and the Lecturer for stages 1 to 3 (Milestones 3 and 4).

Examples (run from the repo root):
    .venv\\Scripts\\python.exe scripts\\run_stages.py CVE-2021-44228                   (dry run)
    .venv\\Scripts\\python.exe scripts\\run_stages.py CVE-2021-44228 --confirm         (live run)
    .venv\\Scripts\\python.exe scripts\\run_stages.py CVE-2021-44228 --stage 3 --confirm

It reads the Knowledge Pack saved by scripts/run_researcher.py (sessions/<CVE>.researcher.json),
so run the Researcher first. Without --confirm nothing calls the model. With --confirm it makes
one Planner call and one Lecturer call per stage (plus corrections), which counts against the
Claude subscription's usage limits (no API key is used or allowed).

With --stage N (and --confirm) only stage N is written again from the saved stages: one Lecturer
call and no Planner call. Only the last saved stage can be replaced, or the next one added.

Saved (git-ignored):
    sessions/<CVE>.stages.json      the plan and the stages
    sessions/<CVE>.stage<N>.mmd     each diagram, ready to paste into https://mermaid.live
    sessions/<CVE>.stage<N>.frame<K>.mmd   the same for each frame of the attack chain (stage 3)
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

from src.orchestrate import rerun_stage, run_stages  # noqa: E402
from src.researcher import AgentRunError, ApiKeyPresentError, TurnLimitError  # noqa: E402
from src.schemas import KnowledgePack  # noqa: E402
from src.settings import SettingsError, load_settings  # noqa: E402
from src.single_call import SingleCallFailedError  # noqa: E402
from src.sources.nvd import normalize_cve_id  # noqa: E402
from src.stage_content import StagesFile  # noqa: E402
from src.stages_config import StagesConfigError, load_stages_config  # noqa: E402
from src.trace import sample_claims  # noqa: E402

SESSIONS = REPO_ROOT / "sessions"


def show_metrics(name, m) -> None:
    print(
        f"  {name}: turns {m.turns}, attempts {m.attempts}, {m.duration_ms / 1000:.1f}s, "
        f"reported cost {m.cost_usd}, usage {m.usage}"
    )


def print_stage(stage) -> None:
    print(f"\n=== Stage {stage.stage_number}: {stage.title} ===")
    for block in stage.blocks:
        source = f"\n      source: {block.source_url}" if block.source_url else ""
        print(f"  [{block.tag.value}] {block.value}{source}")
    for entry in stage.glossary:
        source = f"\n      source: {entry.definition.source_url}" if entry.definition.source_url else ""
        print(f"  Term: {entry.term} [{entry.definition.tag.value}] {entry.definition.value}{source}")
    if stage.diagram is not None:
        print(f"\n  Diagram ({stage.diagram.type.value}):")
        for line in stage.diagram.mermaid.splitlines():
            print(f"    {line}")
    for entry, frame in zip(stage.chain, stage.frames):
        source = f"\n      source: {entry.detail.source_url}" if entry.detail.source_url else ""
        print(f"\n  Step {entry.step} [{entry.detail.tag.value}] {entry.detail.value}{source}")
        print(f"  Frame {frame.step} of {len(stage.frames)}:")
        for line in frame.mermaid.splitlines():
            print(f"    {line}")


def print_trace(stages, pack, seed: int | None = None) -> None:
    claims, skipped = sample_claims(stages, pack, count=5, rng=random.Random(seed), with_counts=True)
    print(f"\n=== Trace check: {len(claims)} random documented claims ({skipped} other blocks not sampled) ===")
    for n, claim in enumerate(claims, 1):
        print(f"\n  {n}. (stage {claim.stage_number}) {claim.text}\n     cites: {claim.source_url}")
        if not claim.matches:
            print("     ! no Pack entry carries this URL")
        if claim.matches:
            print(f"     closest Pack entries ({len(claim.matches)} of {claim.same_url_total} under this URL):")
        for label, value in claim.matches:
            print(f"     Pack {label}: {value}")


def show_result(run, pack, seed: int | None = None) -> None:
    plan = run.file.plan
    print(f"\n=== Stage plan: {plan.stage_count} stages ===")
    for s in plan.stages:
        print(f"  {s.number}. [{s.key}] {s.subject}  (depth {s.depth.value}, diagram {s.diagram.value})")
    for note in run.not_built:
        print(f"  ! stage '{note}' is planned but not built yet (later milestone)")

    for stage in run.file.stages:
        print_stage(stage)
    print_trace(run.file.stages, pack, seed)

    print("\n--- Run metrics ---")
    show_metrics("Planner", run.planner_metrics)
    for stage, m in zip(run.file.stages, run.stage_metrics):
        show_metrics(f"Stage {stage.stage_number}", m)


def save_diagrams(stage, topic: str) -> None:
    if stage.diagram is not None:
        mmd = SESSIONS / f"{topic}.stage{stage.stage_number}.mmd"
        mmd.write_text(stage.diagram.mermaid.strip() + "\n", encoding="utf-8")
        print(f"Saved diagram {stage.stage_number} to {mmd} (paste it into https://mermaid.live)")
    for frame in stage.frames:
        mmd = SESSIONS / f"{topic}.stage{stage.stage_number}.frame{frame.step}.mmd"
        mmd.write_text(frame.mermaid.strip() + "\n", encoding="utf-8")
        print(f"Saved frame {frame.step} of stage {stage.stage_number} to {mmd}")


def save(run) -> None:
    topic = run.file.topic
    SESSIONS.mkdir(parents=True, exist_ok=True)
    out = SESSIONS / f"{topic}.stages.json"
    out.write_text(run.file.model_dump_json(indent=2), encoding="utf-8")
    print(f"\nSaved plan and stages to {out}")
    for stage in run.file.stages:
        save_diagrams(stage, topic)


def explain_failure(exc: Exception) -> None:
    if isinstance(exc, ApiKeyPresentError):
        print(f"Stopped: {exc}")
    elif isinstance(exc, (TurnLimitError, AgentRunError)):
        print(f"The run failed: {type(exc).__name__}: {exc}")
    elif isinstance(exc, SingleCallFailedError):
        print(f"The output never passed validation: {exc}")
        for i, error in enumerate(exc.errors, 1):
            print(f"  attempt {i}: {error}")
    else:
        print(f"Cannot do that: {exc}")


FAILURES = (ApiKeyPresentError, TurnLimitError, AgentRunError, SingleCallFailedError)


def rerun_one_stage(pack, number, lecturer_settings, config, seed) -> int:
    path = SESSIONS / f"{pack.topic}.stages.json"
    try:
        saved = StagesFile.model_validate_json(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValidationError) as exc:
        print(f"Cannot read the saved stages at {path} ({type(exc).__name__}). Run without --stage first.")
        return 1
    print(f"\nWriting stage {number} again from {path.name} (one Lecturer call, no Planner call)...")
    try:
        new_file, metrics = asyncio.run(rerun_stage(pack, saved, number, lecturer_settings, config))
    except (ValueError, *FAILURES) as exc:
        explain_failure(exc)
        return 1
    stage = new_file.stages[number - 1]
    print_stage(stage)
    print_trace([stage], pack, seed)
    print("\n--- Run metrics ---")
    show_metrics(f"Stage {number}", metrics)
    path.write_text(new_file.model_dump_json(indent=2), encoding="utf-8")
    print(f"\nSaved to {path}")
    save_diagrams(stage, pack.topic)
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Plan and write stages 1 to 3 for one CVE.")
    parser.add_argument("cve_id", help="for example CVE-2021-44228")
    parser.add_argument("--confirm", action="store_true", help="really call the model (uses subscription usage)")
    parser.add_argument("--stage", type=int, default=None,
                        help="write only this stage again from the saved stages (needs --confirm)")
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
    if args.stage is None:
        print(f"Planner:  model {p.model}, effort {p.effort}, corrections allowed {p.max_schema_retries}")
    print(f"Lecturer: model {l.model}, effort {l.effort}, corrections allowed {l.max_schema_retries}")
    print("No tools are available to either role. Stages built so far: overview, why_possible, attack_chain.")

    if not args.confirm:
        what = f"stage {args.stage} only" if args.stage is not None else "the Planner and every stage"
        print(f"\nDry run: no model was called. Add --confirm to run {what} for real.")
        return 0

    if args.stage is not None:
        return rerun_one_stage(pack, args.stage, l, config, args.seed)

    print("\nRunning. This counts against your subscription usage...")
    try:
        run = asyncio.run(run_stages(pack, p, l, config))
    except FAILURES as exc:
        explain_failure(exc)
        return 1

    show_result(run, pack, args.seed)
    save(run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
