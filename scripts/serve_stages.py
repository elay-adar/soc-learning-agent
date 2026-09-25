"""Show saved stages on the local page (Milestone 4). Makes no model call and uses no usage.

Examples (run from the repo root):
    .venv\\Scripts\\python.exe scripts\\serve_stages.py CVE-2021-44228   (stages from run_stages.py)
    .venv\\Scripts\\python.exe scripts\\serve_stages.py --demo           (invented sample data)

It reads sessions/<CVE>.stages.json, written by scripts/run_stages.py --confirm, starts the page
server on 127.0.0.1 and prints one address. Open that exact address once: it carries the
per-session token. Then type commands here: next, repeat N, help, quit.
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from pydantic import ValidationError  # noqa: E402

from src.demo import demo_stages_file  # noqa: E402
from src.server import DEFAULT_PORT, LocalServer, PageState  # noqa: E402
from src.sources.nvd import normalize_cve_id  # noqa: E402
from src.stage_content import StagesFile  # noqa: E402
from src.terminal import HELP, handle_command  # noqa: E402

SESSIONS = REPO_ROOT / "sessions"


def load_file(args) -> StagesFile | None:
    if args.demo:
        return demo_stages_file()
    if not args.cve_id:
        print("Give a CVE id (for example CVE-2021-44228) or use --demo.")
        return None
    try:
        path = SESSIONS / f"{normalize_cve_id(args.cve_id)}.stages.json"
    except ValueError as exc:
        print(f"Cannot start: {exc}")
        return None
    try:
        return StagesFile.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"No saved stages at {path}. Run scripts/run_stages.py {args.cve_id} --confirm first.")
    except ValidationError as exc:
        print(f"The saved stages are not valid: {exc}")
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Show saved stages on the local page.")
    parser.add_argument("cve_id", nargs="?", help="for example CVE-2021-44228")
    parser.add_argument("--demo", action="store_true", help="show invented sample stages instead")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="preferred port (a free one is used if busy)")
    parser.add_argument("--open", action="store_true", help="open the address in the default browser")
    args = parser.parse_args(argv)

    stages_file = load_file(args)
    if stages_file is None:
        return 1
    state = PageState(stages_file)
    try:
        server = LocalServer(state, port=args.port)
    except FileNotFoundError as exc:
        print(f"Cannot start: {exc}")
        return 1
    server.start()

    print(f"Topic: {stages_file.topic}")
    print(f"Plan: {stages_file.plan.stage_count} stages, {len(stages_file.stages)} written.")
    print(f"\nOpen this address in your browser (it works for this session only):\n  {server.url()}\n")
    print(HELP)
    if args.open:
        webbrowser.open(server.url())
    try:
        while True:
            try:
                line = input("> ")
            except EOFError:
                break
            result = handle_command(state, line)
            if result.message:
                print(result.message)
            if result.quit:
                break
    except KeyboardInterrupt:
        print()
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
