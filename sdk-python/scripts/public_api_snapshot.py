from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "src" / "agent_did_sdk" / "__init__.py"
SNAPSHOT = ROOT / "public-api.snapshot.txt"


def load_public_names() -> list[str]:
    module = ast.parse(ENTRYPOINT.read_text(encoding="utf-8"))

    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue

        if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
            continue

        if not isinstance(node.value, (ast.List, ast.Tuple)):
            raise SystemExit("Expected __all__ to be a static list or tuple of public names.")

        public_names: list[str] = []
        for element in node.value.elts:
            if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                raise SystemExit("Expected __all__ to contain only string literals.")
            public_names.append(element.value)

        return sorted(public_names)

    raise SystemExit("Could not find __all__ in sdk-python/src/agent_did_sdk/__init__.py")


def render_snapshot() -> str:
    lines = ["# Public API snapshot for agent-did-sdk", *load_public_names()]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate or verify the public API snapshot for agent-did-sdk.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="Write the current public API snapshot to disk.")
    mode.add_argument("--check", action="store_true", help="Verify that the checked-in snapshot matches __all__.")
    args = parser.parse_args()

    next_snapshot = render_snapshot()

    if args.write:
        SNAPSHOT.write_text(next_snapshot, encoding="utf-8")
        print(f"Wrote {SNAPSHOT.relative_to(ROOT)}")
        return 0

    current_snapshot = SNAPSHOT.read_text(encoding="utf-8") if SNAPSHOT.exists() else ""
    if current_snapshot != next_snapshot:
        print(
            "Public API snapshot is out of date. Run `python sdk-python/scripts/public_api_snapshot.py --write` "
            "or `npm run api:snapshot` at the repo root.",
            file=sys.stderr,
        )
        return 1

    print(f"Public API snapshot is up to date: {SNAPSHOT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
