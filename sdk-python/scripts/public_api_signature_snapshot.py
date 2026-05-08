from __future__ import annotations

import argparse
import importlib
import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
PACKAGE_NAME = "agent_did_sdk"
SNAPSHOT = ROOT / "public-api.signature.snapshot.txt"


def load_public_module():
    if str(SRC_ROOT) not in sys.path:
        sys.path.insert(0, str(SRC_ROOT))
    return importlib.import_module(PACKAGE_NAME)


def render_annotation(annotation: object) -> str:
    if isinstance(annotation, str):
        return annotation
    try:
        return inspect.formatannotation(annotation)
    except Exception:  # noqa: BLE001
        return repr(annotation)


def render_signature(callable_obj: object) -> str:
    try:
        return str(inspect.signature(callable_obj))
    except (TypeError, ValueError):
        return "(...)"


def render_value(value: object) -> str:
    if isinstance(value, (str, int, float, bool, type(None))):
        return repr(value)
    return repr(value)


def render_class(name: str, cls: type[object]) -> list[str]:
    lines = [f"class {name}{render_signature(cls)}"]
    annotations = {
        member_name: annotation
        for member_name, annotation in getattr(cls, "__annotations__", {}).items()
        if not member_name.startswith("_")
    }

    for member_name in sorted(annotations):
        lines.append(f"  attr {member_name}: {render_annotation(annotations[member_name])}")

    for member_name in sorted(name for name in cls.__dict__ if not name.startswith("_")):
        if member_name in annotations:
            continue

        member = cls.__dict__[member_name]
        if isinstance(member, property):
            lines.append(f"  property {member_name}")
            continue

        if isinstance(member, classmethod):
            lines.append(f"  classmethod {member_name}{render_signature(member.__func__)}")
            continue

        if isinstance(member, staticmethod):
            lines.append(f"  staticmethod {member_name}{render_signature(member.__func__)}")
            continue

        if inspect.isfunction(member):
            lines.append(f"  def {member_name}{render_signature(member)}")
            continue

        lines.append(f"  member {member_name} = {render_value(member)}")

    return lines


def render_public_symbol(name: str, value: object) -> list[str]:
    if inspect.isclass(value):
        return render_class(name, value)

    if inspect.isfunction(value) or inspect.ismethod(value) or inspect.isbuiltin(value):
        return [f"def {name}{render_signature(value)}"]

    return [f"value {name} = {render_value(value)}"]


def render_snapshot() -> str:
    module = load_public_module()
    public_names = sorted(getattr(module, "__all__", []))
    sections = ["# Public API signature snapshot for agent-did-sdk"]

    for name in public_names:
        if not hasattr(module, name):
            raise SystemExit(f"Public symbol {name!r} is listed in __all__ but not exposed by {PACKAGE_NAME}.")

        sections.append("")
        sections.append(f"## {name}")
        sections.extend(render_public_symbol(name, getattr(module, name)))

    return "\n".join(sections) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate or verify the signature-level public API snapshot for agent-did-sdk."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="Write the current signature snapshot to disk.")
    mode.add_argument(
        "--check",
        action="store_true",
        help="Verify that the checked-in signature snapshot matches the current public API.",
    )
    args = parser.parse_args()

    next_snapshot = render_snapshot()

    if args.write:
        SNAPSHOT.write_text(next_snapshot, encoding="utf-8")
        print(f"Wrote {SNAPSHOT.relative_to(ROOT)}")
        return 0

    current_snapshot = SNAPSHOT.read_text(encoding="utf-8") if SNAPSHOT.exists() else ""
    if current_snapshot != next_snapshot:
        print(
            (
                "Public API signature snapshot is out of date. Run "
                "`python sdk-python/scripts/public_api_signature_snapshot.py --write` "
                "or `npm run api:signature:snapshot:python` at the repo root."
            ),
            file=sys.stderr,
        )
        return 1

    print(f"Public API signature snapshot is up to date: {SNAPSHOT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
