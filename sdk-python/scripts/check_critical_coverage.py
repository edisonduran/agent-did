"""C-QA-2 gate (docs/RELEASE-1.0-CRITERIA.md): every line of the crypto, signing, verification and resolver modules.

Reads the JSON report of ``pytest --cov=agent_did_sdk --cov-report=json:<path>`` and fails when a file of those
modules has a missed line. A defensive branch no input can reach carries ``# pragma: no cover`` with the reason.
TypeScript parity: the per-module ``coverageThreshold`` in ``sdk/jest.config.js``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

CRITICAL = re.compile(r"^(crypto|verification|resolver|http_signatures)/|^core/(http_signatures|message_signing)\.py$")


def main(report_path: str) -> int:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    checked = 0
    failures: list[str] = []
    for path, data in sorted(report["files"].items()):
        relative = path.replace("\\", "/").split("agent_did_sdk/", 1)[-1]
        if not CRITICAL.search(relative):
            continue
        checked += 1
        missing = data["missing_lines"]
        if missing:
            failures.append(f"  {relative}: lines {', '.join(str(line) for line in missing)}")
    if checked == 0:
        print("No critical module found in the coverage report", file=sys.stderr)
        return 1
    if failures:
        print("Critical modules must have every line covered (C-QA-2):", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Critical module coverage: 100% of lines in {checked} files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.json"))
