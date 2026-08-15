#!/usr/bin/env python3

import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: extract-ris-bottleneck.py LOG OUTPUT", file=sys.stderr)
        return 1

    log_lines = Path(sys.argv[1]).read_text().splitlines()
    output = Path(sys.argv[2])

    marker = "[integration] bottleneck report:"
    start = None
    for idx, line in enumerate(log_lines):
        if line.strip() == marker:
            start = idx + 1
            break

    if start is None:
        print("bottleneck report marker not found in test log", file=sys.stderr)
        return 1

    report = []
    for line in log_lines[start:]:
        if line.startswith("[integration]") or line.startswith("##["):
            break
        if line.startswith("test\t") or line.startswith("test "):
            break
        report.append(line)

    text = "\n".join(report).strip()
    if not text:
        print("bottleneck report was empty", file=sys.stderr)
        return 1

    output.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
