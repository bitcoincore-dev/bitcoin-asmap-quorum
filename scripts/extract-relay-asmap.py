#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: extract-relay-asmap.py LOG OUTPUT", file=sys.stderr)
        return 1

    log = Path(sys.argv[1]).read_text()
    output = Path(sys.argv[2])
    match = re.search(r"\[libp2p\] relay payload json: (\{.*\})", log)
    if not match:
        print("relay payload json not found in test log", file=sys.stderr)
        return 1

    payload = json.loads(match.group(1))
    output.write_text(payload["human_readable"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
