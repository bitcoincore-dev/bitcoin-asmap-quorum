#!/usr/bin/env python3

import json
import os
import re
import sys
from pathlib import Path


def grab(log: str, pattern: str):
    match = re.search(pattern, log, re.MULTILINE)
    return match.group(1) if match else None


def main() -> int:
    if len(sys.argv) != 4:
        print(
            "usage: summarize-relay-roundtrip.py LOG UTC_TIME SHORT_SHA",
            file=sys.stderr,
        )
        return 1

    log = Path(sys.argv[1]).read_text()
    utc_time = sys.argv[2]
    short_sha = sys.argv[3]

    summary = {
        "workflow": "libp2p_relay_gossipsub_roundtrip",
        "utc_time": utc_time,
        "commit": short_sha,
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
        "relay_bootstrap": grab(log, r"\[libp2p\] relay bootstrap addr: (.+)"),
        "listener_addr": grab(log, r"\[libp2p\] listener relay addr: (.+)"),
        "dialer_addr": grab(log, r"\[libp2p\] dialer relay addr: (.+)"),
        "message_published": "dialer sent relay-backed gossipsub payload" in log,
        "message_received": "listener got gossipsub message" in log,
    }

    json.dump(summary, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
