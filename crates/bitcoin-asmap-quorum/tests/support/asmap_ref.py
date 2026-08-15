#!/usr/bin/env python3
"""Persistent oracle worker wrapping the vendored ``contrib/asmap/asmap.py``.

Driven by ``tests/differential_python.rs``. Speaks JSON-lines on stdin/stdout:
one request object per line in, one response object per line out, in order.

It is a *persistent* worker rather than a process per trial on purpose. The
differential makes several hundred oracle calls; at roughly 60 ms of CPython
start-up each that would be half a minute of pure overhead, which is exactly the
kind of cost that gets a CI job disabled. Through one worker it is ~2 s.

Invoked as::

    python3 -I -B asmap_ref.py <abs path to contrib/asmap>

``-I`` isolates the interpreter from ``PYTHONPATH``, user site-packages and
``PYTHONSTARTUP``; ``-B`` keeps ``contrib/asmap/__pycache__/`` from appearing in
``git status``. The vendored directory is inserted at ``sys.path[0]`` below, so a
pip-installed ``asmap`` can never win the import.

Standard library only. No venv, no pip, no network.
"""

import binascii
import hashlib
import json
import os
import random
import sys

MIN_PYTHON = (3, 9)


def _fail(message):
    print(json.dumps({"error": message}), flush=True)
    sys.exit(1)


def _load_reference(vendored_dir):
    """Import the vendored asmap.py and nothing else."""
    if sys.version_info < MIN_PYTHON:
        _fail(
            "python %s is too old; asmap.py needs >= %s"
            % (".".join(map(str, sys.version_info[:3])), ".".join(map(str, MIN_PYTHON)))
        )
    path = os.path.join(vendored_dir, "asmap.py")
    if not os.path.isfile(path):
        _fail("vendored reference implementation not found at %s" % path)
    sys.path.insert(0, vendored_dir)
    import asmap  # noqa: E402  (deliberately after the sys.path fix-up)

    if os.path.dirname(os.path.abspath(asmap.__file__)) != os.path.abspath(vendored_dir):
        _fail("imported asmap from %s, expected the vendored copy" % asmap.__file__)
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    return asmap, path, digest


def _lines(reference, entries):
    """Render entries the way both implementations print them."""
    return ["%s AS%d" % (reference.prefix_to_net(prefix), asn) for prefix, asn in entries]


def _handle(reference, path, digest, req):
    cmd = req["cmd"]

    if cmd == "preflight":
        return {
            "version": list(sys.version_info[:3]),
            "executable": sys.executable,
            "asmap_path": path,
            "asmap_sha256": digest,
        }

    if cmd == "gen":
        # Seed immediately before generating, so a trial is a pure function of
        # its own seed and not of how many trials ran before it.
        random.seed(req["seed"])
        amap = reference.ASMap.from_random(
            num_leaves=req["leaves"],
            max_asn=req["max_asn"],
            unassigned_prob=req["unassigned"],
        )
        entries = {}
        for overlapping in (False, True):
            for fill in (False, True):
                key = "ov%df%d" % (int(overlapping), int(fill))
                entries[key] = _lines(
                    reference, amap.to_entries(overlapping=overlapping, fill=fill)
                )
        return {
            "bin": {
                "0": amap.to_binary(fill=False).hex(),
                "1": amap.to_binary(fill=True).hex(),
            },
            "entries": entries,
            # The lossless, canonical text form: non-overlapping, no fill.
            # Used as the shared input both implementations start from, so the
            # encode comparison does not presuppose a working decoder.
            "text": "".join(line + "\n" for line in entries["ov0f0"]),
        }

    if cmd == "from_binary":
        raw = binascii.unhexlify(req["hex"])
        amap = reference.ASMap.from_binary(raw)
        if amap is None:
            return {"ok": False}
        return {
            "ok": True,
            "entries": _lines(reference, amap.to_entries(overlapping=False, fill=False)),
        }

    if cmd == "to_entries":
        raw = binascii.unhexlify(req["hex"])
        amap = reference.ASMap.from_binary(raw)
        if amap is None:
            return {"ok": False}
        return {
            "ok": True,
            "lines": _lines(
                reference,
                amap.to_entries(overlapping=req["overlapping"], fill=req["fill"]),
            ),
        }

    if cmd == "quit":
        return None

    _fail("unknown command %r" % (cmd,))


def main():
    if len(sys.argv) != 2:
        _fail("usage: asmap_ref.py <path to contrib/asmap>")
    reference, path, digest = _load_reference(sys.argv[1])

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError as exc:
            _fail("malformed request: %s" % exc)
        try:
            resp = _handle(reference, path, digest, req)
        except Exception as exc:  # pylint: disable=broad-except
            _fail("%s: %s" % (type(exc).__name__, exc))
        if resp is None:
            return
        print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
