# Bitcoin Core ASMap notes

This repository vendors Bitcoin Core under `bitcoin/` and uses its ASMap fixture
and runtime code as reference material for the quorum workflow.

## Where the real ASMap lives

- Fixture: `bitcoin/src/test/data/asmap.raw`
- Test reference: `bitcoin/test/functional/feature_asmap.py`
- Unit-test packaging: `bitcoin/src/test/CMakeLists.txt`

The `asmap.raw` file is a checked-in Bitcoin Core test artifact, not generated
by this project.

## Where Bitcoin Core uses ASMap

Bitcoin Core loads and applies ASMap when the `-asmap=<file>` option is set:

- `bitcoin/src/init.cpp` calls `DecodeAsmap(asmap_path)` during startup.
- `bitcoin/src/util/asmap.cpp` validates and decodes the binary ASMap file.
- `bitcoin/src/netgroup.cpp` maps IPs to ASNs with `NetGroupManager::GetMappedAS()`.
- `bitcoin/src/addrman.cpp` uses that mapped ASN when bucketing peers.
- `bitcoin/src/rpc/net.cpp` exposes the mapped ASN in peer RPC output.

## Why it matters

ASMap lets Bitcoin Core group peers by network ownership instead of raw IP
prefixes. That improves peer diversity in `addrman` and makes it harder for a
single ASN to dominate peer selection.

## In this repo

The Rust CLI can:

- decode `bitcoin/src/test/data/asmap.raw`
- import ASMap snapshots into claims
- replay claims into an offline consensus ASMap
- compare the resulting map against Bitcoin Core behavior

