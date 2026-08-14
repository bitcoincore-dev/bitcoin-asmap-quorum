# bitcoin-asmap-quorum

Rust CLI for ASMap conversion/diff workflows plus quorum-based ASMap consensus artifacts.

## Build, test, and lint

```bash
cargo build
cargo test -- --nocapture
cargo fmt --check
cargo clippy --all-targets --all-features
```

Run one named test:

```bash
cargo test network_roundtrip_ipv4 -- --exact --nocapture
```

## Binaries

- Default binary: `bitcoin-asmap-quorum`
- Alternate binary: `asmap-quorum`

Both binaries call the same `bitcoin_asmap_quorum::run()` entrypoint.

## ASMap text format

- One mapping per line: `prefix AS<number>`
- Example: `1.2.3.0/24 AS64512`
- `#` inline comments are supported
- IPv4 and IPv6 are both accepted

## CLI reference

General form:

```bash
cargo run -- <subcommand> [options]
# or
cargo run --bin asmap-quorum -- <subcommand> [options]
```

### `encode`

Convert text ASMap to binary format.

```bash
encode [-f|--fill] [infile] [outfile]
```

- `-f, --fill`: fill unassigned ranges during export
- `infile`/`outfile` omitted means stdin/stdout

### `decode`

Convert binary ASMap to text format.

```bash
decode [-f|--fill] [-n|--nonoverlapping] [infile] [outfile]
```

- `-f, --fill`: include unassigned ranges
- `-n, --nonoverlapping`: emit non-overlapping prefixes
- `infile`/`outfile` omitted means stdin/stdout

### `diff`

Compare two ASMap files.

```bash
diff [-i|--ignore-unassigned] infile1 infile2
```

- `-i, --ignore-unassigned`: skip changes from unassigned (`AS0`)

### `diff_addrs` / `diff-addrs`

Compare ASMap assignment changes for address samples.

```bash
diff_addrs [-s|--show-addresses] infile1 infile2 addrs_file
```

- `-s, --show-addresses`: print changed addresses by reassignment bucket
- `addrs_file` must be JSON like `bitcoin-cli getnodeaddresses` output
- only entries with `network == "ipv4"` or `network == "ipv6"` are used

### `import`

Convert one or more snapshot ASMap inputs into signed claim JSON.

```bash
import [--epoch N] [--sender-prefix PREFIX] [--output FILE] snapshot1 [snapshot2...]
```

- default epoch: `1`
- default sender prefix: `snapshot`
- default output: `claims.json`

### `replay`

Replay claims offline to produce quorum map + JSON report.

```bash
replay [--threshold N] [--epoch N] [--topic NAME] [--local-peer-id ID] [--output FILE] [--report FILE] claims.json
```

- default threshold: `3`
- default topic: `bitcoin-asmap-quorum`
- default local peer-id: `offline-replay`
- default map output: `asmap.map`
- default report output: `asmap.json`

### `verify`

Validate a JSON consensus report and optionally match a map file.

```bash
verify report.json [mapfile]
```

### `compare`

Compare two JSON consensus reports at prefix level.

```bash
compare report1.json report2.json
```

### `serve`

Run a networked quorum node serving one local ASMap snapshot.

```bash
serve [--threshold N] [--epoch N] [--epoch-secs N] [--topic NAME] [--bootstrap ADDR[,ADDR...]] [--relay ADDR[,ADDR...]] [infile] [outfile]
```

- defaults: threshold `3`, epoch `1`, epoch-secs `60`, topic `bitcoin-asmap-quorum`
- writes consensus map to `outfile` (default `asmap.map`)
- writes matching JSON report beside map with `.json` extension

### `collect`

Run a networked quorum node that periodically fetches RIPE RIS state before publishing claims.

```bash
collect [--threshold N] [--epoch N] [--epoch-secs N] [--refresh-secs N] [--topic NAME] [-n 0,1,2] [--bootstrap ADDR[,ADDR...]] [--relay ADDR[,ADDR...]] [--output FILE]
```

- defaults: threshold `3`, epoch `1`, epoch-secs `60`, refresh-secs `1800`
- default topic: `bitcoin-ris-collection`
- collectors flag aliases: `-n`, `--ripe_collector_number` (long form uses underscores), `--collectors`
- default output map: `ris-asmap.map` (+ `.json` report)

### `download`

Download latest RIPE RIS dumps.

```bash
download [-o OUT] [-n 0,1,2]
```

- `-o, --out`: output directory (default `dump`)
- `-n, --ripe_collector_number`: comma-separated collector ids
- if `-n` is omitted, downloads collectors `0..24`

### `find-bottleneck` / `find_bottleneck`

Extract bottleneck AS mappings from MRT dumps.

```bash
find-bottleneck -d DIR [-o OUT]
```

- `-d, --dir`: input dump directory (required)
- `-o, --out`: output directory; if omitted, writes to stdout
- with `--out`, output file is `bottleneck.<unix-epoch>.txt`

## Typical workflow

```bash
# 1) Convert ASMap text to binary
cargo run -- encode input.txt asmap.map

# 2) Build claims from multiple snapshots
cargo run -- import --epoch 42 --output claims.json snapshot-a.txt snapshot-b.txt

# 3) Replay claims into consensus artifacts
cargo run -- replay --threshold 2 --output consensus.map --report consensus.json claims.json

# 4) Verify report/map consistency
cargo run -- verify consensus.json consensus.map
```
