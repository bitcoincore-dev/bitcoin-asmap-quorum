## Scenario runner

Use `run-scenario.sh` to execute both variants for a scenario:

```bash
./scripts/run-scenario.sh real-world
./scripts/run-scenario.sh tests
```

It runs:

1. `./scripts/test-<scenario>.sh`
2. `./scripts/<scenario>.sh`

Extra arguments are forwarded to both scripts.

## Available scenarios

These scenario names match the CLI subcommands:

- `encode`
- `decode`
- `diff`
- `diff_addrs`
- `import`
- `replay`
- `compare`
- `verify`
- `download`
- `find-bottleneck`
- `serve`
- `collect`

The `serve` and `collect` scenarios are lightweight help checks; the others run
small local or network-backed smoke workflows.