# RepoSentry

**Inspect a repository before you trust it.**

RepoSentry is a CLI for developers who want an evidence-first safety and intelligence review of a local repository. It maps source files and languages, then flags reviewable code, workflow, and dependency-manifest signals.

## Safety boundary

RepoSentry never executes scanned code, package scripts, or repository commands. Its static findings require human review: they are not a malware verdict and do not evaluate a repository's developers, identity, intent, or suitability for employment.

## Install and run

```bash
python -m pip install -e .
reposentry scan /path/to/repository
```

Write machine-readable output:

```bash
reposentry scan /path/to/repository --format json --output reposentry-report.json
```

Add `--online` to query public PyPI and npm metadata without downloading or running packages. It flags unresolved, yanked, and deprecated dependencies; it cannot prove a package is malicious.

## Version 0.1 checks

- Possible GitHub and AWS credential patterns
- Sensitive files such as `.env` and private-key filenames
- Downloaded content piped to a shell, dynamic evaluation, and `shell=True`
- npm lifecycle scripts in `package.json`
- Direct Git/URL Python dependencies
- Optional PyPI/npm registry checks for unresolved, yanked, and deprecated packages
- Over-permissive and branch-pinned GitHub Actions
- Bounded file count, bytes scanned, and language breakdown

## Roadmap

1. Lockfile parsing and OSV vulnerability lookup for npm and Python packages.
2. SARIF output for code-scanning integrations.
3. Optional GitHub Action and local dashboard built on this CLI rule engine.

## Development

```bash
python -m pip install -e '.[dev]'
pytest
```

## License

MIT. See [LICENSE](LICENSE).
