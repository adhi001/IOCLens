# Contributing to IOC-Lens

Thanks for helping make threat-intelligence assessments more transparent.

## Good first contributions

- Add validation tests for edge-case domains, URLs, and hashes.
- Add a new evidence category with documented semantics.
- Improve score explanation wording without hiding uncertainty.
- Add a provider adapter behind a clear interface.
- Add STIX 2.1 export tests.
- Improve documentation and examples.

## Workflow

1. Open an issue describing the problem or proposal.
2. Fork the repository and create a focused branch.
3. Install development dependencies: `pip install -e ".[dev]"`.
4. Add or update tests.
5. Run `pytest` and `ruff check .`.
6. Open a pull request explaining the change and its security implications.

## Design principles

- Preserve source attribution and timestamps.
- Never turn missing data into a benign verdict.
- Keep scoring deterministic and explainable.
- Do not commit API keys, credentials, customer data, or real incident artifacts.
- Provider integrations must document licensing, rate limits, and data handling.

Small, focused pull requests are easiest to review.
