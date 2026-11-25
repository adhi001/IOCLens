# IOC-Lens

**Explainable threat-intelligence enrichment API.**

IOC-Lens turns an indicator of compromise (IP address, domain, URL, or file hash) into a transparent, reproducible assessment. Instead of returning a mysterious *malicious / benign* verdict, it records evidence, source attribution, confidence, and the reasons behind its score.

> **Status:** Early-stage MVP. The current scoring engine is deterministic and uses explicitly supplied evidence. It does not query commercial threat-intelligence providers or claim that an indicator is safe merely because no evidence is present.

## Features

- FastAPI REST API with interactive OpenAPI documentation
- IOC validation for IPv4, IPv6, domains, URLs, and MD5/SHA-1/SHA-256 hashes
- Explainable 0–100 risk score with evidence-level reasoning
- Confidence and evidence freshness metadata
- SQLite persistence for submitted analyses
- Indicator lookup, score explanation, and relationship endpoints
- STIX 2.1-compatible export can be added as a follow-on milestone
- Docker-ready, typed Python, and pytest tests

## Quick start

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn ioc_lens.main:app --reload
```

Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

## API

### Analyze an indicator

`POST /api/v1/analyze`

```json
{
  "indicator": "198.51.100.10",
  "indicator_type": "ipv4",
  "evidence": [
    {
      "source": "example-sandbox",
      "category": "malware",
      "severity": "high",
      "confidence": 0.9,
      "observed_at": "2026-11-24T10:00:00Z",
      "summary": "Observed contacting a known test payload"
    }
  ]
}
```

The address above is from the documentation-only TEST-NET-2 range and is not a real threat indicator.

### Other endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/analyze` | Validate and assess an IOC |
| GET | `/api/v1/lookup/{type}/{value}` | Retrieve the latest stored assessment |
| GET | `/api/v1/score/{type}/{value}` | Retrieve score and explanation |
| GET | `/api/v1/relationships/{value}` | Retrieve known related indicators |
| GET | `/api/v1/feeds` | List configured evidence sources |
| GET | `/health` | Service health |

## Scoring model

The MVP maps evidence severity to a weighted contribution, adjusts it by source confidence and evidence age, and combines independent contributions with a diminishing-return formula. The response includes the evidence that influenced the score. No evidence produces an **unknown / no-evidence** result, not a clean bill of health.

This is a research prototype, not an autonomous blocking decision system. Validate evidence and tune thresholds before operational use.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Good first contributions include additional validators, scoring-model tests, provider adapters, and STIX export.

## Security

Please do not submit real customer indicators, secrets, credentials, or sensitive incident data to public instances. See [SECURITY.md](SECURITY.md).

## Roadmap

- [x] Typed FastAPI service and IOC validation
- [x] Explainable evidence scoring
- [x] SQLite analysis history
- [x] API tests and container setup
- [ ] Pluggable passive-DNS / reputation provider adapters
- [ ] STIX 2.1 bundle export
- [ ] Background enrichment jobs and Redis cache
- [ ] Authentication, rate limiting, and audit events
- [ ] OpenTelemetry metrics and traces

## License

MIT. See [LICENSE](LICENSE).
