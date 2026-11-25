from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, HTTPException

from . import store
from .schemas import AnalysisResponse, AnalyzeRequest, FeedInfo
from .scoring import score_evidence, verdict_for


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.initialize()
    yield


app = FastAPI(
    title="IOC-Lens API",
    summary="Explainable threat-intelligence enrichment",
    description=(
        "Analyze indicators using attributed evidence and transparent scoring. "
        "No external intelligence feeds are queried by this MVP."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health", tags=["Operations"])
def health():
    return {"status": "ok", "service": "ioc-lens", "version": app.version}


@app.post("/api/v1/analyze", response_model=AnalysisResponse, tags=["Analysis"])
def analyze(payload: AnalyzeRequest):
    score, confidence, evidence, explanation = score_evidence(payload.evidence)
    now = datetime.now(timezone.utc)
    response = AnalysisResponse(
        analysis_id=str(uuid4()),
        indicator=payload.indicator,
        indicator_type=payload.indicator_type,
        verdict=verdict_for(score),
        risk_score=score,
        confidence=confidence,
        evidence_count=len(evidence),
        explanation=explanation,
        evidence=evidence,
        analyzed_at=now,
    )
    store.save(response.model_dump(mode="json"))
    return response


@app.get("/api/v1/lookup/{indicator_type}/{value}", response_model=AnalysisResponse, tags=["Lookup"])
def lookup(indicator_type: str, value: str):
    result = store.latest(indicator_type, value.lower().rstrip("."))
    if not result:
        raise HTTPException(status_code=404, detail="No stored analysis for this indicator")
    return result


@app.get("/api/v1/score/{indicator_type}/{value}", tags=["Analysis"])
def score(indicator_type: str, value: str):
    result = store.latest(indicator_type, value.lower().rstrip("."))
    if not result:
        raise HTTPException(status_code=404, detail="No stored analysis for this indicator")
    return {
        "indicator": result["indicator"],
        "indicator_type": result["indicator_type"],
        "risk_score": result["risk_score"],
        "verdict": result["verdict"],
        "confidence": result["confidence"],
        "explanation": result["explanation"],
    }


@app.get("/api/v1/relationships/{value}", tags=["Relationships"])
def relationships(value: str):
    return {"indicator": value, "relationships": store.related(value), "count": 0,
            "note": "No relationship provider is configured in this MVP."}


@app.get("/api/v1/feeds", response_model=list[FeedInfo], tags=["Intelligence"])
def feeds():
    return [FeedInfo(
        name="manual-evidence",
        mode="manual",
        description="Evidence submitted explicitly in the analyze request; no external feed connection.",
    )]
