from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import ip_address
import re
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    source: str = Field(min_length=2, max_length=120)
    category: str = Field(min_length=2, max_length=80)
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    observed_at: datetime
    summary: str = Field(min_length=4, max_length=500)

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("observed_at must include a timezone")
        return value.astimezone(timezone.utc)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    indicator: str = Field(min_length=3, max_length=2048)
    indicator_type: IndicatorType
    evidence: list[EvidenceIn] = Field(default_factory=list, max_length=100)

    @field_validator("indicator")
    @classmethod
    def normalize_indicator(cls, value: str) -> str:
        return value.rstrip(".").lower()

    @model_validator(mode="after")
    def validate_indicator_type(self):
        value, kind = self.indicator, self.indicator_type
        try:
            if kind in (IndicatorType.IPV4, IndicatorType.IPV6):
                parsed = ip_address(value)
                if (kind == IndicatorType.IPV4) != (parsed.version == 4):
                    raise ValueError("indicator does not match the declared IP version")
            elif kind == IndicatorType.DOMAIN:
                if len(value) > 253 or not re.fullmatch(
                    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+", value
                ):
                    raise ValueError("invalid domain name")
            elif kind == IndicatorType.URL:
                parsed = urlparse(value)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    raise ValueError("URL must be absolute and use http or https")
            else:
                lengths = {IndicatorType.MD5: 32, IndicatorType.SHA1: 40, IndicatorType.SHA256: 64}
                if not re.fullmatch(r"[a-f0-9]+", value) or len(value) != lengths[kind]:
                    raise ValueError(f"invalid {kind.value} hash")
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        return self


class EvidenceOut(EvidenceIn):
    age_hours: float
    contribution: float


class AnalysisResponse(BaseModel):
    analysis_id: str
    indicator: str
    indicator_type: IndicatorType
    verdict: str
    risk_score: int | None
    confidence: float
    evidence_count: int
    explanation: list[str]
    evidence: list[EvidenceOut]
    analyzed_at: datetime


class FeedInfo(BaseModel):
    name: str
    mode: str
    description: str
