from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from .enums import Confidence, IoCType, Severity, TLP


class IoCBase(BaseModel):
    ioc_type: IoCType
    value: str = Field(..., min_length=1, max_length=2048)
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    tlp: TLP = TLP.GREEN
    tags: list[str] = Field(default_factory=list)
    source: str = Field(..., min_length=1, max_length=256)
    description: str | None = None
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class IoCCreate(IoCBase):
    pass


class IoCUpdate(BaseModel):
    severity: Severity | None = None
    confidence: Confidence | None = None
    tlp: TLP | None = None
    tags: list[str] | None = None
    description: str | None = None
    mitre_tactics: list[str] | None = None
    mitre_techniques: list[str] | None = None


class IoCResponse(IoCBase):
    id: UUID = Field(default_factory=uuid4)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True

    model_config = {"from_attributes": True}
