from pydantic import BaseModel


class QueryRequest(BaseModel):
    query: str
    context: str | None = None
    max_results: int = 5


class QueryResponse(BaseModel):
    answer: str
    sources: list[dict]
    confidence: float
    suggested_actions: list[str]


class EnrichmentRequest(BaseModel):
    indicator_type: str
    indicator_value: str


class EnrichmentResponse(BaseModel):
    indicator: str
    threat_type: str
    severity: str
    confidence: int
    description: str
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    related_iocs: list[str]
    recommended_actions: list[str]


class SummaryRequest(BaseModel):
    incident_id: str
    events: list[dict]


class SummaryResponse(BaseModel):
    incident_id: str
    summary: str
    severity_assessment: str
    root_cause: str
    affected_assets: list[str]
    recommended_response: list[str]
    similar_incidents: list[str]
