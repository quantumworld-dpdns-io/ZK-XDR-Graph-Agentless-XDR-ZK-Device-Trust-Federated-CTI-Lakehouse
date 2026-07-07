from fastapi import APIRouter

from app.models.schemas import (
    EnrichmentRequest,
    EnrichmentResponse,
    QueryRequest,
    QueryResponse,
    SummaryRequest,
    SummaryResponse,
)
from app.services.copilot import copilot_service

router = APIRouter()


@router.post("/query", response_model=QueryResponse)
async def query_copilot(request: QueryRequest):
    result = await copilot_service.query(request.query, request.context)
    return QueryResponse(**result)


@router.post("/enrich", response_model=EnrichmentResponse)
async def enrich_indicator(request: EnrichmentRequest):
    result = await copilot_service.enrich_indicator(request.indicator_type, request.indicator_value)
    return EnrichmentResponse(**result)


@router.post("/summarize", response_model=SummaryResponse)
async def summarize_incident(request: SummaryRequest):
    result = await copilot_service.summarize_incident(request.incident_id, request.events)
    return SummaryResponse(**result)
