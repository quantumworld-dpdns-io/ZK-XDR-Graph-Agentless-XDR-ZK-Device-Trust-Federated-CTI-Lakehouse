from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.models.ioc import IoCCreate, IoCResponse, IoCUpdate

router = APIRouter()

_store: dict[UUID, IoCResponse] = {}


@router.post("", response_model=IoCResponse, status_code=201)
async def create_ioc(payload: IoCCreate):
    ioc = IoCResponse(**payload.model_dump())
    _store[ioc.id] = ioc
    return ioc


@router.get("", response_model=list[IoCResponse])
async def list_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    ioc_type: str | None = None,
    severity: str | None = None,
):
    items = list(_store.values())
    if ioc_type:
        items = [i for i in items if i.ioc_type.value == ioc_type]
    if severity:
        items = [i for i in items if i.severity.value == severity]
    start = (page - 1) * page_size
    return items[start : start + page_size]


@router.get("/{ioc_id}", response_model=IoCResponse)
async def get_ioc(ioc_id: UUID):
    if ioc_id not in _store:
        raise HTTPException(status_code=404, detail="IoC not found")
    return _store[ioc_id]


@router.put("/{ioc_id}", response_model=IoCResponse)
async def update_ioc(ioc_id: UUID, payload: IoCUpdate):
    if ioc_id not in _store:
        raise HTTPException(status_code=404, detail="IoC not found")
    existing = _store[ioc_id]
    update_data = payload.model_dump(exclude_unset=True)
    updated = existing.model_copy(update=update_data)
    _store[ioc_id] = updated
    return updated


@router.delete("/{ioc_id}", status_code=204)
async def delete_ioc(ioc_id: UUID):
    if ioc_id not in _store:
        raise HTTPException(status_code=404, detail="IoC not found")
    del _store[ioc_id]


@router.post("/bulk", response_model=list[IoCResponse], status_code=201)
async def bulk_create_iocs(payloads: list[IoCCreate]):
    results = []
    for p in payloads:
        ioc = IoCResponse(**p.model_dump())
        _store[ioc.id] = ioc
        results.append(ioc)
    return results


@router.post("/search", response_model=list[IoCResponse])
async def search_iocs(query: str = Query(..., min_length=1)):
    results = [
        ioc
        for ioc in _store.values()
        if query.lower() in ioc.value.lower()
        or query.lower() in (ioc.description or "").lower()
        or any(query.lower() in tag.lower() for tag in ioc.tags)
    ]
    return results


@router.post("/match", response_model=list[IoCResponse])
async def match_iocs(values: list[str]):
    results = [
        ioc
        for ioc in _store.values()
        if ioc.value in values
    ]
    return results
