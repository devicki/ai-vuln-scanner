"""FastAPI REST API server for Reachability-Aware SCA."""
import logging
from dataclasses import asdict
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)

app = FastAPI(title="Reachability-Aware SCA API", version="1.0.0")


class AnalyzeRequest(BaseModel):
    source_dir: str
    cve_ids: Optional[List[str]] = None
    use_llm: bool = False


class AnalyzeResponse(BaseModel):
    status: str
    report: dict


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_endpoint(request: AnalyzeRequest):
    try:
        from src.reachability.analyzer import analyze
        report = analyze(
            source_dir=request.source_dir,
            cve_ids=request.cve_ids,
            use_llm=request.use_llm,
        )
        return AnalyzeResponse(status="success", report=asdict(report))
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
