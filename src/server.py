"""FastAPI server to receive Bitbucket webhooks and trigger PR reviews."""

import os
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Optional, Any, Dict

from .config import Config
from .review_engine import ReviewEngine

app = FastAPI(title="AI PR Reviewer Webhook")


def _get_repo_slug_from_body(body: Dict[str, Any]) -> Optional[str]:
    """Extract repository slug from Bitbucket Cloud or Server/DC payloads."""
    repo = body.get("repository") or {}

    # Bitbucket Cloud: repository.full_name = "workspace/slug" OR repository.name
    full_name = repo.get("full_name") or ""
    if full_name and "/" in full_name:
        return full_name.split("/", 1)[1]

    name = repo.get("name")
    if name:
        return name

    # Bitbucket Server/DC: repository.slug
    slug = repo.get("slug")
    if slug:
        return slug

    return None


def _get_pr_id_from_body(body: Dict[str, Any]) -> Optional[int]:
    """Extract PR id from Bitbucket Cloud (pullrequest) or Server/DC (pullRequest)."""
    # Cloud
    cloud_pr = body.get("pullrequest")
    if isinstance(cloud_pr, dict) and cloud_pr.get("id") is not None:
        return int(cloud_pr.get("id"))

    # Server/DC
    server_pr = body.get("pullRequest")
    if isinstance(server_pr, dict) and server_pr.get("id") is not None:
        return int(server_pr.get("id"))

    return None


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/webhooks/bitbucket")
async def bitbucket_webhook_info() -> Dict[str, str]:
    # Browser-friendly hint for manual checks
    return {"message": "Use POST with Bitbucket webhook events at this endpoint."}


@app.post("/webhooks/bitbucket")
async def bitbucket_webhook(request: Request):
    # Accept both Bitbucket Cloud and Server/DC payloads
    event_key = request.headers.get("X-Event-Key", "") or request.headers.get("X-Event-Type", "")

    # Cloud PR events are "pullrequest:*"; Server/DC commonly use "pr:*" or others
    is_pr_event = event_key.startswith("pullrequest:") or event_key.startswith("pr:")
    if not is_pr_event:
        return {"status": "ignored", "event": event_key}

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    repo_slug = _get_repo_slug_from_body(body)
    pr_id = _get_pr_id_from_body(body)

    if not repo_slug or pr_id is None:
        raise HTTPException(status_code=400, detail="Missing repository slug or PR id")

    # Build config from env/.env and run review
    config = Config()
    engine = ReviewEngine(config)

    try:
        result = await engine.review_pull_request(repo_slug, int(pr_id))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Review failed: {exc}")

    return {
        "status": "ok",
        "repo": repo_slug,
        "pr_id": pr_id,
        "issues": result.total_issues,
        "critical": result.critical_issues,
        "security": result.security_issues,
        "confidence": result.confidence,
        "recommendation": result.recommendation,
    }