"""Receipt-backed finding argument and storage models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FindingClaimModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1)
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    summary: str = Field(..., min_length=1)
    receipt_paths: list[str] = Field(
        ...,
        min_length=1,
        max_length=8,
        description=(
            "One to eight engagement-relative signed execution receipt JSON paths beneath "
            "evidence/executions. Every cited receipt must have a reviewable result; "
            "evidence_paths may be authenticated by any signed receipt in the engagement, "
            "not only the cited receipt_paths. Validation never exposes benchmark identities "
            "or score."
        ),
    )
    evidence_paths: list[str] = Field(
        default_factory=list,
        max_length=16,
        description=(
            "Optional engagement-relative saved output files under evidence/ that hold the "
            "decisive request/response body (e.g. the exact payload or PII the receipt's "
            "stdout only references). The scorer reads these as proof."
        ),
    )


class SubmitFindingArgsModel(FindingClaimModel):
    """Submit a generic receipt-backed finding without evaluator metadata."""

    eng_dir: str


class FindingRecordModel(FindingClaimModel):
    """Canonical stored finding record."""

    schema_version: Literal[1] = 1
    finding_id: str = Field(..., pattern=r"^FIND-\d{3,}$")
    status: Literal["validated"] = "validated"
    execution_ids: list[str] = Field(default_factory=list)
    evidence_paths: list[str] = Field(default_factory=list)
    created_at: str = ""
    engagement_id: str = ""
