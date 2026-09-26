"""Engagement task and hypothesis argument models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..core.skills.skill_policy import (
    _SOURCE_ROUTES,
    _VULNERABILITY_ROUTES,
    _normalize,
    _vulnerability_class_suggestion,
)


class ReviewOutcomeFields(BaseModel):
    """Shared evidence and next-step fields for task and batch reviews."""

    model_config = ConfigDict(extra="forbid")

    outcome: str = ""
    evidence_paths: list[str] = Field(default_factory=list)
    next_action: str = ""
    next_technique: str = ""
    research_attempted: bool = False


class RecordPttArgsModel(ReviewOutcomeFields):
    """Start one untouched [ ] PTT task with [~], or review the active task after a completed batch. A non-empty note is required; reviewed batches are bound automatically."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str
    id: str
    status: str = Field(
        "",
        description=(
            "Task lifecycle status token: '[~]' (active/start), '[x]' (completed), "
            "'[-]' (cancelled), '[!]' (blocked). Must be a literal bracket token (not 'in_progress')."
        ),
    )
    note: str = ""
    skill: str = Field(..., description="Selected Violin skill required before task activation")
    technique: str = Field(..., description="Concrete technique required before task activation")
    hypothesis_id: str = Field("", description="Required for hypothesis-driven phases")
    title: str = Field("", description="Required when explicitly creating a new PTT task")
    phase: str = Field("", description="Phase for an explicitly created PTT task")


class RecordHypothesisArgsModel(BaseModel):
    """Record or update a hypothesis row in the engagement state."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str
    service: str = ""
    port: str = ""
    id: str = ""
    title: str = ""
    status: str = Field(
        "",
        description=(
            "Canonical status: 'Candidate', 'Likely', 'Validated', or 'Rejected'. "
            "When status='Validated', 'runtime_evidence' is required (path under evidence/). "
            "When status='Rejected', 'verification_status' ('syntax_confirmed' or 'not_implemented'), "
            "'test_command', 'test_response', and 'rejection_reason' are required."
        ),
    )
    confidence: str = Field("", description="0.1-1.0 guesstimate; escalate only with evidence")
    timebox: str = Field("", description="e.g. 4 tool batches or 30 min — then re-evaluate")
    cheapest_test: str = Field(
        "", description="Single cheapest probe that discriminates this theory"
    )
    phase: str = ""
    target: str = Field("", description="target host/IP (must be in scope)")
    vuln_class: str = Field(
        "",
        description=(
            "Canonical vulnerability route key (lowercase; underscores and spaces map to '-'). "
            "Accepted keys: " + ", ".join(sorted(_VULNERABILITY_ROUTES)) + "."
        ),
    )
    rationale: str = ""
    evidence: str = ""
    cve_research: str = Field(
        "",
        description=(
            "Required before exploitation: online CVE/advisory query, source, and outcome. Truthful"
            " no-results/not-applicable/unavailable outcomes are allowed."
        ),
    )
    exploit_research: str = Field(
        "",
        description=(
            "Required before exploitation: online PoC/exploit query, source, and outcome. Truthful"
            " no-results/unavailable outcomes are allowed."
        ),
    )
    test_command: str = Field("", description="Exact syntax tested, including argument order")
    test_response: str = Field("", description="Exact decisive response or error")
    verification_status: str = Field(
        "",
        description=(
            "Required when status='Rejected': must be 'syntax_confirmed' or 'not_implemented'. "
            "Use 'syntax_uncertain' or 'not_tested' to keep hypothesis active for re-testing."
        ),
    )
    kill_criteria: str = Field(
        "",
        description="Evidence that contradicts, or no new info in N batches — then kill & log in Decoy Trail",
    )
    rejection_reason: str = Field(
        "", description="Why a rejected hypothesis is safe to stop pursuing"
    )
    next_step: str = ""
    research_attempted: bool = Field(
        False,
        description="Flag indicating a research attempt was made to discover prior work or techniques",
    )
    candidate_source: str = Field(
        "",
        description=(
            "Optional normalized source route: "
            + ", ".join(sorted(_SOURCE_ROUTES))
            + ". When present, it can select the PTT skill unless vuln_class has a "
            "higher-priority route. api-enumeration is a technique-as-source "
            "alias for api-testing; use vuln_class for the vulnerability type."
        ),
    )
    entry_point: str = ""
    data_flow: str = ""
    source_evidence: str = ""
    runtime_evidence: str = Field(
        "",
        description=(
            "Required when status is Validated. One or more comma-separated, engagement-relative "
            "evidence file paths; globs and semicolon-separated values are not accepted."
        ),
    )
    evidence_paths: list[str] = Field(
        default_factory=list,
        max_length=16,
        description=(
            "Optional engagement-relative saved output files under evidence/ supporting this "
            "hypothesis (the same shape as finding-side evidence_paths). Values are merged "
            "into runtime_evidence."
        ),
    )

    @field_validator("confidence", "port", mode="before")
    @classmethod
    def _coerce_numeric_to_token(cls, value: Any) -> Any:
        """Accept a numeric confidence or port and coerce it to its string form."""
        if isinstance(value, (int, float)):
            return str(value)
        return value

    @field_validator("vuln_class", mode="after")
    @classmethod
    def _normalise_vuln_class(cls, value: str) -> str:
        """Map a human-readable vuln_class to its canonical route key."""
        canonical = _normalize(value)
        if not canonical:
            return value
        if canonical not in _VULNERABILITY_ROUTES:
            suggestion = _vulnerability_class_suggestion(canonical)
            message = f"unknown vuln_class {value!r}"
            if suggestion:
                message += f". Did you mean '{suggestion}'?"
                separator = " "
            else:
                separator = ". "
            raise ValueError(
                f"{message}{separator}Valid classes are: "
                + ", ".join(sorted(_VULNERABILITY_ROUTES))
            )
        return canonical

    @model_validator(mode="after")
    def _merge_evidence_paths(self) -> RecordHypothesisArgsModel:
        """Fold finding-shaped evidence_paths into runtime_evidence."""
        if self.evidence_paths:
            merged = [p.strip() for p in self.runtime_evidence.split(",") if p.strip()]
            for path in self.evidence_paths:
                if path not in merged:
                    merged.append(path)
            self.runtime_evidence = ", ".join(merged)
        return self


class ReviewBatchArgsModel(ReviewOutcomeFields):
    """Review a completed batch and release its sync lock. Submit findings separately."""

    model_config = ConfigDict(extra="forbid")

    eng_dir: str
    id: str = Field(..., description="Active PTT task id")
    status: str = Field(
        "[~]",
        description=(
            "PTT status after review. Defaults to '[~]' so continued same-phase work keeps the "
            "same task; use '[x]' only when deliberately closing it."
        ),
    )
    note: str = Field(..., description="Truthful result/evidence review")
    skill: str = Field(
        "",
        description="Review skill; defaults to the active execution binding (or fp-check if specified)",
    )
    hypothesis_id: str = Field("", description="Required for hypothesis-driven phases")
