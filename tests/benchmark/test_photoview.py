from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from benchmark.photoview import PROTOCOL
from benchmark.photoview.aggregate import COMPATIBILITY_FIELDS, aggregate
from benchmark.photoview.evaluate import ReviewLedger, digest, evaluate, markdown, sarif
from benchmark.photoview.fixture import compose_config, media_ready
from benchmark.photoview.run import initialize, scope_for_target, source_digest
from benchmark.photoview.usage import COLUMNS, collect_usage
from plugins.violin_guard.core.evidence.receipt_integrity import seal_execution_receipt


@pytest.fixture
def reviewed_run(tmp_path: Path) -> tuple[Path, dict]:
    engagement = tmp_path / "engagement"
    evidence = engagement / "evidence" / "executions"
    evidence.mkdir(parents=True)
    body = engagement / "evidence" / "response.txt"
    body.write_text("HTTP/1.1 200 OK\n\nsynthetic owned/foreign comparison", encoding="utf-8")
    key = Ed25519PrivateKey.generate()
    receipt = seal_execution_receipt(
        {
            "status": "completed",
            "exit_code": 0,
            "execution_id": "probe",
            "evidence_paths": {"response": "evidence/response.txt"},
        },
        engagement,
        signing_key=key.private_bytes_raw(),
    )
    (evidence / "probe.json").write_text(json.dumps(receipt), encoding="utf-8")
    finding = {
        "finding_id": "FIND-001",
        "title": "Synthetic claim",
        "severity": "High",
        "summary": "synthetic comparison",
        "receipt_paths": ["evidence/executions/probe.json"],
        "evidence_paths": ["evidence/response.txt"],
    }
    findings_path = engagement / "evidence" / "findings.jsonl"
    findings_path.write_text(json.dumps(finding) + "\n", encoding="utf-8")
    manifest = {field: "pinned" for field in COMPATIBILITY_FIELDS}
    manifest.update(
        protocol=PROTOCOL,
        run_id="run-a",
        fixture_id="reset-a",
        runner_valid=True,
        violin_dirty=False,
        receipt_verification={"public_key_hex": key.public_key().public_bytes_raw().hex()},
    )
    (engagement / "run-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    ledger = {
        "reviewer": "fixture reviewer",
        "reviewed_at": datetime.now(UTC).isoformat(),
        "run_manifest_sha256": digest(engagement / "run-manifest.json"),
        "findings_sha256": digest(findings_path),
        "reviews": [
            {
                "finding_id": "FIND-001",
                "verdict": "true_positive",
                "rationale": "Reviewed saved synthetic comparison",
                "reviewed_severity": "Medium",
                "patched_case_ids": ["PV-02"],
            }
        ],
    }
    return engagement, ledger


def test_photoview_scope_has_no_duck_store_assumptions(tmp_path: Path) -> None:
    scope = scope_for_target("http://photoview:80", tmp_path)
    text = json.dumps(scope)
    assert "duck-store" not in text
    assert "openapi" not in text
    assert "PhotoviewAdmin!2026" in text
    assert "coverage_obligations" not in scope["engagement"]
    assert "ordinary user" in scope["engagement"]["brief"]


def test_scope_rejects_foreign_target_before_creating_files(tmp_path: Path) -> None:
    target = tmp_path / "fresh"
    with pytest.raises(ValueError, match="disposable"):
        initialize(target, "https://external.example", tmp_path)
    assert not target.exists()


def test_fixture_waits_for_processed_media_urls() -> None:
    assert not media_ready([])
    assert not media_ready([{"thumbnail": None, "highRes": None}])
    assert not media_ready([{"thumbnail": {"url": "/thumb"}, "highRes": None}])
    assert media_ready([{"thumbnail": {"url": "/thumb"}, "highRes": {"url": "/full"}}])


def test_fixture_initializes_cache_volume_for_nonroot_runtime(tmp_path: Path) -> None:
    config = compose_config(tmp_path, 4803, "synthetic root password")
    services = config["services"]
    assert services["cache-init"]["user"] == "0:0"
    assert services["cache-init"]["command"] == ["chown -R 999:999 /cache"]
    assert services["photoview"]["depends_on"]["cache-init"]["condition"] == (
        "service_completed_successfully"
    )


def test_initialization_preserves_existing_engagement(tmp_path: Path) -> None:
    (tmp_path / "keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(FileExistsError):
        initialize(tmp_path, "http://photoview:80", tmp_path)
    assert (tmp_path / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_source_digest_binds_paths_and_contents(tmp_path: Path) -> None:
    schema = tmp_path / "api/graphql/schema.graphql"
    schema.parent.mkdir(parents=True)
    schema.write_text("first", encoding="utf-8")
    first = source_digest(tmp_path)
    schema.write_text("second", encoding="utf-8")
    assert source_digest(tmp_path) != first
    (tmp_path / ".git").mkdir()
    with pytest.raises(ValueError, match="history"):
        source_digest(tmp_path)


def test_evaluation_separates_severity_and_partial_recall(reviewed_run: tuple) -> None:
    engagement, ledger = reviewed_run
    result = evaluate(engagement, ReviewLedger.model_validate(ledger))
    assert result["evaluation_complete"]
    assert result["true_positives"] == 1
    assert result["exact_severity_agreement"] == 0
    assert result["partial_patched_recall"] == 1 / 7
    assert sarif(result)["runs"][0]["results"][0]["level"] == "warning"


def test_unreviewed_claim_receives_no_credit(reviewed_run: tuple) -> None:
    engagement, ledger = reviewed_run
    ledger["reviews"] = []
    result = evaluate(engagement, ReviewLedger.model_validate(ledger))
    assert not result["evaluation_complete"]
    assert result["unresolved"] == 1
    assert result["true_positives"] == 0
    assert result["partial_patched_recall"] == 0
    assert sarif(result)["runs"][0]["results"] == []


def test_changed_evidence_cannot_receive_positive_verdict(reviewed_run: tuple) -> None:
    engagement, ledger = reviewed_run
    (engagement / "evidence/response.txt").write_text("changed bytes", encoding="utf-8")
    with pytest.raises(ValueError, match="authenticated"):
        evaluate(engagement, ReviewLedger.model_validate(ledger))


def test_review_hashes_bind_decisions_to_exact_run(reviewed_run: tuple) -> None:
    engagement, ledger = reviewed_run
    path = engagement / "evidence/findings.jsonl"
    path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="stale"):
        evaluate(engagement, ReviewLedger.model_validate(ledger))


def test_unknown_case_ids_and_naive_review_times_are_rejected(reviewed_run: tuple) -> None:
    _, ledger = reviewed_run
    ledger["reviews"][0]["patched_case_ids"] = ["DUCK-001"]
    with pytest.raises(ValidationError):
        ReviewLedger.model_validate(ledger)
    ledger["reviews"][0]["patched_case_ids"] = []
    ledger["reviewed_at"] = "2026-10-16T14:00:00"
    with pytest.raises(ValidationError):
        ReviewLedger.model_validate(ledger)


def test_duplicate_review_cannot_reference_itself(reviewed_run: tuple) -> None:
    engagement, ledger = reviewed_run
    ledger["reviews"][0].update(verdict="duplicate", duplicate_of="FIND-001", patched_case_ids=[])
    with pytest.raises(ValueError, match="duplicates"):
        evaluate(engagement, ReviewLedger.model_validate(ledger))


def test_cost_requires_actual_usage_provenance(reviewed_run: tuple) -> None:
    engagement, ledger = reviewed_run
    ledger["cost_usd"] = 0.0
    with pytest.raises(ValueError, match="measured source"):
        evaluate(engagement, ReviewLedger.model_validate(ledger))
    ledger["usage_source"] = "synthetic test fixture"
    assert evaluate(engagement, ReviewLedger.model_validate(ledger))["cost_usd"] == 0


def test_aggregate_retains_failure_and_rejects_mixed_models(
    reviewed_run: tuple, tmp_path: Path
) -> None:
    engagement, ledger = reviewed_run
    result = evaluate(engagement, ReviewLedger.model_validate(ledger))
    first = tmp_path / "first.json"
    first.write_text(json.dumps(result), encoding="utf-8")
    second = tmp_path / "second.json"
    result["manifest"].update(run_id="run-b", fixture_id="reset-b", runner_valid=False)
    result.update(
        evaluation_complete=False,
        true_positives=0,
        partial_patched_recall=0,
        matched_patched_cases=[],
    )
    second.write_text(json.dumps(result), encoding="utf-8")
    combined = aggregate([first, second])
    assert combined["failed_runners"] == 1
    assert combined["mean_observed_true_positives"] == 0.5
    assert combined["patched_case_hits"]["PV-02"] == 1
    assert combined["patched_cases_not_observed"] == [
        "PV-01",
        "PV-03",
        "PV-04",
        "PV-05",
        "PV-06",
        "PV-07",
    ]
    assert combined["total_known_actual_cost_usd"] == 0
    assert combined["total_provider_estimated_cost_usd"] == 0
    assert not combined["publishable_provenance"]
    result["manifest"]["model"] = "different"
    second.write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ValueError, match="mix"):
        aggregate([first, second])


def test_aggregate_rejects_reused_reset_identity(reviewed_run: tuple, tmp_path: Path) -> None:
    engagement, ledger = reviewed_run
    result = evaluate(engagement, ReviewLedger.model_validate(ledger))
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    first.write_text(json.dumps(result), encoding="utf-8")
    result["manifest"]["run_id"] = "different"
    second.write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ValueError, match="reset identities"):
        aggregate([first, second])


def test_usage_exports_only_current_accounting_and_preserves_unknown_cost(tmp_path: Path) -> None:
    with sqlite3.connect(tmp_path / "state.db") as db:
        db.execute("CREATE TABLE sessions (" + ",".join(COLUMNS) + ", conversation_secret)")
        for started, actual in ((1, 100), (20, None), (30, 0.5)):
            row = dict.fromkeys(COLUMNS)
            row.update(
                id=str(started),
                model="synthetic",
                started_at=started,
                input_tokens=12,
                output_tokens=8,
                api_call_count=1,
                estimated_cost_usd=0.6,
                actual_cost_usd=actual,
            )
            db.execute(
                "INSERT INTO sessions VALUES ("
                + ",".join("?" for _ in range(len(COLUMNS) + 1))
                + ")",
                [*row.values(), "must never export"],
            )
    usage = collect_usage(tmp_path, 10)
    assert usage["api_call_count"] == 2
    assert usage["input_tokens"] == 24
    assert usage["actual_cost_usd"] is None
    assert usage["estimated_cost_usd"] == 1.2
    assert "must never export" not in json.dumps(usage)


def test_evaluation_binds_exported_usage_to_manifest(reviewed_run: tuple) -> None:
    engagement, ledger = reviewed_run
    usage = engagement / "usage.json"
    usage.write_text(
        json.dumps(
            {
                "source": "provider accounting",
                "actual_cost_usd": None,
                "estimated_cost_usd": 1.25,
                "input_tokens": 12,
                "output_tokens": 8,
            }
        ),
        encoding="utf-8",
    )
    manifest_path = engagement / "run-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["usage_sha256"] = digest(usage)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    ledger["run_manifest_sha256"] = digest(manifest_path)
    result = evaluate(engagement, ReviewLedger.model_validate(ledger))
    assert result["cost_usd"] is None
    assert result["estimated_cost_usd"] == 1.25
    assert "Provider estimate (USD): 1.25" in markdown(result)
    usage.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="accounting changed"):
        evaluate(engagement, ReviewLedger.model_validate(ledger))
