from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ISSUE_TEMPLATE_DIR = ROOT / ".github" / "ISSUE_TEMPLATE"

FORMS = {
    "bug_report.yml": {
        "type": "bug",
        "labels": {"Summary", "Reproduction", "Acceptance criteria"},
    },
    "feature_request.yml": {
        "type": "feature",
        "labels": {
            "Summary",
            "Why this matters",
            "Proposed implementation",
            "Acceptance criteria",
        },
    },
    "task.yml": {
        "type": "task",
        "labels": {
            "Summary",
            "Why this matters",
            "Proposed implementation",
            "Acceptance criteria",
        },
    },
}


def _load_form(filename: str) -> dict:
    with (ISSUE_TEMPLATE_DIR / filename).open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _field_labels(form: dict) -> set[str]:
    return {
        block["attributes"]["label"]
        for block in form["body"]
        if block.get("type") != "markdown" and "label" in block.get("attributes", {})
    }


def test_issue_forms_use_native_types_and_clean_titles() -> None:
    for filename, expected in FORMS.items():
        form = _load_form(filename)

        assert form["type"] == expected["type"]
        assert not form.get("title"), (
            f"{filename} must not inject priority/type prefixes into issue titles"
        )


def test_issue_forms_keep_required_structure() -> None:
    for filename, expected in FORMS.items():
        labels = _field_labels(_load_form(filename))
        missing = expected["labels"] - labels

        assert not missing, f"{filename} is missing required fields: {sorted(missing)}"


def test_issue_forms_require_duplicate_check() -> None:
    for filename in FORMS:
        form = _load_form(filename)
        duplicate_block = next(
            block for block in form["body"] if block.get("id") == "duplicate-check"
        )
        options = duplicate_block["attributes"]["options"]

        assert options
        assert all(option.get("required") is True for option in options)


def test_issue_standards_are_referenced_by_agent_and_contributor_guidance() -> None:
    standards = ROOT / ".github" / "ISSUE_STANDARDS.md"
    assert standards.is_file()

    for path in (ROOT / "AGENTS.md", ROOT / "CONTRIBUTING.md"):
        content = path.read_text(encoding="utf-8")
        assert ".github/ISSUE_STANDARDS.md" in content
