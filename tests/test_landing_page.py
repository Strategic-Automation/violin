"""Contracts for the public landing page in ``docs/index.html``.

The page is the project's front door, so the claims it renders have to match the repository that ships beside
it. These checks are deliberately about load-bearing facts, not markup: the inventory it displays, the receipt
vocabulary it quotes, and the one line of script whose absence empties the coverage grid.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from plugins.violin_guard.core.receipt_integrity import (
    DIGESTS_FIELD,
    PUBLIC_SIGNATURE_FIELD,
    SIGNATURE_FIELD,
)
from plugins.violin_guard.registry import REGISTERED_TOOLS

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "index.html"


def page() -> str:
    return PAGE.read_text(encoding="utf-8")


def test_landing_page_exists() -> None:
    assert PAGE.is_file(), "the landing page that README and Pages point at is missing"


def test_page_lists_every_shipped_playbook_and_nothing_else() -> None:
    on_disk = {path.stem for path in ROOT.glob("skills/*/playbooks/*.md")}
    on_page = set(re.findall(r'class="playbook-name">([^<]+)<', page()))

    assert on_disk, "no playbooks found on disk"
    assert on_page == on_disk, f"page={sorted(on_page ^ on_disk)} differs from disk"


def test_page_lists_every_registered_tool() -> None:
    on_page = set(re.findall(r"<code>(violin_[a-z_]+)</code>", page()))

    assert on_page == set(REGISTERED_TOOLS), (
        f"page differs: {sorted(on_page ^ set(REGISTERED_TOOLS))}"
    )


def test_page_quotes_the_real_receipt_fields() -> None:
    """A demo of sealed receipts must name the fields the guard actually seals."""
    rendered = page()

    assert "-E0" not in rendered, "page quotes a violation-code scheme the guard does not implement"
    for field in (SIGNATURE_FIELD, PUBLIC_SIGNATURE_FIELD, DIGESTS_FIELD):
        assert field in rendered, f"page never shows {field}"


def test_playbook_grid_is_rendered_on_load() -> None:
    """Cards ship hidden in CSS so the grid can be filtered, so the filter must run unprompted."""
    assert re.search(r"^\s{0,4}updatePlaybooks\(\);\s*$", page(), re.MULTILINE), (
        "no top-level updatePlaybooks() call: the grid would render empty until a pill is clicked"
    )


def articles() -> list[Path]:
    return sorted((ROOT / "docs" / "articles").glob("*.md"))


def front_matter(path: Path) -> str:
    return path.read_text(encoding="utf-8").split("---", 2)[1]


def test_article_front_matter_has_no_duplicate_keys() -> None:
    """YAML and the cross-posting editors both take the last duplicate key, silently overriding the first."""
    for path in articles():
        keys = [
            line.split(":")[0]
            for line in front_matter(path).splitlines()
            if ":" in line and not line.startswith(" ")
        ]
        duplicates = {key for key in keys if keys.count(key) > 1}

        assert not duplicates, f"{path.name}: duplicate front-matter keys {duplicates}"


def test_article_canonical_url_points_at_the_article() -> None:
    """A cross-posted copy must point readers at its own page, not the repository root."""
    for path in articles():
        canonical = yaml.safe_load(front_matter(path))["canonical_url"]

        assert canonical.endswith(f"/articles/{path.stem}.html"), f"{path.name}: {canonical}"


def test_articles_do_not_carry_promotional_material() -> None:
    """Launch copy belongs in PROMOTION.md, not in the source of what readers are served."""
    for path in articles():
        text = path.read_text(encoding="utf-8")

        assert "<!-- PROMO" not in text, f"{path.name} carries a promo block"
        assert "cover_image_note" not in text, f"{path.name} carries a cover-graphic note"
