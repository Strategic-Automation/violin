"""Contracts for the public website and its focused documentation pages.

The page is the project's front door, so the claims it renders have to match the repository that ships beside
it. These checks are deliberately about load-bearing facts, not markup: the inventory it displays, the receipt
vocabulary it quotes, working local navigation, and an intentionally concise homepage.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import yaml

from plugins.violin_guard.core.evidence.receipt_integrity import (
    DIGESTS_FIELD,
    PUBLIC_SIGNATURE_FIELD,
    SIGNATURE_FIELD,
)
from plugins.violin_guard.registry import REGISTERED_TOOLS

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "index.html"


def page(name: str = "index") -> str:
    return (PAGE.parent / f"{name}.html").read_text(encoding="utf-8")


def test_landing_page_exists() -> None:
    assert PAGE.is_file(), "the landing page that README and Pages point at is missing"


def test_page_lists_every_shipped_playbook_and_nothing_else() -> None:
    on_disk = {path.stem for path in ROOT.glob("skills/*/playbooks/*.md")}
    on_page = set(re.findall(r'class="playbook-name">([^<]+)<', page("coverage")))

    assert on_disk, "no playbooks found on disk"
    assert on_page == on_disk, f"page={sorted(on_page ^ on_disk)} differs from disk"


def test_page_lists_every_registered_tool() -> None:
    on_page = set(re.findall(r"<code>(violin_[a-z_]+)</code>", page("tools")))

    assert on_page == set(REGISTERED_TOOLS), (
        f"page differs: {sorted(on_page ^ set(REGISTERED_TOOLS))}"
    )


def test_page_quotes_the_real_receipt_fields() -> None:
    """A demo of sealed receipts must name the fields the guard actually seals."""
    rendered = page("guard")

    assert "-E0" not in rendered, "page quotes a violation-code scheme the guard does not implement"
    for field in (SIGNATURE_FIELD, PUBLIC_SIGNATURE_FIELD, DIGESTS_FIELD):
        assert field in rendered, f"page never shows {field}"


def test_playbook_grid_is_rendered_on_load() -> None:
    """The inventory is available without JavaScript and enhanced with live filtering."""
    rendered = page("coverage")
    cards = WebsiteDocument(rendered).playbooks
    assert len(cards) == 35
    assert all("hidden" not in card for card in cards)
    assert 'src="assets/coverage.js"' in rendered
    script = (PAGE.parent / "assets" / "coverage.js").read_text(encoding="utf-8")
    assert re.search(r"^\s{0,4}updatePlaybooks\(\);\s*$", script, re.MULTILINE)


class WebsiteDocument(HTMLParser):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.links: list[str] = []
        self.assets: list[str] = []
        self.playbooks: list[dict[str, str | None]] = []
        self.commands: dict[str, str] = {}
        self.active_command: str | None = None
        self.words: list[str] = []
        self.feed(text)

    def handle_starttag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        attrs = dict(attributes)
        if tag == "code" and attrs.get("id") in {"install-code", "alternative-code"}:
            self.active_command = attrs["id"]
            self.commands[self.active_command] = ""
        if tag == "a" and "playbook-card" in (attrs.get("class") or "").split():
            self.playbooks.append(attrs)
        if attrs.get("id"):
            self.ids.append(attrs["id"])
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag in {"script", "img"} and attrs.get("src"):
            self.assets.append(attrs["src"])
        if tag == "link" and attrs.get("rel") == "stylesheet":
            self.assets.append(attrs["href"])

    def handle_data(self, data: str) -> None:
        self.words.extend(data.split())
        if self.active_command:
            self.commands[self.active_command] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "code":
            self.active_command = None


def test_copyable_installation_commands_are_single_shell_commands() -> None:
    expected = "hermes profile install https://github.com/Strategic-Automation/violin"
    for name in ("index", "guide"):
        commands = WebsiteDocument(page(name)).commands
        assert commands["install-code"].strip() == expected
        if name == "guide":
            assert commands["alternative-code"].strip() == expected


def test_homepage_is_a_short_introduction_with_paths_to_the_docs() -> None:
    homepage = WebsiteDocument(page())
    assert len(homepage.words) <= 350, "keep technical detail in the documentation"
    assert {"guide.html", "guard.html", "coverage.html"} <= set(homepage.links)
    assert not {"tools", "playbooks", "sim-output"}.intersection(homepage.ids)


def test_every_website_page_has_unique_ids_and_working_local_destinations() -> None:
    pages = {
        path.name: WebsiteDocument(path.read_text(encoding="utf-8"))
        for path in PAGE.parent.glob("*.html")
    }
    for name, document in pages.items():
        assert len(document.ids) == len(set(document.ids)), f"duplicate IDs in {name}"
        for value in document.links + document.assets:
            url = urlsplit(value)
            if url.scheme or url.netloc:
                continue
            target = PAGE.parent / unquote(url.path) if url.path else PAGE.parent / name
            assert target.is_file(), f"{name}: missing {value}"
            if url.fragment and target.name in pages:
                assert unquote(url.fragment) in pages[target.name].ids, f"{name}: broken {value}"


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
    """Published articles must not contain embedded launch-copy blocks."""
    for path in articles():
        text = path.read_text(encoding="utf-8")

        assert "<!-- PROMO" not in text, f"{path.name} carries a promo block"
        assert "cover_image_note" not in text, f"{path.name} carries a cover-graphic note"
