"""Contract tests for benchmark requests behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmark.proof import _command_requests, match_finding
from benchmark.score import load_golden_set
from plugins.violin_guard.core.evidence import receipt_integrity
from tests.benchmark.receipt_fixture import _write_receipt


def test_command_requests_recovers_urls_from_nested_sh_c_wrapper() -> None:
    # A `sh -c 'python3 - <<PY ... curl ... PY ...'` wrapper collapses to a
    # single shlex token; the scorer must still recover the curl URLs so the
    # finding's evidence-body bundle inherits the right method/path.
    command = (
        "sh -c 'python3 - <<PY\n"
        "import base64,json\n"
        'h=base64.urlsafe_b64encode(json.dumps({"alg":"none"}).encode())\n'
        "PY\n"
        "curl -sS -i --http1.1 https://duck-store.escape.tech/api/v1/auth/me "
        '-H "Authorization: Bearer x" -o evidence/vuln-research/jwt-none-me.txt '
        '-w "HTTP %{http_code}\\n"\''
    )
    requests = _command_requests(command)
    urls = {str(request.url) for request in requests}
    assert "https://duck-store.escape.tech/api/v1/auth/me" in urls


def test_command_requests_resolves_shell_baseurl_variables() -> None:
    # `export B=...; curl $B/auth/login ...; curl $B/users/me/profile ...` puts
    # the URLs behind a shell variable. URL extraction must resolve $B so the
    # exploit request (not just the literal export assignment) is recovered.
    command = (
        "export B=https://duck-store.escape.tech/api/v1; "
        "ATOK=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' "
        '-d \'{"username":"tester","password":"pw"}\' | python3 -c \'import '
        'sys,json;print(json.load(sys.stdin)["access_token"])\'); '
        "curl -sS -i -X PUT $B/users/me/profile -H 'Authorization: Bearer ***' "
        '-d \'{"role":"admin"}\' -o evidence/vuln-research/massassign.txt'
    )
    requests = _command_requests(command)
    urls = {str(request.url) for request in requests}
    assert "https://duck-store.escape.tech/api/v1/users/me/profile" in urls


def test_command_requests_does_not_mutate_command_substitution() -> None:
    # ``$(...)`` is command substitution, not a variable reference: the opener
    # ``$`` is followed by ``(`` so it must not collapse into an env lookup.
    command = "echo $(whoami) && curl -sS -i https://example.test/api/items -w 'HTTP %{http_code}'"
    assert _command_requests(command)


def test_compound_login_command_body_does_not_inherit_login_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A body saved by the SECOND curl (the exploit) of a compound command that
    # first logs in must NOT be matched to the login endpoint (weak-admin-creds).
    # The shell-variable resolution must not leak `POST $B/auth/login` into the
    # saved body's requests.
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    command = (
        "export B=https://duck-store.escape.tech/api/v1; "
        "ATOK=$(curl -s -X POST $B/auth/login -H 'Content-Type: application/json' "
        '-d \'{"username":"tester","password":"pw"}\'); '
        "curl -sS -i $B/testimonials/6 -o evidence/vuln-research/testimonial-6-read.txt "
        "-w 'HTTP %{http_code}'"
    )
    body_dir = tmp_path / "evidence" / "vuln-research"
    body_dir.mkdir(parents=True, exist_ok=True)
    body = body_dir / "testimonial-6-read.txt"
    body.write_text("HTTP/1.1 200 OK\n", encoding="utf-8")
    body_relative = body.relative_to(tmp_path).as_posix()
    receipt_path = _write_receipt(
        tmp_path,
        key=key,
        command=command,
        proof="HTTP/1.1 200 OK\n",
        declared_evidence_outputs=[body_relative],
    )
    golden_id, candidates = match_finding(
        tmp_path,
        {
            "receipt_paths": [receipt_path],
            "evidence_paths": [body_relative],
        },
        load_golden_set(),
        receipt_key=key,
    )
    assert "weak-admin-creds" not in candidates


def test_compound_command_body_correlates_to_its_own_subcommand(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A body saved by the SECOND curl of a two-curl `sh -c` command must not
    # inherit the FIRST curl's method/path. Regression: user-enumeration body
    # was matched to mass-assign-role because it inherited the mass-assign PUT.
    key = b"k" * 32
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_KEY", key)
    monkeypatch.setattr(receipt_integrity, "_RUNTIME_SIGNING_KEY", None)
    command = (
        "sh -c 'curl -sS -i --http1.1 -X PUT "
        "https://duck-store.escape.tech/api/v1/users/me/profile "
        '-H "Authorization: Bearer x" -d "{\\"role\\":\\"admin\\"}" '
        '-o evidence/vuln-research/profile-massassign.txt -w "HTTP %{http_code}\\n"; '
        "curl -sS -i --http1.1 https://duck-store.escape.tech/api/v1/users/ "
        '-o evidence/vuln-research/users-unauth-enum.txt -w "HTTP %{http_code}\\n"\''
    )
    # Save the user-enumeration body and attach it as evidence_paths.
    body_dir = tmp_path / "evidence" / "vuln-research"
    body_dir.mkdir(parents=True, exist_ok=True)
    body = body_dir / "users-unauth-enum.txt"
    body.write_text(
        'HTTP/1.1 200 OK\n{"users":[{"username":"alice"},{"username":"bob"}]}\n',
        encoding="utf-8",
    )
    body_relative = body.relative_to(tmp_path).as_posix()
    receipt_path = _write_receipt(
        tmp_path,
        key=key,
        command=command,
        proof="HTTP/1.1 200 OK\n",
        declared_evidence_outputs=[body_relative],
    )
    finding = {
        "receipt_paths": [receipt_path],
        "evidence_paths": [body_relative],
    }
    golden_id, candidates = match_finding(
        tmp_path,
        finding,
        load_golden_set(),
        receipt_key=key,
    )
    assert golden_id == "user-enumeration", candidates
    assert "mass-assign-role" not in candidates


def test_agent_container_excludes_private_evaluator() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    sources = [
        source
        for line in dockerfile.splitlines()
        if line.startswith("COPY ")
        for source in line.split()[1:-1]
    ]
    copied_files = {
        child.as_posix()
        for source in sources
        for child in (Path(source).rglob("*") if Path(source).is_dir() else [Path(source)])
        if child.is_file()
    }
    assert "benchmark/run.py" in copied_files
    assert "benchmark/targets/duck-store/scope.yaml" in copied_files
    assert not any(
        path.startswith(("benchmark/private/", "benchmark/targets/duck-store/calibration/"))
        or path in {"benchmark/proof.py", "benchmark/score.py"}
        for path in copied_files
    )


def test_structured_proof_skips_source_parsing_and_duplicate_reads(tmp_path, monkeypatch):
    from benchmark import proof

    relative = _write_receipt(
        tmp_path,
        key=b"s" * 32,
        command="python3 probe.py",
        proof='GET /items HTTP/1.1\nHTTP/1.1 200 OK\n{"items":[]}\n',
    )
    original_read = proof._read
    reads = []

    def read(path, *args):
        reads.append(path)
        return original_read(path, *args)

    def unexpected_parse(*args):
        pytest.fail("structured proof should not parse command/script source")

    monkeypatch.setattr(proof, "_read", read)
    monkeypatch.setattr(proof, "_source_requests", unexpected_parse)
    assert proof.receipt_bundles(
        tmp_path,
        [relative],
        receipt_key=b"s" * 32,
        evidence_paths=["evidence/executions/proof.stdout.txt"],
    )
    assert len(reads) == len(set(reads)) == 2
