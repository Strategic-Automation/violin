"""Static request inference must distinguish Python syntax from URL-shaped text."""

import shlex

import pytest

from benchmark.proof import _python_request_observations, _scripted_flow_requests

URL = "https://example.test/items"


@pytest.mark.parametrize(
    "source,expected",
    [
        (f"requests.get('{URL}')", [("GET", URL)]),
        (f"# requests.get('{URL}')", []),
        (f'''text = "requests.get('{URL}')"''', []),
        (f"BASE = '{URL}'", []),
        (f"import requests as client\nclient.post(url='{URL}')", [("POST", URL)]),
        (f"from requests import put as send\nsend('{URL}')", [("PUT", URL)]),
        (f"session = requests.Session()\nsession.delete('{URL}')", [("DELETE", URL)]),
        (f"BASE = '{URL}'\nrequests.get(BASE + '/1')", [("GET", URL + "/1")]),
        (f"BASE = '{URL}'\nitem = 7\nrequests.get(f'{{BASE}}/{{item}}')", [("GET", URL + "/7")]),
        (f"print(requests.patch(url='{URL}', json=dict(value=1)))", [("PATCH", URL)]),
        (f"Request('{URL}', data=b'x', method='PUT')", [("PUT", URL)]),
        (f"Request('{URL}', data=None)", [("GET", URL)]),
        (f"Request('{URL}', b'x')", [("POST", URL)]),
        (
            f"from urllib.request import Request as R\nR(fullurl='{URL}', data=encode(payload), method='PUT')",
            [("PUT", URL)],
        ),
        (
            f"BASE = '{URL}'\ndef call(method, path):\n return requests.request(method, BASE + path)\ncall('POST', '/1')",
            [("POST", URL + "/1")],
        ),
        (f"def unused():\n return requests.get('{URL}')", []),
        (f"call('POST', '/1') # {URL}", []),
        (f"requests = other_client\nrequests.get('{URL}')", []),
        (f"requests.get('{URL}')\nrequests.get(dynamic_url)", []),
        (f"requests.get(f'{URL}/{{unknown}}')", []),
        (f"False and requests.get('{URL}')", []),
        (f"if False:\n requests.get('{URL}')", []),
        (f"requests.get('{URL}', url='https://other.test')", []),
        (f"requests.get('{URL}'", []),
    ],
)
def test_python_request_candidates(source, expected):
    assert [
        (item.method, str(item.url)) for item in _python_request_observations(source)
    ] == expected


def test_script_loading_uses_actual_python_arguments(tmp_path):
    source = f"requests.post('{URL}')"
    script = tmp_path / "probe with spaces.py"
    script.write_text(source, encoding="utf-8")
    commands = [f"python3 -c {shlex.quote(source)}", f"python3 {shlex.quote(script.name)}"]
    for command in commands:
        assert [
            (item.method, str(item.url)) for item in _scripted_flow_requests(command, tmp_path)
        ] == [("POST", URL)]
    assert not _scripted_flow_requests(f"echo {shlex.quote(script.name)}", tmp_path)
    assert not _scripted_flow_requests("python3 ../outside.py", tmp_path)
    script.write_text(source + "\n" + " " * (256 * 1024), encoding="utf-8")
    assert not _scripted_flow_requests(f"python3 {shlex.quote(script.name)}", tmp_path)


def test_constant_expansion_is_bounded():
    source = "path = 'x'\n" + "path = path + path\n" * 30
    source += "requests.get('https://example.test/' + path)"
    assert _python_request_observations(source) == []
