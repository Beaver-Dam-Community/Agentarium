import json
import pathlib
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent / "testdata" / "pylib"
SCANNER = HERE.parent / "pyscan" / "scan.py"

sys.path.insert(0, str(SCANNER.parent))
import scan  # noqa: E402


@pytest.fixture(scope="module")
def result():
    return scan.scan(str(ROOT))


def sites(result):
    return {(s["caller"], s["callee"], s["category"]): s for s in result["call_sites"]["call_sites"]}


def test_aliases_resolve_to_targets(result):
    got = sites(result)
    assert ("mylib.transport.send", "http.client.HTTPSConnection", "http.client") in got
    assert got[("mylib.transport.send", "http.client.HTTPSConnection", "http.client")]["import_alias"] == "hc"
    assert ("mylib.transport.run", "subprocess.run", "subprocess") in got
    assert ("mylib.transport.run", "os.open", "os.open") in got
    assert got[("mylib.transport.run", "os.open", "os.open")]["import_alias"] == "os_open"
    assert ("mylib.transport.run", "open", "open") in got


def test_constructor_receivers_are_tracked(result):
    got = sites(result)
    # conn = hc.HTTPSConnection(...); conn.request(...)
    assert ("mylib.transport.send", "http.client.HTTPSConnection.request", "http.client") in got
    # s = socket.socket(); s.connect(...)
    assert ("mylib.transport.send", "socket.socket.connect", "socket") in got
    # with HttpxClient() as c: c.post(...)
    assert ("mylib.transport.Uploader.upload", "httpx.Client.post", "httpx") in got
    assert ("mylib.transport.Uploader.__init__", "urllib3.PoolManager", "urllib3") in got
    assert ("mylib.transport.Uploader.helper", "requests.get", "requests") in got


def test_non_constructor_results_and_shadowing_are_not_targets(result):
    callees = {s["callee"] for s in result["call_sites"]["call_sites"]}
    # r = requests.get(...) is not a constructor; r.json() must not be listed.
    assert "requests.get.json" not in callees
    shadowed = [s for s in result["call_sites"]["call_sites"] if s["caller"] == "mylib.transport.shadowed"]
    assert shadowed == []


def test_dynamic_dispatch_is_reported_as_limitation(result):
    callers = {s["caller"] for s in result["call_sites"]["call_sites"]}
    assert "mylib.transport.dynamic" not in callers
    lim = result["call_sites"]["limitations"]
    assert any("dynamic dispatch" in x for x in lim)
    assert any(x.startswith("not parsed: mylib/broken.py") for x in lim)


def test_import_aliases_and_callgraph(result):
    aliases = {(i["alias"], i["target"]) for i in result["call_sites"]["imports"]}
    assert ("hc", "http.client") in aliases
    assert ("HttpxClient", "httpx.Client") in aliases
    assert ("sp", "subprocess") in aliases
    graph = result["callgraph"]
    assert "mylib.transport.Uploader.helper" in graph["mylib.transport.Uploader.upload"]
    assert graph["mylib.transport.send"] == sorted(graph["mylib.transport.send"])


def test_cli_output_is_deterministic():
    out1 = subprocess.run([sys.executable, str(SCANNER), str(ROOT)], check=True, capture_output=True).stdout
    out2 = subprocess.run([sys.executable, str(SCANNER), str(ROOT)], check=True, capture_output=True).stdout
    assert out1 == out2
    doc = json.loads(out1)
    assert doc["call_sites"]["language"] == "python"
    assert doc["call_sites"]["tool"] == "python-ast"
