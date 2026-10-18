import pytest

from agentarium_discovery import template as tpl


@pytest.mark.parametrize(
    "text",
    [
        "https://*.googleapis.com/v1/",
        "https://oauth2.googleapis.com/token",
        "HTTPS://OAuth2.GoogleAPIs.com/token",
        "http://example.com:8080/",
        "https://10.0.0.1:443/",
        "https://[2001:db8::1]:8443/",
    ],
)
def test_valid_templates(text):
    assert tpl.is_valid(text)


@pytest.mark.parametrize(
    "text",
    [
        "https://**.googleapis.com/v1/",  # ** forbidden
        "https://a*.googleapis.com/",  # partial wildcard
        "ftp://example.com/",  # scheme
        "https://example.com",  # path-prefix required
        "https://example.com:0/",  # port range
        "https://example.com:65536/",
        "https://example..com/",  # empty label
        "https://-bad.com/",
        "https://example.com/v1/*",  # path is a literal
        "https://example.com/v1?x=1",
        "https://user@example.com/",
        "https://" + "a." * 300 + "com/",
    ],
)
def test_invalid_templates(text):
    assert not tpl.is_valid(text)


def test_default_ports():
    assert tpl.parse("https://example.com/").port == 443
    assert tpl.parse("http://example.com/").port == 80


def test_host_glob_is_one_label_and_case_insensitive():
    t = tpl.parse("https://*.googleapis.com/")
    assert t.host_matches("storage.googleapis.com")
    assert t.host_matches("Storage.GoogleAPIs.COM.")
    assert not t.host_matches("googleapis.com")
    assert not t.host_matches("a.b.googleapis.com")
    assert not t.host_matches("storage.googleapis.com.evil.net")


def test_path_prefix_segment_boundary():
    t = tpl.parse("https://example.com/v1")
    assert t.path_matches("/v1")
    assert t.path_matches("/v1/x")
    assert t.path_matches("/v1?alt=json")
    assert not t.path_matches("/v10")
    assert not t.path_matches("/v")
    slash = tpl.parse("https://example.com/v1/")
    assert slash.path_matches("/v1/x")
    assert not slash.path_matches("/v1")
    assert tpl.parse("https://example.com/").path_matches("/anything")
    assert not tpl.parse("https://example.com/token").path_matches("/tokens")


def test_for_observation():
    assert tpl.for_observation(None, None, "203.0.113.5", 8443) == "https://203.0.113.5:8443/"
    assert tpl.for_observation("http", None, "2001:db8::1", 80) == "https://[2001:db8::1]:80/"
    assert tpl.for_observation("https", "api.example.com", "203.0.113.5", 443) == "https://api.example.com/"
    assert tpl.for_observation(None, "api.example.com", "203.0.113.5", 9000) == "https://api.example.com:9000/"
    for t in ["https://203.0.113.5:8443/", "https://[2001:db8::1]:80/"]:
        assert tpl.is_valid(t)
