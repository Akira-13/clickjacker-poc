
import requests

from clickjack import check_clickjacking


def _build_response(headers=None, cookies=None):
    """Construct a Response with custom headers and cookies for testing."""
    resp = requests.Response()
    resp.status_code = 200
    resp._content = b"ok"
    resp.headers = headers or {}
    jar = requests.cookies.RequestsCookieJar()
    for name, value, rest in cookies or []:
        jar.set(name, value, rest=rest)
    resp.cookies = jar
    return resp


def test_vulnerable_when_no_xfo_or_csp(monkeypatch):
    resp = _build_response(
        headers={},
    )

    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is True
    assert report["details"]["x_frame_options"] == "MISSING"
    assert report["details"]["csp_frame_ancestors"] is False


def test_not_vulnerable_with_deny_xfo(monkeypatch):
    resp = _build_response(headers={"X-Frame-Options": "DENY"})
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is False
    assert report["details"]["x_frame_options"] == "DENY"

def test_not_vulnerable_with_same_origin_xfo(monkeypatch):
    resp = _build_response(headers={"X-Frame-Options": "SAMEORIGIN"})
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is False
    assert report["details"]["x_frame_options"] == "SAMEORIGIN"

def test_not_vulnerable_with_frame_ancestors(monkeypatch):
    csp = "default-src 'self'; frame-ancestors 'none'"
    resp = _build_response(headers={"Content-Security-Policy": csp})
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is False
    assert report["details"]["csp_frame_ancestors"] is True


def test_request_exception_returns_error(monkeypatch):
    def _raise(*args, **kwargs):
        raise requests.exceptions.RequestException("boom")

    monkeypatch.setattr("requests.get", _raise)

    report = check_clickjacking("http://example.com")

    assert report == {"error": "boom"}


def test_vulnerable_with_xfo_but_insecure_cookies(monkeypatch):
    resp = _build_response(
        headers={"X-Frame-Options": "DENY"},
        cookies=[("session", "abc123", {"SameSite": ""})],
    )
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is False
    assert report["details"]["x_frame_options"] == "DENY"
    assert report["details"]["insecure_cookies"] == ["session"]


def test_not_vulnerable_but_with_strict_samesite_cookie(monkeypatch):
    resp = _build_response(
        headers={"X-Frame-Options": "DENY"},
        cookies=[("session", "abc123", {"SameSite": "Strict"})],
    )
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is False
    assert report["details"]["insecure_cookies"] == []


def test_not_vulnerable_but_with_lax_samesite_cookie(monkeypatch):
    resp = _build_response(
        headers={"X-Frame-Options": "DENY"},
        cookies=[("session", "abc123", {"SameSite": "Lax"})],
    )
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is False
    assert report["details"]["insecure_cookies"] == []


def test_not_vulnerable_but_with_none_samesite_cookie(monkeypatch):
    resp = _build_response(
        headers={"X-Frame-Options": "DENY"},
        cookies=[("session", "abc123", {"SameSite": "None"})],
    )
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is False
    assert report["details"]["insecure_cookies"] == ["session"]


def test_not_vulnerable_but_with_multiple_insecure_cookies(monkeypatch):
    resp = _build_response(
        headers={"X-Frame-Options": "DENY"},
        cookies=[
            ("session", "abc", {"SameSite": ""}),
            ("csrf", "xyz", {"SameSite": "None"}),
            ("tracking", "123", {}),
        ],
    )
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is False
    assert set(report["details"]["insecure_cookies"]) == {"session", "csrf", "tracking"}


def test_not_vulnerable_but_with_cookies_all_secure(monkeypatch):
    resp = _build_response(
        headers={"X-Frame-Options": "DENY"},
        cookies=[
            ("session", "abc", {"SameSite": "Strict"}),
            ("csrf", "xyz", {"SameSite": "Lax"}),
        ],
    )
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is False
    assert report["details"]["insecure_cookies"] == []


def test_vulnerable_frameable_with_protected_cookies(monkeypatch, capsys):
    resp = _build_response(
        headers={},
        cookies=[
            ("session", "abc", {"SameSite": "Strict"}),
            ("csrf", "xyz", {"SameSite": "Lax"}),
        ],
    )
    monkeypatch.setattr("requests.get", lambda *args, **kwargs: resp)

    report = check_clickjacking("http://example.com")

    assert report["vulnerable"] is True
    assert report["details"]["insecure_cookies"] == []
    
    captured = capsys.readouterr()
    assert "Site appears to be frameable but has protected cookies" in captured.out
    assert "session" in captured.out
    assert "csrf" in captured.out
