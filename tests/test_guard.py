import pytest
from app.security.guard import normalize_url, UnsafeURL

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/a", "https://localhost/", "http://192.168.1.9/",
    "https://169.254.169.254/latest", "ftp://example.com/", "https://user:pass@example.com",
    "https://example.com:4443/", "http://[::1]/", "http://10.0.0.1/a",
    "http://metadata.google.internal/", "file:///etc/passwd", "javascript:alert(1)",
    "https://a.test/", "https://a.local/", "http://0.0.0.0/", "http://8.8.8.8:1234/"
])
def test_reject_internal_and_unsafe(url):
    with pytest.raises(UnsafeURL):
        normalize_url(url)

@pytest.mark.parametrize("url,expected", [
    ("https://example.com", "https://example.com/"),
    ("example.com/path", "https://example.com/path"),
    ("http://example.com:80/page?q=ok#fragment", "http://example.com:80/page?q=ok"),
    ("https://www.google.com/path", "https://www.google.com/path"),
])
def test_normalize(url, expected):
    assert normalize_url(url) == expected
