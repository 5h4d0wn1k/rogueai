import unittest

from rogueai import scope


class TestScopeAllowlist(unittest.TestCase):
    LOOPBACK_OK = [
        "127.0.0.1",
        "localhost",
        "127.0.0.1:8080",
        "127.0.0.2",
        "127.99.1.1",
        "[::1]",
        "[::1]:9000",
        "localhost:22",
        "127.0.0.1:443",
    ]

    EXTERNAL_NO = [
        "8.8.8.8",
        "8.8.8.8:80",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "0.0.0.0",
        "example.com",
        "example.com:8080",
        "https://example.com",
    ]

    def test_loopback_allowed(self):
        for t in self.LOOPBACK_OK:
            with self.subTest(t=t):
                self.assertTrue(scope.safe(t), t)

    def test_external_refused(self):
        for t in self.EXTERNAL_NO:
            with self.subTest(t=t):
                self.assertFalse(scope.safe(t), t)

    def test_lab_fixtures_allowed(self):
        for t in ("lab://http", "lab://ssh", "lab://mqtt", "lab://vault", "lab://vault/x"):
            with self.subTest(t=t):
                self.assertTrue(scope.safe(t), t)

    def test_empty_invalid_refused(self):
        for t in ("", " ", None):
            with self.subTest(t=t):
                self.assertFalse(scope.safe(t))

    def test_http_scheme_loopback_allowed(self):
        self.assertTrue(scope.safe("http://127.0.0.1:8080"))
        self.assertTrue(scope.safe("https://localhost"))

    def test_http_scheme_external_refused(self):
        self.assertFalse(scope.safe("http://8.8.8.8"))
        self.assertFalse(scope.safe("ftp://example.com"))

    def test_parse_forms(self):
        kind, value, port = scope.parse_target("127.0.0.1:8443")
        self.assertEqual((kind, value, port), ("host", "127.0.0.1", 8443))
        kind, value, port = scope.parse_target("lab://mqtt")
        self.assertEqual((kind, value), ("lab", "mqtt"))
        kind, value, port = scope.parse_target("[::1]:443")
        self.assertEqual((kind, value, port), ("host", "::1", 443))

    def test_is_loopback(self):
        self.assertTrue(scope.is_loopback("127.0.0.1"))
        self.assertTrue(scope.is_loopback("localhost"))
        self.assertTrue(scope.is_loopback("::1"))
        self.assertFalse(scope.is_loopback("8.8.8.8"))
        self.assertFalse(scope.is_loopback("google.com"))

    def test_describe(self):
        self.assertIn("loopback", scope.describe("127.0.0.1"))
        self.assertIn("external", scope.describe("8.8.8.8"))
        self.assertIn("lab fixture", scope.describe("lab://http"))


if __name__ == "__main__":
    unittest.main()