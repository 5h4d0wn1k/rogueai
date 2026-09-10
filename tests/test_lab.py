import unittest

from rogueai.lab import LabManager
from rogueai.lab_http import DB_SECRET, sqli_oracle
from rogueai.lab_mqtt import mqtt_subscribe
from rogueai.lab_ssh import auth_session, knock
from rogueai.lab_vault import VAULT_FLAG, read_fixture, read_trips


class TestLabFixtures(unittest.TestCase):
    def setUp(self):
        self.lab = LabManager()
        self.endpoints = self.lab.spawn_all()

    def tearDown(self):
        self.lab.stop_all()

    def test_all_endpoints_spawned(self):
        self.assertTrue(self.endpoints["http"])
        self.assertTrue(self.endpoints["ssh"])
        self.assertTrue(self.endpoints["mqtt"])
        self.assertEqual(self.endpoints["vault"]["flag"], VAULT_FLAG)

    def test_http_counts_requests(self):
        base = f"http://{self.lab.endpoint('http')}/__counter"
        import urllib.request

        before = int(urllib.request.urlopen(base).read())
        urllib.request.urlopen(base).read()
        after = int(urllib.request.urlopen(base).read())
        self.assertGreater(after, before)

    def test_http_index(self):
        import urllib.request

        body = urllib.request.urlopen(f"http://{self.lab.endpoint('http')}/").read().decode()
        self.assertIn("/item?id=", body)
        self.assertIn("/comment?msg=", body)

    def test_sqli_endpoint_found_and_missing(self):
        import urllib.parse
        import urllib.request

        true_payload = urllib.parse.quote("1' AND '1'='1-- -")
        false_payload = urllib.parse.quote("1' AND '1'='2-- -")
        base = f"http://{self.lab.endpoint('http')}/item?id="
        self.assertIn("ITEM_FOUND", urllib.request.urlopen(base + true_payload).read().decode())
        self.assertIn("ITEM_MISSING", urllib.request.urlopen(base + false_payload).read().decode())

    def test_sqli_oracle_unit(self):
        self.assertTrue(sqli_oracle("1"))
        self.assertTrue(sqli_oracle("1' AND (SELECT MID(secret,1,1))>CHAR(63)-- -"))
        self.assertTrue(sqli_oracle(f"1' AND (SELECT MID(secret,1,1))=CHAR({ord('F')})-- -"))
        self.assertFalse(sqli_oracle(f"1' AND (SELECT MID(secret,1,1))=CHAR({ord('X')})-- -"))
        self.assertFalse(sqli_oracle("1' AND (SELECT MID(secret,99,1))=CHAR(70)-- -"))

    def test_xss_echo(self):
        import urllib.parse
        import urllib.request

        payload = "<script>alert(1)</script>"
        body = urllib.request.urlopen(
            f"http://{self.lab.endpoint('http')}/comment?msg={urllib.parse.quote(payload)}"
        ).read().decode()
        self.assertIn(payload, body)

    def test_open_redirect(self):
        import http.client

        host, port = self.lab.endpoint("http").split(":")
        conn = http.client.HTTPConnection(host, int(port))
        conn.request("GET", "/redirect?url=http://example.example/")
        resp = conn.getresponse()
        resp.read()
        self.assertEqual(resp.status, 302)
        self.assertEqual(resp.getheader("Location"), "http://example.example/")
        conn.close()

    def test_ssh_creds_fixture(self):
        host, port = self.lab.endpoint("ssh").split(":")
        results = auth_session(host, int(port), [("admin", "hunter2"), ("admin", "wrong"), ("root", "toor")])
        found = {(u, p) for u, p, ok in results if ok}
        self.assertIn(("admin", "hunter2"), found)
        self.assertIn(("root", "toor"), found)
        self.assertEqual(len(found), 2)

    def test_ssh_knock_sim(self):
        host, port = self.lab.endpoint("ssh").split(":")
        self.assertIn("KNOCK_OK", knock(host, int(port)))

    def test_mqtt_bad_subscribe_flag(self):
        host, port = self.lab.endpoint("mqtt").split(":")
        messages = mqtt_subscribe(host, int(port), "vault/telemetry")
        topics = [t for t, _ in messages]
        payloads = [p for _, p in messages]
        self.assertIn("vault/telemetry", topics)
        self.assertTrue(any("FLAG{" in p for p in payloads))

    def test_mqtt_wildcard_subscribe(self):
        host, port = self.lab.endpoint("mqtt").split(":")
        messages = mqtt_subscribe(host, int(port), "#")
        self.assertGreaterEqual(len(messages), 2)
        topics = {t for t, _ in messages}
        self.assertTrue(topics.issuperset({"vault/telemetry", "lab/notice"}))

    def test_vault_flag_deterministic(self):
        self.assertEqual(read_fixture("flag.txt"), VAULT_FLAG)
        self.assertEqual(read_fixture("flag.txt"), VAULT_FLAG)

    def test_vault_honeytoken_trip(self):
        before = len(read_trips())
        read_fixture("flag.txt")
        after = len(read_trips())
        self.assertEqual(after, before + 1)

    def test_vault_traversal_refused(self):
        with self.assertRaises(ValueError):
            read_fixture("../flag.txt")

    def test_stop_all(self):
        self.lab.stop_all()
        self.lab.stop_all()


if __name__ == "__main__":
    unittest.main()