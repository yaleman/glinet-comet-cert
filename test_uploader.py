"""Exercise certificate deployment against a loopback-only HTTPS fixture."""

import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse

UPLOADER = Path(__file__).with_name("uploader.py")
USERNAME = "mock fixture user+%"
PASSWORD = "mock fixture password+&%"
COOKIE_VALUE = "mock-secret-cookie"
HOSTNAME = "comet-fixture.test"


class HTTPSFixture(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self, paths, reject_upload=False, untrusted_old=False,
        require_mfa=False, disconnect_on_upload=False,
    ):
        self.paths = paths
        self.reject_upload = reject_upload
        self.require_mfa = require_mfa
        self.disconnect_on_upload = disconnect_on_upload
        self.requests = []
        self.contexts = {}
        for kind in ("old", "new"):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            cert = paths["old_untrusted_crt"] if kind == "old" and untrusted_old else paths[kind + "_crt"]
            context.load_cert_chain(cert, paths[kind + "_key"])
            self.contexts[kind] = context
        self.active = "old"
        super().__init__(("127.0.0.1", 0), FixtureHandler)

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(3)
        try:
            return self.contexts[self.active].wrap_socket(sock, server_side=True), addr
        except OSError:
            sock.close()
            raise


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_POST(self):
        count = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(count).decode("utf-8")
        content_type = self.headers.get_content_type()
        body_fields = json.loads(data) if content_type == "application/json" else urllib.parse.parse_qs(data)
        cookie = self.headers.get("Cookie", "")
        self.server.requests.append((self.path, body_fields, cookie, content_type))
        status = 200
        new_cookie = None
        if len(self.server.requests) == 1:
            reply = {"ok": True, "result": {"two_step_required": True}
                     if self.server.require_mfa else {}}
            new_cookie = f"auth_token={COOKIE_VALUE}; Path=/; Secure; HttpOnly"
        elif self.server.reject_upload:
            reply = {"ok": True, "result": {"success": False}}
        else:
            self.server.active = "new"
            if self.server.disconnect_on_upload:
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            reply = {"ok": True, "result": {"success": True}}
        body = json.dumps(reply).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if new_cookie:
            self.send_header("Set-Cookie", new_cookie)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class TestUploader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp_dir.cleanup)
        root = Path(cls.temp_dir.name)
        cls.paths = {
            name: root / (name.replace("_", "."))
            for name in ("ca_crt", "ca_key", "old_crt", "old_key", "new_crt", "new_key",
                         "old_ca_crt", "old_ca_key", "old_untrusted_crt")
        }
        config = root / "extensions.cnf"
        config.write_text(
            "[req]\ndistinguished_name=dn\n[dn]\n[leaf]\n"
            "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
            f"subjectAltName=DNS:{HOSTNAME},IP:127.0.0.1\n"
            "[ca]\nbasicConstraints=critical,CA:TRUE\n"
            "keyUsage=critical,keyCertSign,cRLSign\n",
            encoding="ascii",
        )

        def openssl(*args):
            subprocess.run(
                ["openssl", *map(str, args)],
                capture_output=True, check=True, timeout=20,
            )

        openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
            "-subj", "/CN=Disposable Comet Fixture CA",
            "-keyout", cls.paths["ca_key"], "-out", cls.paths["ca_crt"],
            "-config", config, "-extensions", "ca",
        )
        openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3",
            "-subj", "/CN=Independent Comet Fixture CA",
            "-keyout", cls.paths["old_ca_key"], "-out", cls.paths["old_ca_crt"],
            "-config", config, "-extensions", "ca",
        )
        for serial, kind in enumerate(("old", "new"), start=1):
            csr = root / (kind + ".csr")
            openssl(
                "req", "-newkey", "rsa:2048", "-nodes",
                "-subj", f"/CN={HOSTNAME}", "-keyout", cls.paths[kind + "_key"],
                "-out", csr, "-config", config,
            )
            openssl(
                "x509", "-req", "-days", "2", "-in", csr, "-set_serial", serial,
                "-CA", cls.paths["ca_crt"], "-CAkey", cls.paths["ca_key"],
                "-out", cls.paths[kind + "_crt"], "-extfile", config,
                "-extensions", "leaf",
            )

        openssl(
            "x509", "-req", "-days", "2", "-in", root / "old.csr", "-set_serial", "1",
            "-CA", cls.paths["old_ca_crt"], "-CAkey", cls.paths["old_ca_key"],
            "-out", cls.paths["old_untrusted_crt"], "-extfile", config,
            "-extensions", "leaf",
        )

    def start_server(self, **kwargs):
        server = HTTPSFixture(self.paths, **kwargs)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=4)

        self.addCleanup(cleanup)
        return server

    def run_cli(self, server, *, cli_args=(), factory_pin=None, **overrides):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("COMET_")}
        env.update(
            COMET_URL=f"https://{HOSTNAME}:{server.server_port}",
            COMET_CONNECT_IP="127.0.0.1",
            COMET_USERNAME=USERNAME,
            COMET_PASSWORD=PASSWORD,
            COMET_CERT_PATH=str(self.paths["new_crt"]),
            COMET_KEY_PATH=str(self.paths["new_key"]),
            COMET_CA_PATH=str(self.paths["ca_crt"]),
        )
        for key, value in overrides.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
        if factory_pin is None:
            command = [sys.executable, str(UPLOADER), *cli_args]
        else:
            command = [sys.executable, "-c",
                       "import uploader,sys; uploader.FACTORY_PIN=sys.argv.pop(1); "
                       "raise SystemExit(uploader.main())", factory_pin, *cli_args]
        run = subprocess.run(
            command, cwd=UPLOADER.parent,
            env=env, capture_output=True, text=True, timeout=25,
        )
        output = run.stdout + run.stderr
        for secret in ["PRIVATE KEY", "BEGIN CERTIFICATE", USERNAME, PASSWORD,
                       COOKIE_VALUE, *self.paths["new_key"].read_text().splitlines()[1:3]]:
            self.assertNotIn(secret, output, "CLI printed confidential input")
        return run

    def assert_upload_forms(self, server, login_fields):
        self.assertEqual(len(server.requests), 2)
        login_path, login, login_cookie, login_content_type = server.requests[0]
        upload_path, upload, upload_cookie, upload_content_type = server.requests[1]
        self.assertEqual(login_path, "/api/auth/login")
        self.assertEqual(upload_path, "/api/system/ssl_cert")
        for key, expected in zip(login_fields, (USERNAME, PASSWORD)):
            self.assertEqual(login.get(key), [expected])
        self.assertEqual(login_cookie, "")
        self.assertIn(f"auth_token={COOKIE_VALUE}", upload_cookie)
        self.assertEqual(login_content_type, "application/x-www-form-urlencoded")
        self.assertEqual(upload_content_type, "application/json")
        self.assertEqual(set(upload), {"ssl_cert", "ssl_key"})
        for upload_key, path_key in (("ssl_cert", "new_crt"), ("ssl_key", "new_key")):
            self.assertTrue(upload[upload_key].strip() == self.paths[path_key].read_text().strip(),
                            "Upload did not preserve the PEM field")

    def test_updates_then_skips_identical_leaf_without_logging_in_again(self):
        server = self.start_server()
        first = self.run_cli(server)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(server.active, "new")
        self.assert_upload_forms(server, ("user", "passwd"))

        second = self.run_cli(server)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(len(server.requests), 2)

    def test_alternate_login_fields(self):
        server = self.start_server()
        run = self.run_cli(server, COMET_LOGIN_FIELDS="username-password")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assert_upload_forms(server, ("username", "password"))

    def test_untrusted_peer_receives_no_posts(self):
        server = self.start_server(untrusted_old=True)
        run = self.run_cli(server)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(server.requests, [])

    def test_wrong_pin_for_untrusted_peer_receives_no_posts(self):
        server = self.start_server(untrusted_old=True)
        run = self.run_cli(server, COMET_TLS_PIN_SHA256="0" * 64)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(server.requests, [])

    def test_shared_factory_fingerprint_cannot_authorize_posts(self):
        from uploader import FACTORY_PIN

        server = self.start_server(untrusted_old=True)
        run = self.run_cli(server, COMET_TLS_PIN_SHA256=FACTORY_PIN)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("shared factory certificate", run.stderr)
        self.assertEqual(server.requests, [])

    def synthetic_factory_pin(self):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            self.paths["old_untrusted_crt"].read_text()
        )).hexdigest()

    def test_factory_bootstrap_is_opt_in(self):
        server = self.start_server(untrusted_old=True)
        run = self.run_cli(server, factory_pin=self.synthetic_factory_pin())
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(server.requests, [])

    def test_factory_bootstrap_requires_explicit_connect_ip(self):
        server = self.start_server(untrusted_old=True)
        run = self.run_cli(
            server, cli_args=("--allow-factory-bootstrap",),
            factory_pin=self.synthetic_factory_pin(), COMET_CONNECT_IP=None,
        )
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("COMET_CONNECT_IP", run.stderr)
        self.assertEqual(server.requests, [])

    def test_factory_bootstrap_cannot_be_combined_with_custom_pin(self):
        server = self.start_server(untrusted_old=True)
        run = self.run_cli(
            server, cli_args=("--allow-factory-bootstrap",),
            factory_pin=self.synthetic_factory_pin(), COMET_TLS_PIN_SHA256="a" * 64,
        )
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("COMET_TLS_PIN_SHA256", run.stderr)
        self.assertEqual(server.requests, [])

    def test_factory_bootstrap_rejects_untrusted_nonfactory_leaf(self):
        server = self.start_server(untrusted_old=True)
        run = self.run_cli(
            server, cli_args=("--allow-factory-bootstrap",),
            factory_pin="a" * 64,
        )
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(server.requests, [])

    def test_factory_bootstrap_rotates_matching_synthetic_factory_leaf(self):
        server = self.start_server(untrusted_old=True)
        pin = self.synthetic_factory_pin()
        first = self.run_cli(
            server, cli_args=("--allow-factory-bootstrap",), factory_pin=pin,
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(server.active, "new")
        self.assert_upload_forms(server, ("user", "passwd"))

        second = self.run_cli(
            server, cli_args=("--allow-factory-bootstrap",), factory_pin=pin,
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(len(server.requests), 2)

    def test_matching_old_pin_allows_rotation_to_known_new_leaf(self):
        server = self.start_server(untrusted_old=True)
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            self.paths["old_untrusted_crt"].read_text()
        )).hexdigest()
        run = self.run_cli(server, COMET_TLS_PIN_SHA256=pin)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(server.active, "new")
        self.assert_upload_forms(server, ("user", "passwd"))

    def test_mismatched_replacement_key_is_rejected_before_post(self):
        server = self.start_server()
        run = self.run_cli(server, COMET_KEY_PATH=str(self.paths["old_key"]))
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("Replacement PEM check failed", run.stderr)
        self.assertEqual(server.requests, [])

    def test_replacement_wrong_dns_name_is_rejected_before_post(self):
        server = self.start_server()
        run = self.run_cli(
            server, COMET_URL=f"https://wrong-comet-fixture.test:{server.server_port}",
        )
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("Replacement PEM check failed", run.stderr)
        self.assertEqual(server.requests, [])

    def test_two_step_authentication_never_uploads(self):
        server = self.start_server(require_mfa=True)
        run = self.run_cli(server)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("two-step", run.stderr)
        self.assertEqual([request[0] for request in server.requests], ["/api/auth/login"])

    def test_reload_disconnect_verifies_new_peer_without_reupload(self):
        server = self.start_server(disconnect_on_upload=True)
        run = self.run_cli(server)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(server.active, "new")
        self.assert_upload_forms(server, ("user", "passwd"))

    def test_failed_upload_is_not_retried(self):
        server = self.start_server(reject_upload=True)
        run = self.run_cli(server)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(server.active, "old")
        self.assert_upload_forms(server, ("user", "passwd"))


if __name__ == "__main__":
    unittest.main()
