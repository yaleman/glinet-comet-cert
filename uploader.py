#!/usr/bin/env python3
"""Install a renewed HTTPS certificate on a GL.iNet Comet."""
import argparse
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import tempfile
import time
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlencode, urlsplit


FACTORY_PIN = "29a022dbe5de0f400698105d92af25640fa5f149cb590a02abd3eaa3542cffca"
PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", re.S)
TOKEN = re.compile(r"[A-Za-z0-9_.~+/=-]{1,2048}", re.ASCII)
LIMIT = 128 * 1024


class Failure(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    connect_ip: str
    username: str = field(repr=False)
    password: str = field(repr=False)
    cert: str
    key: str
    ca: str
    pin: str
    login_fields: tuple
    ignore_tls_verify: bool = False

    @classmethod
    def from_env(cls, args):
        def env(key):
            return os.environ.get("COMET_" + key, "")

        try:
            url = urlsplit(env("URL"))
            host = url.hostname
            port = 443 if url.port is None else url.port
            if (
                url.scheme != "https" or not host or not port
                or url.username is not None or url.password is not None
                or url.path not in ("", "/") or url.query or url.fragment
                or re.fullmatch(r"[A-Za-z0-9.-]+", host) is None
            ):
                raise ValueError
            connect_ip = env("CONNECT_IP")
            if connect_ip:
                connect_ip = str(ipaddress.ip_address(connect_ip))
        except ValueError as e:
            raise Failure("COMET_URL must be a plain HTTPS origin; COMET_CONNECT_IP must be an IP address.") from e

        pin = env("TLS_PIN_SHA256").lower().replace(":", "")
        if pin and not re.fullmatch(r"[0-9a-f]{64}", pin):
            raise Failure("COMET_TLS_PIN_SHA256 must be a SHA-256 certificate fingerprint.")
        ignore = env("IGNORE_TLS_VERIFY").strip().lower()
        if ignore not in ("", "0", "false", "no", "off", "1", "true", "yes", "on"):
            raise Failure("COMET_IGNORE_TLS_VERIFY must be a boolean (true/false or 1/0).")
        ignore_tls_verify = ignore in ("1", "true", "yes", "on")
        if ignore_tls_verify and pin:
            raise Failure("COMET_IGNORE_TLS_VERIFY cannot be combined with COMET_TLS_PIN_SHA256.")
        if pin == FACTORY_PIN:
            raise Failure("The shared factory certificate cannot establish identity.")
        fields = {
            "user-passwd": ("user", "passwd"),
            "username-password": ("username", "password"),
        }.get(env("LOGIN_FIELDS") or "user-passwd")
        if not fields:
            raise Failure("COMET_LOGIN_FIELDS must be user-passwd or username-password.")
        username, password = env("USERNAME"), env("PASSWORD")
        cert, key = args.cert or env("CERT_PATH"), args.key or env("KEY_PATH")
        if not all((username, password, cert, key)):
            raise Failure("Set COMET_USERNAME and COMET_PASSWORD, and provide both cert and key paths.")
        return cls(host, port, connect_ip or host, username, password, cert, key,
                   env("CA_PATH"), pin, fields, ignore_tls_verify)


def unverified_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def client_context(settings):
    if settings.ignore_tls_verify:
        return unverified_context()
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if settings.ca:
        try:
            context.load_verify_locations(cafile=settings.ca)
        except (OSError, ValueError) as e:
            raise Failure("Could not load the configured CA bundle.") from e
    return context


def read_pem(path):
    with open(path, "rb") as stream:
        body = stream.read(LIMIT + 1)
    if not body.strip() or len(body) > LIMIT:
        raise Failure("Certificate and key files must be nonempty and at most 128 KiB each.")
    return body


def leaf_der(pem):
    match = PEM_CERT.search(pem)
    if not match:
        raise Failure("The certificate file does not contain a PEM certificate.")
    return ssl.PEM_cert_to_DER_cert(match.group().decode("ascii"))


def validate_chain(client_context, server_context, name):
    """Perform a local, in-memory TLS handshake before uploading anything."""
    ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(ci, co, server_hostname=name)
    server = server_context.wrap_bio(si, so, server_side=True)
    client_done = server_done = False
    for _ in range(16):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        if co.pending:
            si.write(co.read())
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        if so.pending:
            ci.write(so.read())
        if client_done and server_done:
            return
    raise Failure("Could not complete the local TLS check of the replacement certificate.")


def material(settings, trust):
    try:
        cert, key = read_pem(settings.cert), read_pem(settings.key)
        der = leaf_der(cert)
        if hashlib.sha256(der).hexdigest() == FACTORY_PIN:
            raise Failure("Refusing to install the shared factory certificate.")
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with tempfile.TemporaryDirectory(prefix="comet-pem-") as scratch:
            chain_path, key_path = (Path(scratch, path) for path in ("chain.pem", "key.pem"))
            for path, body in ((chain_path, cert), (key_path, key)):
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(body)
            server.load_cert_chain(chain_path, key_path, password=b"")
        validate_chain(trust, server, settings.host)
        body = json.dumps({"ssl_cert": cert.decode("ascii").strip(), "ssl_key": key.decode("ascii").strip()}).encode()
        return der, body
    except (OSError, ValueError) as e:
        raise Failure("Replacement PEM check failed: verify the key pair, certificate dates, full chain and DNS name.") from e


class Connection(http.client.HTTPSConnection):
    def __init__(self, settings, trust, *, bootstrap=False, timeout=8):
        super().__init__(settings.host, port=settings.port, timeout=timeout, context=trust)
        self.settings = settings
        self.trust = trust
        self.bootstrap = bootstrap
        self.peer = None
        self.verified = False

    def connect(self):
        def handshake(context):
            raw = socket.create_connection((self.settings.connect_ip, self.port), timeout=self.timeout)
            try:
                return context.wrap_socket(raw, server_hostname=self.host)
            except BaseException:
                raw.close()
                raise

        try:
            conn = handshake(self.trust)
            self.verified = not self.settings.ignore_tls_verify
        except ssl.SSLCertVerificationError as e:
            pin = self.settings.pin
            if not self.bootstrap or not pin:
                raise Failure("The device TLS certificate is not trusted for COMET_URL; no credentials sent on this connection.") from e
            conn = handshake(unverified_context())
            fingerprint = hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest()
            if not hmac.compare_digest(fingerprint, pin):
                conn.close()
                raise Failure("The device TLS fingerprint does not match the supplied pin.")
        self.sock = conn
        self.peer = conn.getpeercert(binary_form=True)


def request(settings, trust, path, body, content_type, cookie=None):
    headers = {"Content-Type": content_type, "Accept": "application/json",
               "User-Agent": "glinet-comet-cert/0.1"}
    if cookie is not None:
        headers["Cookie"] = "auth_token=" + cookie
    conn = Connection(settings, trust, bootstrap=True)
    try:
        conn.request("POST", path, body, headers)
        with conn.getresponse() as reply:
            if reply.status != 200:
                raise Failure(f"{path} returned HTTP {reply.status}; no retry sent.")
            data = reply.read(LIMIT + 1)
            cookies = [v for k, v in reply.getheaders() if k.lower() == "set-cookie"]
    finally:
        conn.close()
    if len(data) > LIMIT:
        raise Failure("The device returned a response larger than 128 KiB.")
    try:
        payload = json.loads(data)
    except (ValueError, UnicodeError) as e:
        raise Failure("The device returned an invalid API response.") from e
    if not isinstance(payload, dict) or payload.get("ok") is not True or not isinstance(payload.get("result"), dict):
        raise Failure("The device did not acknowledge the API request.")
    return payload["result"], cookies


def session(settings, trust):
    form = urlencode(dict(zip(settings.login_fields, (settings.username, settings.password)))).encode()
    result, cookies = request(settings, trust, "/api/auth/login", form, "application/x-www-form-urlencoded")
    if result.get("two_step_required") is True:
        raise Failure("The device requires interactive two-step login; no certificate was uploaded.")
    tokens = []
    try:
        for header in cookies:
            parsed = SimpleCookie()
            parsed.load(header)
            if "auth_token" in parsed:
                tokens.append(parsed["auth_token"].value)
    except CookieError as e:
        raise Failure("The device returned an invalid auth cookie.") from e
    if len(tokens) != 1 or not TOKEN.fullmatch(tokens[0]):
        raise Failure("Login did not provide one valid auth_token cookie; no certificate was uploaded.")
    return tokens[0]


def probe(settings, trust, *, bootstrap=False, timeout=8):
    conn = Connection(settings, trust, bootstrap=bootstrap, timeout=timeout)
    try:
        conn.connect()
        return conn.peer, conn.verified
    finally:
        conn.close()


def run(settings):
    trust = client_context(settings)
    expected, body = material(settings, trust)
    current, verified = probe(settings, trust, bootstrap=True)
    if settings.ignore_tls_verify:
        print("Warning: TLS identity verification is disabled. Use only an isolated management link.", file=sys.stderr)
    if (verified or settings.ignore_tls_verify) and current == expected:
        return "The peer is already serving the desired certificate; no write needed."
    token = session(settings, trust)
    try:
        result, _ = request(settings, trust, "/api/system/ssl_cert", body, "application/json", token)
        if result.get("success") is not True:
            raise Failure("The certificate upload was not acknowledged as successful.")
    except (OSError, http.client.HTTPException):
        # nginx can restart before the HTTP response arrives. Verify; never replay.
        pass

    for wait in (0, 1, 2, 3, 4, 5, 6, 7):
        time.sleep(wait)
        try:
            peer, _ = probe(settings, trust, timeout=3)
            if peer == expected:
                if settings.ignore_tls_verify:
                    return "The peer is serving the exact replacement certificate (TLS trust verification disabled)."
                return "Verified: the Comet is serving the replacement certificate over trusted HTTPS."
        except (Failure, OSError):
            pass
    raise Failure("Upload outcome unverified: the replacement certificate was not observed. No upload was repeated.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", metavar="PATH", help="PEM leaf followed by intermediates (or COMET_CERT_PATH)")
    parser.add_argument("--key", metavar="PATH", help="unencrypted PEM private key (or COMET_KEY_PATH)")
    args = parser.parse_args(argv)
    try:
        print(run(Settings.from_env(args)))
    except Failure as e:
        print(str(e), file=sys.stderr)
        return 1
    except (OSError, http.client.HTTPException, ValueError):
        print("Could not complete a secure connection to the Comet; check LAN reachability and configuration.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
