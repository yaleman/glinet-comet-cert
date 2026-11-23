# GL.iNet Comet certificate uploader

Uploads a TLS key pair to a GL.iNet Comet (GL-RM1). The Python 3.9+ client
has no third-party dependencies. The container runs as UID/GID 65532 and
needs a small writable `/tmp` (preferably memory-backed) to check a consistent
copy of the certificate and private key before sending anything.

## Local use

Normally the device must serve an independently trusted HTTPS certificate
for its name. Set the password in your environment via a private prompt or
your normal secret manager, not as a command argument. For zsh:

```sh
export COMET_USERNAME=admin
read -rs 'COMET_PASSWORD?Comet password: '; echo
export COMET_PASSWORD
COMET_URL=https://comet.example.com \
COMET_CONNECT_IP=192.0.2.10 \
python3 uploader.py --cert /path/to/tls.crt --key /path/to/tls.key
unset COMET_PASSWORD
```

| Setting | Purpose |
| --- | --- |
| `COMET_URL` | HTTPS origin. The DNS name is used for TLS SNI/verification and the HTTP Host header. |
| `COMET_CONNECT_IP` | Optional direct IP. Bypasses DNS without changing the TLS name. |
| `COMET_USERNAME`, `COMET_PASSWORD` | Required device credentials. |
| `COMET_CERT_PATH`, `COMET_KEY_PATH` | Instead of flags. Provide PEM leaf plus intermediate chain and its unencrypted PEM private key. |
| `COMET_CA_PATH` | Optional CA bundle for a private issuer, in addition to the system roots. |
| `COMET_IGNORE_TLS_VERIFY` | Default false. Set to `true` or `1` to disable CA and hostname verification, including for factory, self-signed, or private-CA certificates. Cannot be combined with a bootstrap pin. |
| `COMET_TLS_PIN_SHA256` | Optional fallback for a device-unique bootstrap certificate with a fingerprint verified independently. Normal CA and DNS validation still takes precedence; after upload, normal validation is mandatory. Never pin a shared/default certificate. |
| `COMET_LOGIN_FIELDS` | Default `user-passwd` follows [GL.iNet upstream](https://github.com/gl-inet/glkvm/blob/main/kvmd/apps/kvmd/api/auth.py). Set `username-password` only if that firmware sends those names. There is no automatic retry with different fields. |

### Untrusted certificates

Set `COMET_IGNORE_TLS_VERIFY=true` for an isolated management connection when
you deliberately want to accept the device's untrusted certificate. This still
uses HTTPS, but an impostor that intercepts the connection could receive the
password and replacement private key. Prefer `COMET_CA_PATH` for a private CA,
or leave verification on after installing a certificate from a trusted CA.

Before sending anything the uploader validates the replacement key pair, and
with verification enabled it also checks the full replacement chain and DNS
name locally. If the desired leaf is already served, there is no write.
Otherwise it logs in once, uses only the returned `auth_token` cookie, and
POSTs the PEM pair as JSON. It checks the exact new leaf on a fresh connection
while nginx restarts, without replaying the upload. With verification disabled,
a matching leaf is not independent authentication of the device. The uploader
never asks the device to return the private key. Firmware requiring interactive
two-step authentication is not supported.

## Kubernetes

Mount the certificate issuer's TLS Secret read-only, and set
`COMET_CERT_PATH` and `COMET_KEY_PATH` to its PEM files (for example,
`/tls/tls.crt` and `/tls/tls.key`). Inject `COMET_USERNAME` and
`COMET_PASSWORD` from a separate Secret. Don't commit secrets or keys.

In a CronJob, pin the image by digest, mount a small writable `/tmp`, and
allow egress only to the device's management address on TCP 443. Keep TLS
verification enabled for unattended runs. If you use a private CA, mount
its CA bundle and set `COMET_CA_PATH`. If you use public ACME, the certificate
name may appear in public Certificate Transparency logs.

```sh
python3 -m unittest -v
docker build -t glinet-comet-cert:local .
```

## Image publishing

The [GitHub Actions workflow](.github/workflows/image.yml) runs the TLS
integration tests before calling [Docker's official reusable builder](https://github.com/docker/github-builder).
Pushes to `main` publish an AMD64/ARM64 index to
`ghcr.io/yaleman/glinet-comet-cert` with `latest` and a full commit SHA tag.
Use the published index digest in Kubernetes rather than `latest`.
The workflow uses GitHub's built-in job token; it does not need appliance
credentials or a separately stored registry token.
