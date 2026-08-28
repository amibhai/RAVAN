"""TLS / certificate inspection (pure stdlib ``ssl``).

A trusted, hostname-valid endpoint yields full certificate details (subject,
issuer, SANs, validity window). A self-signed / untrusted endpoint — common in
labs — still yields the negotiated TLS version, cipher, and a SHA-256
fingerprint of the presented certificate. Deep DER field extraction for
untrusted certs is a documented optional (``cryptography``) upgrade.
"""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
from typing import Any


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def probe_tls(
    host: str,
    port: int,
    *,
    timeout: float = 4.0,
    server_hostname: str | None = None,
) -> dict[str, Any]:
    """Inspect the TLS service at ``host:port``. Returns ``{}`` if no TLS
    handshake completes."""
    sni = None if _is_ip(host) else (server_hostname or host)

    # Only attempt a verifying handshake for hostnames — IP endpoints almost
    # never carry a hostname-valid cert, so go straight to the enumerating path.
    if sni is not None:
        verified = _handshake(host, port, timeout, sni, verify=True)
        if verified is not None:
            return verified

    return _handshake(host, port, timeout, sni, verify=False) or {}


def _handshake(
    host: str, port: int, timeout: float, sni: str | None, *, verify: bool
) -> dict[str, Any] | None:
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                result: dict[str, Any] = {"verified": verify}
                version = tls.version()
                if version:
                    result["tls_version"] = version
                cipher = tls.cipher()
                if cipher:
                    result["cipher"] = cipher[0]
                der = tls.getpeercert(binary_form=True)
                if der:
                    result["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
                if verify:
                    _fill_cert_fields(result, tls.getpeercert() or {})
                return result
    except ssl.SSLCertVerificationError:
        return None  # untrusted cert — caller retries unverified
    except (OSError, ssl.SSLError):
        return None


def _fill_cert_fields(result: dict[str, Any], cert: dict[str, Any]) -> None:
    subject = _flatten_name(cert.get("subject", ()))
    issuer = _flatten_name(cert.get("issuer", ()))
    if subject.get("commonName"):
        result["subject_cn"] = subject["commonName"]
    if issuer.get("commonName"):
        result["issuer_cn"] = issuer["commonName"]
    if cert.get("notBefore"):
        result["not_before"] = cert["notBefore"]
    if cert.get("notAfter"):
        result["not_after"] = cert["notAfter"]
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    if sans:
        result["subject_alt_names"] = sans


def _flatten_name(name: Any) -> dict[str, str]:
    flat: dict[str, str] = {}
    for rdn in name:
        for key, value in rdn:
            flat[key] = value
    return flat


__all__ = ["probe_tls"]
