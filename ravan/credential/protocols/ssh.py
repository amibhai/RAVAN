"""SSH credential attacker (paramiko — optional dependency).

The only non-stdlib protocol. If paramiko is not installed the attacker reports
``UNSUPPORTED`` and the engine skips it, so the rest of the suite still runs.
"""

from __future__ import annotations

import contextlib
import importlib.util
import time
from typing import Any

from ravan.credential.attempt import AttemptResult, AttemptStatus
from ravan.credential.base import ProtocolAttacker

_HAS_PARAMIKO = importlib.util.find_spec("paramiko") is not None


class SSHAttacker(ProtocolAttacker):
    protocol = "ssh"
    default_port = 22
    optional = True

    @classmethod
    def available(cls) -> bool:
        return _HAS_PARAMIKO

    def authenticate(
        self, host: str, port: int, username: str, password: str, timeout: float
    ) -> AttemptResult:
        if not _HAS_PARAMIKO:
            return self._result(
                host,
                port,
                username,
                password,
                AttemptStatus.UNSUPPORTED,
                error="paramiko not installed (pip install 'ravan[ssh]')",
            )
        import paramiko

        started = time.monotonic()
        client: Any = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            transport = client.get_transport()
            banner = transport.remote_version if transport is not None else None
            return self._result(
                host,
                port,
                username,
                password,
                AttemptStatus.SUCCESS,
                banner=banner,
                response_time=time.monotonic() - started,
            )
        except paramiko.AuthenticationException as exc:
            return self._result(
                host, port, username, password, AttemptStatus.FAILED, error=str(exc)
            )
        except paramiko.SSHException as exc:
            return self._result(host, port, username, password, AttemptStatus.ERROR, error=str(exc))
        except TimeoutError as exc:
            return self._result(
                host, port, username, password, AttemptStatus.TIMEOUT, error=str(exc)
            )
        except OSError as exc:
            return self._result(host, port, username, password, AttemptStatus.ERROR, error=str(exc))
        finally:
            with contextlib.suppress(OSError):
                client.close()


__all__ = ["SSHAttacker"]
