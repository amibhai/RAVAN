# Changelog

All notable changes to RAVAN are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/); RAVAN is pre-1.0 and not yet
tagged, so changes are grouped by build phase under **Unreleased**.

## [Unreleased]

### Phase 3 — Execution, Persistence, Initial Access (2026-08-30)

New lab-safe emulation modules (no existing tool to port), built on the Atomic
Red Team model — benign, ATT&CK-tagged atomics with idempotent cleanup — wrapped
in RAVAN's scope-enforced, structured-logging engine. Pure stdlib; cross-platform
(Windows/Linux/macOS); zero new dependencies.

**Added**
- Shared emulation library `ravan.emulation`: OS detection, a no-shell benign
  command runner that captures process telemetry (pid, exit code, output), canary
  markers, an `Atomic` interface with idempotent `revert()`, and a `LocalAtomicHead`
  base that authorizes local emulation against the engagement scope.
- **Execution head** (`execution`, ATT&CK T1059/T1047): benign command execution
  via native interpreters — Python (T1059.006), PowerShell (T1059.001), cmd
  (T1059.003), Unix shell (T1059.004), and WMI (T1047) — generating real
  process-creation telemetry. Requires the `execute-emulation` permission.
- **Persistence head** (`persistence`, ATT&CK T1547/T1053/T1543/T1546): user-level,
  benign autostart artifacts — registry Run key, startup file, scheduled task
  (Windows); systemd user service, shell profile (Linux); launch agent (macOS) —
  each reverted idempotently after the run (or kept via `keep: true`). Requires the
  `persistence-emulation` permission.
- **Initial Access head** (`initaccess`, ATT&CK T1078/T1566): valid-account foothold
  validation via the credential library (T1078) and benign phishing-lure generation
  — macro/HTA/script/HTML artifacts for testing mail/endpoint controls, no delivery
  (T1566). Requires the `initial-access` permission.
- Local-emulation heads authorize `localhost`/`127.0.0.1`/hostname against the
  engagement scope, so the operator explicitly authorizes acting on the host.

### Phase 2 — Credential Access + Lateral Movement (2026-08-29)

Ported `credential-attacks-toolkit` into a shared credential library and two new
heads. Dependency stance: pure stdlib for eight protocols; SSH via an optional
`paramiko` extra that degrades gracefully when absent.

**Added**
- Shared credential library `ravan.credential`:
  - `ProtocolAttacker` interface + nine attackers — FTP, HTTP Basic, HTTP Form
    (CSRF/cookie-aware), SMTP, POP3, IMAP, Telnet, Redis (all stdlib), and SSH
    (paramiko, `available()`-gated).
  - `LockoutDetector` — sliding-window per-user failure tracking; the engine
    skips accounts nearing a real lockout.
  - `BruteEngine` — bounded concurrency, stop-on-success, lockout-safe.
  - `CredentialSpec` — five attack modes: dictionary, spray (lockout-safe
    order), smart (username/company/year patterns), defaults (182 vendor default
    pairs), combo (credential stuffing).
- **Credential Access head** (`credaccess`, ATT&CK T1110 Brute Force):
  guessing/smart/defaults → T1110.001, spray → T1110.003, combo → T1110.004;
  emits found-credential, lockout (BLOCKED), and failed-campaign events. Requires
  the `credential-attack` scope permission.
- **Lateral Movement head** (`lateral`, ATT&CK T1021 / T1078): validates
  credential reuse across in-scope hosts (expands CIDRs), tagging remote-service
  access (SSH → T1021.004) enabled by valid accounts. Requires the
  `lateral-movement` scope permission.
- `paramiko` as an optional dependency extra (`pip install 'ravan[ssh]'`).

### Phase 1 — Reconnaissance + Resource Development (2026-08-28)

Ported `SHIV-reconnaissance_toolkit` and `wordsmith`. Pure stdlib, no root,
cross-platform — a deliberate portability edge over scapy/nmap-based tooling.

**Added**
- **Reconnaissance head** (`recon`): TCP-connect host discovery and port scan
  (T1595.001), service/version detection (T1592.002), banner-to-CVE matching
  against a 55-entry database (T1595.002), DNS enumeration with a self-contained
  UDP resolver + subdomain brute-force (T1590.002), reverse DNS (T1590.005), TLS
  certificate inspection (T1596.003), and HTTP fingerprinting.
- **Resource Development head** (`resdev`, ATT&CK T1587 Develop Capabilities):
  13-strategy mutation engine, shared likelihood scoring, a memory-bounded top-K
  streaming accumulator, tiered hashcat-rule export, and inline password-policy
  filtering.
- Per-head configuration via the engagement `heads:` block and CLI
  `--option key=value` overrides, surfaced through `RunContext.options`.

### Phase 0 — Foundation (2026-08-27)

**Added**
- Plugin engine with structural, engine-level scope enforcement (tactic,
  technique, permission, time window, per-target) and plugin isolation.
- `BaseHead` plugin contract (`run` / `report` / `cleanup` + ATT&CK metadata)
  and `RunContext`.
- `TechniqueEvent` structured-logging schema (`Tactic`, `Outcome`, timestamped,
  ATT&CK-tagged) and event sinks (in-memory, JSONL, console).
- `EngagementScope` YAML loader (targets incl. CIDR, allowed tactics/techniques,
  permissions, time window) and the plugin loader.
- Typer CLI (`ravan list` / `validate` / `run`) and GitHub Actions CI running
  ruff + mypy + pytest on Python 3.11–3.13.
