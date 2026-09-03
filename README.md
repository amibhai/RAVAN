# RAVAN

```
     /^\ /^\ /^\ /^\ /^\ /^\ /^\ /^\ /^\ /^\
    (o_o|o_o|o_o|o_o|o_o|o_o|o_o|o_o|o_o|o_o)   ← ten heads
     `"""""""""""""""""""""""""""""""""""""`
                     \__|__/
    ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗
    ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║
    ██████╔╝███████║██║   ██║███████║██╔██╗ ██║
    ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║██║╚██╗██║
    ██║  ██║██║  ██║ ╚████╔╝ ██║  ██║██║ ╚████║
    ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝
        ten heads · one engine · ten ATT&CK tactics
```

**A ten-headed adversary emulation framework — one engine, ten attack tactics, closing the loop from attack to detection.**

> Named for the ten-headed king of Indian myth — mastery across many domains, and the illusion (maya) that made him formidable. RAVAN emulates ten distinct MITRE ATT&CK tactic categories through a single modular engine, so a defender can measure — not assume — what their detections actually catch.

---

## What RAVAN actually does

RAVAN is a **purple-team framework**: it runs realistic, configurable attack technique emulations across ten MITRE ATT&CK tactic categories (the "ten heads"), logs everything it does in a structured, machine-readable format, and feeds that log into a detection-validation layer (built on top of `mirrorlab`) that checks which techniques your SIEM/Sigma rules actually caught.

In short: **it consolidates the offensive tooling already scattered across this account — `SHIV-reconnaissance_toolkit`, `spoofed`, `credential-attacks-toolkit`, `wordsmith`, `wifi_down` — into a single coherent framework**, and adds the missing piece: automated proof of whether your defenses noticed.

It is built strictly for **authorized environments**: your own lab, a CTF range, or an engagement with signed scope. RAVAN enforces a scope/target allow-list at the engine level — it will not run against a target that isn't explicitly declared in the engagement config.

### The ten heads (ATT&CK tactic modules)

| # | Head (`name`) | ATT&CK Tactic | Draws from existing work | Status |
|---|------|---------------|---------------------------|--------|
| 1 | Reconnaissance (`recon`) | Reconnaissance | `SHIV-reconnaissance_toolkit` | ✅ done |
| 2 | Resource Development (`resdev`) | Resource Development | `wordsmith` (targeted wordlist generation) | ✅ done |
| 3 | Initial Access (`initaccess`) | Initial Access | new | ✅ done |
| 4 | Execution (`execution`) | Execution | new | ✅ done |
| 5 | Persistence (`persistence`) | Persistence | new | ✅ done |
| 6 | Credential Access (`credaccess`) | Credential Access | `credential-attacks-toolkit` | ✅ done |
| 7 | Lateral Movement (`lateral`) | Lateral Movement | credential reuse (T1021/T1078) | ✅ done |
| 8 | Collection | Collection | new | planned |
| 9 | Exfiltration | Exfiltration | new, metadata-resistant patterns informed by `Parda` | planned |
| 10 | Command & Control | Command and Control | new | planned |

Each head is a self-contained plugin implementing a shared interface (`run()`, `cleanup()`, `report()`), so heads can be added, removed, or swapped without touching the core engine.

### The closed loop

```
RAVAN (attacks, logs structured technique metadata)
        │
        ▼
Structured engagement log (JSON, ATT&CK-tagged)
        │
        ▼
mirrorlab (replays against your Sigma ruleset)
        │
        ▼
Coverage report: which techniques were detected, which were silent
```

This is the piece most adversary-emulation student projects skip — running attacks without ever closing the loop on whether detection worked. RAVAN's differentiator is that the loop is closed by default, not a manual afterthought.

---

## Install

```bash
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"         # add the optional SSH backend: pip install -e ".[dev,ssh]"
```

The engine and the currently-implemented heads run on **pure Python stdlib** — no
root, no scapy, no external binaries — so they behave identically on Windows,
Linux, and macOS. The only optional dependency so far is `paramiko` (SSH).

## Quick start

```bash
ravan list                                        # list discovered heads
ravan validate --scope engagements/example.yaml   # validate an engagement scope

# Reconnaissance — TCP scan + service/CVE/DNS/TLS/HTTP, ATT&CK-tagged JSONL
ravan run recon --scope engagements/example.yaml -O ports=top100

# Resource Development — target-tailored wordlist + hashcat rules
ravan run resdev --scope engagements/example.yaml -O domain=lab.local -O company="Acme Corp"

# Credential Access — lockout-aware brute force
ravan run credaccess --scope engagements/example.yaml -O protocol=ssh -O mode=defaults

# Lateral Movement — validate credential reuse across in-scope hosts
ravan run lateral --scope engagements/example.yaml \
  -O 'protocols=[ssh]' -O 'credentials=[admin:Password1!]'

# Execution — benign command execution via native interpreters (needs localhost in scope)
ravan run execution --scope engagements/example.yaml

# Persistence — benign, self-cleaning autostart artifacts
ravan run persistence --scope engagements/example.yaml

# Initial Access — benign phishing-lure generation for detection testing
ravan run initaccess --scope engagements/example.yaml -O 'operations=[phishing-lure]'
```

Every action is scope-gated at the engine level and emits a structured
`TechniqueEvent` to a JSONL engagement log. Per-head settings live under the
engagement's `heads:` block and can be overridden with `-O key=value`.

---

## Approach

The build is deliberately incremental — one head fully working (engine, logging, tests, docs) before the next begins, rather than ten shallow stubs at once. This keeps the framework demoable at every stage and avoids a half-finished sprawl.

**Design principles:**
- **Config over code** — engagements are defined in a YAML scope file (targets, allowed techniques, time window). The engine refuses to act outside it.
- **Structured logging first** — every module emits a common `TechniqueEvent` schema (ATT&CK ID, timestamp, target, outcome) before it emits anything else. Detection validation depends on this being consistent from head #1 onward.
- **Plugin isolation** — a bug or crash in one head cannot take down the engine or another head.
- **Authorized-use enforcement is structural, not a comment** — the scope allow-list is checked in code on every action, not just documented in the README.

---

## Phases

### Phase 0 — Foundation ✅
- Repo scaffold, plugin interface (`BaseHead` abstract class), `TechniqueEvent` schema
- Engagement scope config (YAML) + enforcement layer
- CLI skeleton (`ravan run <head> --scope engagement.yaml`)
- CI: lint, type-check, basic scope-enforcement tests

### Phase 1 — Recon + Resource Development (Heads 1–2) ✅
- Port and refactor `SHIV-reconnaissance_toolkit` logic into the plugin interface
- Port `wordsmith` as the Resource Development head
- First end-to-end structured log output validated

### Phase 2 — Credential Access + Lateral Movement (Heads 6–7) ✅
- Port `credential-attacks-toolkit` into a shared credential library + `credaccess` head
- `lateral` head validates credential reuse across in-scope hosts (T1021/T1078)

### Phase 3 — Execution, Persistence, Initial Access (Heads 3–5) ✅
- Lab-safe atomic emulation (Atomic Red Team model) on a shared `ravan.emulation` library
- `execution` (T1059/T1047), `persistence` (T1547/T1053/T1543, self-cleaning), `initaccess` (T1078 foothold + T1566 benign lures)

### Phase 4 — Collection, Exfiltration, C2 (Heads 8–10)
- Exfiltration module informed by `Parda`'s metadata-resistance research
- Minimal C2 beacon for engagement realism, not a full C2 framework

### Phase 5 — Detection validation integration
- Wire engagement logs into `mirrorlab`
- Generate the coverage report: technique attempted → detected (yes/no) → rule that fired

### Phase 6 — Reporting + polish
- HTML/Markdown engagement report generator (techniques run, MITRE Navigator heatmap export, detection gaps)
- Full README, architecture diagram, demo GIF/recording
- Tag v1.0

---

## Tech stack

- **Python** — plugin engine, CLI, most heads (consistent with existing repos)
- **Rust** (optional, later) — for any performance-sensitive head (e.g., high-volume packet handling), consistent with `Chiral`/`Parda`
- **YAML** — engagement scope config
- **MITRE ATT&CK Navigator** — coverage heatmap export

## Legal / Ethical use

RAVAN is built for authorized security testing only — your own infrastructure, a lab environment, or an engagement with explicit written scope. The engine enforces a target allow-list; running against out-of-scope targets is a configuration error the tool refuses, not just a policy note.

## Status

Active development. **Phases 0–3 complete** — the engine with structural scope
enforcement, plus seven heads: Reconnaissance, Resource Development, Credential
Access, Lateral Movement, Execution, Persistence, and Initial Access. Phase 4
(Collection, Exfiltration, C2) is next. See [CHANGELOG.md](CHANGELOG.md) for the
full history.
