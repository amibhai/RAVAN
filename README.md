# RAVAN

**A ten-headed adversary emulation framework — one engine, ten attack tactics, closing the loop from attack to detection.**

> Named for the ten-headed king of Indian myth — mastery across many domains, and the illusion (maya) that made him formidable. RAVAN emulates ten distinct MITRE ATT&CK tactic categories through a single modular engine, so a defender can measure — not assume — what their detections actually catch.

---

## What RAVAN actually does

RAVAN is a **purple-team framework**: it runs realistic, configurable attack technique emulations across ten MITRE ATT&CK tactic categories (the "ten heads"), logs everything it does in a structured, machine-readable format, and feeds that log into a detection-validation layer (built on top of `mirrorlab`) that checks which techniques your SIEM/Sigma rules actually caught.

In short: **it consolidates the offensive tooling already scattered across this account — `SHIV-reconnaissance_toolkit`, `spoofed`, `credential-attacks-toolkit`, `wordsmith`, `wifi_down` — into a single coherent framework**, and adds the missing piece: automated proof of whether your defenses noticed.

It is built strictly for **authorized environments**: your own lab, a CTF range, or an engagement with signed scope. RAVAN enforces a scope/target allow-list at the engine level — it will not run against a target that isn't explicitly declared in the engagement config.

### The ten heads (ATT&CK tactic modules)

| # | Head | ATT&CK Tactic | Draws from existing work |
|---|------|---------------|---------------------------|
| 1 | Reconnaissance | Reconnaissance | `SHIV-reconnaissance_toolkit` |
| 2 | Resource Development | Resource Development | `wordsmith` (targeted wordlist generation) |
| 3 | Initial Access | Initial Access | new |
| 4 | Execution | Execution | new |
| 5 | Persistence | Persistence | new |
| 6 | Credential Access | Credential Access | `credential-attacks-toolkit` |
| 7 | Lateral Movement | Lateral Movement | `spoofed` (LLMNR/NBT-NS, interception) |
| 8 | Collection | Collection | new |
| 9 | Exfiltration | Exfiltration | new, metadata-resistant patterns informed by `Parda` |
| 10 | Command & Control | Command and Control | new |

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

## Approach

The build is deliberately incremental — one head fully working (engine, logging, tests, docs) before the next begins, rather than ten shallow stubs at once. This keeps the framework demoable at every stage and avoids a half-finished sprawl.

**Design principles:**
- **Config over code** — engagements are defined in a YAML scope file (targets, allowed techniques, time window). The engine refuses to act outside it.
- **Structured logging first** — every module emits a common `TechniqueEvent` schema (ATT&CK ID, timestamp, target, outcome) before it emits anything else. Detection validation depends on this being consistent from head #1 onward.
- **Plugin isolation** — a bug or crash in one head cannot take down the engine or another head.
- **Authorized-use enforcement is structural, not a comment** — the scope allow-list is checked in code on every action, not just documented in the README.

---

## Phases

### Phase 0 — Foundation
- Repo scaffold, plugin interface (`BaseHead` abstract class), `TechniqueEvent` schema
- Engagement scope config (YAML) + enforcement layer
- CLI skeleton (`ravan run <head> --scope engagement.yaml`)
- CI: lint, type-check, basic scope-enforcement tests

### Phase 1 — Recon + Resource Development (Heads 1–2)
- Port and refactor `SHIV-reconnaissance_toolkit` logic into the plugin interface
- Port `wordsmith` as the Resource Development head
- First end-to-end structured log output validated

### Phase 2 — Credential Access + Lateral Movement (Heads 6–7)
- Port `credential-attacks-toolkit` and `spoofed` into plugin form
- These are your most mature existing modules — fastest phase to complete

### Phase 3 — Execution, Persistence, Initial Access (Heads 3–5)
- New modules, built to the same interface
- Kept intentionally simple/lab-safe (e.g., scheduled-task persistence, not novel exploit development)

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

🚧 Early development — Phase 0 in progress.
