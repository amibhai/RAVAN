"""RAVAN command-line interface.

    ravan list                              # list available heads
    ravan validate --scope engagement.yaml  # validate a scope file
    ravan run <head> --scope engagement.yaml # dispatch a head under scope
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer
import yaml

from ravan.core.engine import Engine
from ravan.core.exceptions import HeadNotFound, ScopeConfigError, ScopeViolation
from ravan.core.loader import HeadLoader
from ravan.core.scope import EngagementScope
from ravan.core.sinks import ConsoleSink, EventSink, JsonlFileSink, MultiSink

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="RAVAN — ten-headed adversary emulation framework (authorized use only).",
)

ScopeOption = Annotated[
    Path,
    typer.Option("--scope", "-s", help="Path to the engagement scope YAML file."),
]


def _load_scope(path: Path) -> EngagementScope:
    try:
        return EngagementScope.from_file(path)
    except ScopeConfigError as exc:
        typer.echo(f"invalid engagement scope: {exc}", err=True)
        raise typer.Exit(2) from exc


def _parse_options(items: list[str]) -> dict[str, Any]:
    """Parse ``--option key=value`` pairs; values are read as YAML scalars, so
    ``ports=top100`` is a str, ``threads=50`` an int, ``operations=[dns,tls]`` a
    list."""
    options: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            typer.echo(f"invalid --option {item!r}; expected key=value", err=True)
            raise typer.Exit(2)
        key, raw = item.split("=", 1)
        try:
            value = yaml.safe_load(raw)
        except yaml.YAMLError:
            value = raw
        options[key.strip()] = value
    return options


@app.command("list")
def list_heads() -> None:
    """List available heads (discovered plugins)."""
    loader = HeadLoader()
    heads = loader.discover()
    if not heads:
        typer.echo("No heads available.")
    else:
        typer.echo(f"Available heads ({len(heads)}):")
        for name in sorted(heads):
            cls = heads[name]
            typer.echo(
                f"  {name:<22} {cls.tactic.value:<22} {cls.technique_id:<8} {cls.technique_name}"
            )
            if cls.description:
                typer.echo(f"      {cls.description}")
    for err in loader.load_errors:
        typer.echo(f"  ! load error: {err}", err=True)


@app.command()
def validate(scope: ScopeOption) -> None:
    """Validate an engagement scope file and print a summary."""
    engagement = _load_scope(scope)
    tactics = ", ".join(sorted(t.value for t in engagement.allowed_tactics))
    start = engagement.window_start.isoformat() if engagement.window_start else "(open)"
    end = engagement.window_end.isoformat() if engagement.window_end else "(open)"
    typer.echo(f"OK: engagement {engagement.name!r} is valid.")
    typer.echo(f"  targets:            {', '.join(engagement.targets)}")
    typer.echo(f"  allowed tactics:    {tactics}")
    if engagement.allowed_techniques:
        typer.echo(f"  allowed techniques: {', '.join(sorted(engagement.allowed_techniques))}")
    if engagement.permissions:
        typer.echo(f"  permissions:        {', '.join(sorted(engagement.permissions))}")
    typer.echo(f"  time window:        {start}  ->  {end}")


@app.command()
def run(
    head: Annotated[str, typer.Argument(help="Name of the head to run, e.g. 'recon'.")],
    scope: ScopeOption,
    log: Annotated[
        Path | None,
        typer.Option("--log", help="JSONL log path (default: engagements/logs/<name>.jsonl)."),
    ] = None,
    no_log: Annotated[
        bool,
        typer.Option("--no-log", help="Do not write a JSONL engagement log file."),
    ] = False,
    option: Annotated[
        list[str] | None,
        typer.Option("--option", "-O", help="Head option override, key=value (repeatable)."),
    ] = None,
) -> None:
    """Validate the scope, then dispatch a head under it."""
    engagement = _load_scope(scope)
    options = _parse_options(option or [])

    sinks: list[EventSink] = [ConsoleSink()]
    file_sink: JsonlFileSink | None = None
    log_path = log or (Path("engagements") / "logs" / f"{engagement.name}.jsonl")
    if not no_log:
        file_sink = JsonlFileSink(log_path)
        sinks.append(file_sink)

    engine = Engine(engagement, sink=MultiSink(*sinks))
    try:
        result = engine.run_head(head, options=options)
    except HeadNotFound as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except ScopeViolation as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(3) from exc
    finally:
        if file_sink is not None:
            file_sink.close()

    typer.echo("")
    typer.echo(f"head {result.head_name!r} finished with status: {result.status}")
    report = result.report
    if report is not None:
        typer.echo(
            f"  events: {report.total_events} "
            f"(success={report.successes}, fail={report.failures}, blocked={report.blocked})"
        )
        if report.summary:
            typer.echo(f"  {report.summary}")
    if not no_log:
        typer.echo(f"  log written to: {log_path}")

    if result.status != "ok":
        raise typer.Exit(1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
