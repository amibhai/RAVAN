"""Reconnaissance head (Head #1) — a real, cross-platform, no-root recon engine.

Ports SHIV recon-toolkit's active-scanning capabilities into RAVAN's plugin
interface. Each operation is mapped to a specific MITRE ATT&CK Reconnaissance
(sub-)technique and emits scope-gated, structured events — so a defender can
validate which of these recon actions their sensors actually caught.

Operations (all pure stdlib, TCP-connect based, no privileges required):
  discover  T1595.001  host discovery across an IP block / CIDR
  portscan  T1595.001  TCP connect port scan of a host
  services  T1592.002  service / version / banner identification
  vuln      T1595.002  banner-to-CVE matching (passive comparison)
  dns       T1590.002  DNS record enumeration + subdomain brute-force
  (dns/ip)  T1590.005  reverse-DNS / IP-address mapping
  tls       T1596.003  TLS certificate inspection
  http      T1592.002  HTTP service + security-header fingerprinting
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ravan.core.base import BaseHead, RunContext
from ravan.core.exceptions import ScopeViolation
from ravan.heads.recon import cve, dnsenum, httpprobe, tlsprobe
from ravan.heads.recon.ports import (
    HTTP_PORTS,
    TLS_PORTS,
    classify_target,
    expand_hosts,
    parse_port_spec,
)
from ravan.heads.recon.scanner import connect_scan, detect_service, host_is_up
from ravan.schemas.events import HeadReport, Outcome, Tactic

# ATT&CK technique reference per operation: (technique_id, technique_name).
TechniqueRef = tuple[str, str]
OP_DISCOVER: TechniqueRef = ("T1595.001", "Active Scanning: Scanning IP Blocks")
OP_PORTSCAN: TechniqueRef = ("T1595.001", "Active Scanning: Scanning IP Blocks")
OP_SERVICE: TechniqueRef = ("T1592.002", "Gather Victim Host Information: Software")
OP_VULN: TechniqueRef = ("T1595.002", "Active Scanning: Vulnerability Scanning")
OP_DNS: TechniqueRef = ("T1590.002", "Gather Victim Network Information: DNS")
OP_REVDNS: TechniqueRef = ("T1590.005", "Gather Victim Network Information: IP Addresses")
OP_TLS: TechniqueRef = ("T1596.003", "Search Open Technical Databases: Digital Certificates")
OP_HTTP: TechniqueRef = ("T1592.002", "Gather Victim Host Information: Software")

ALL_OPS: tuple[str, ...] = ("discover", "portscan", "services", "vuln", "dns", "tls", "http")
HOST_SCAN_OPS: frozenset[str] = frozenset({"portscan", "services", "vuln", "tls", "http"})
DISCOVERY_PORTS: list[int] = [80, 443, 22, 445, 3389, 139, 53, 8080, 3306, 21, 25, 23, 8443]


@dataclass
class ReconConfig:
    operations: frozenset[str]
    ports: str
    timeout: float
    workers: int
    max_hosts: int
    dns_subdomains: bool
    dns_resolver: str | None


class ReconHead(BaseHead):
    head_name = "recon"
    technique_id = "T1595"
    technique_name = "Active Scanning"
    tactic = Tactic.RECONNAISSANCE
    required_permissions = ("active-scan",)
    description = "Reconnaissance: no-root TCP discovery, port/service scan, DNS, TLS, HTTP, CVE."

    def __init__(self) -> None:
        self._stats: dict[str, int] = {
            "targets": 0,
            "hosts_up": 0,
            "hosts_scanned": 0,
            "open_ports": 0,
            "services": 0,
            "cves": 0,
            "subdomains": 0,
        }

    # -- lifecycle ------------------------------------------------------------

    def run(self, context: RunContext) -> None:
        cfg = self._build_config(context)
        for target in context.targets:
            self._stats["targets"] += 1
            try:
                self._process_target(context, target, cfg)
            except ScopeViolation:
                # authorize() already logged a BLOCKED event; move to next target.
                continue
            except Exception as exc:  # isolate one target's failure
                context.record(
                    target=target,
                    outcome=Outcome.FAIL,
                    details={"reason": "recon failed for target", "error": repr(exc)},
                )

    def report(self) -> HeadReport:
        s = self._stats
        summary = (
            f"recon: {s['targets']} target(s), {s['hosts_up']} host(s) up, "
            f"{s['hosts_scanned']} scanned, {s['open_ports']} open port(s), "
            f"{s['services']} service(s), {s['cves']} CVE match(es), "
            f"{s['subdomains']} subdomain(s)"
        )
        report = self.build_report(summary=summary)
        return report

    def cleanup(self) -> None:
        for key in self._stats:
            self._stats[key] = 0

    # -- configuration --------------------------------------------------------

    def _build_config(self, context: RunContext) -> ReconConfig:
        ops_raw = context.option("operations")
        if isinstance(ops_raw, str):
            ops = frozenset(o.strip() for o in ops_raw.split(",") if o.strip())
        elif isinstance(ops_raw, (list, tuple)):
            ops = frozenset(str(o).strip() for o in ops_raw)
        else:
            ops = frozenset(ALL_OPS)
        resolver = context.option("dns_resolver")
        return ReconConfig(
            operations=ops,
            ports=str(context.option("ports", "top100")),
            timeout=float(context.option("timeout", 1.5)),
            workers=int(context.option("workers", 100)),
            max_hosts=int(context.option("max_hosts", 256)),
            dns_subdomains=bool(context.option("dns_subdomains", True)),
            dns_resolver=str(resolver) if resolver else None,
        )

    # -- per-target dispatch --------------------------------------------------

    def _process_target(self, context: RunContext, target: str, cfg: ReconConfig) -> None:
        context.authorize(target)
        kind = classify_target(target)
        if kind == "cidr":
            self._process_cidr(context, target, cfg)
        elif kind == "ip":
            if "dns" in cfg.operations:
                self._op_reverse_dns(context, target, cfg)
            self._scan_host(context, target, cfg)
        else:  # hostname / domain
            if "dns" in cfg.operations:
                self._op_dns_host(context, target, cfg)
            self._scan_host(context, target, cfg)

    def _process_cidr(self, context: RunContext, cidr: str, cfg: ReconConfig) -> None:
        hosts = expand_hosts(cidr, cfg.max_hosts)
        for host in hosts:
            context.authorize(host)
            if "discover" in cfg.operations:
                responsive = host_is_up(host, probe_ports=DISCOVERY_PORTS, timeout=cfg.timeout)
                if responsive is None:
                    continue  # host silent — no event, keep the log signal high
                self._stats["hosts_up"] += 1
                self._emit(
                    context, OP_DISCOVER, host,
                    Outcome.SUCCESS, {"responsive_port": responsive},
                )
            self._scan_host(context, host, cfg)

    # -- host scanning --------------------------------------------------------

    def _scan_host(self, context: RunContext, host: str, cfg: ReconConfig) -> None:
        applicable = cfg.operations & HOST_SCAN_OPS
        if not applicable:
            return
        ports = parse_port_spec(cfg.ports)
        open_ports = connect_scan(host, ports, timeout=cfg.timeout, workers=cfg.workers)
        self._stats["hosts_scanned"] += 1
        self._stats["open_ports"] += len(open_ports)

        if "portscan" in applicable:
            self._emit(
                context, OP_PORTSCAN, host, Outcome.SUCCESS,
                {"ports_scanned": len(ports), "open_ports": [p.port for p in open_ports]},
            )

        if applicable & {"services", "vuln"}:
            for result in open_ports:
                svc, version, banner = detect_service(host, result.port, timeout=cfg.timeout)
                result.service, result.version, result.banner = svc, version, banner
                if "services" in applicable and (svc or banner):
                    self._stats["services"] += 1
                    self._emit(
                        context, OP_SERVICE, f"{host}:{result.port}",
                        Outcome.SUCCESS, result.to_details(),
                    )
                if "vuln" in applicable and banner:
                    for entry in cve.match_cves(banner, service=svc):
                        self._stats["cves"] += 1
                        self._emit(
                            context, OP_VULN, f"{host}:{result.port}",
                            Outcome.SUCCESS, cve.to_details(entry),
                        )

        if "tls" in applicable:
            for result in open_ports:
                if result.port in TLS_PORTS:
                    info = tlsprobe.probe_tls(host, result.port, timeout=cfg.timeout + 1.0)
                    if info:
                        self._emit(context, OP_TLS, f"{host}:{result.port}", Outcome.SUCCESS, info)

        if "http" in applicable:
            for result in open_ports:
                if result.port in HTTP_PORTS or result.port in TLS_PORTS:
                    info = httpprobe.probe_http(
                        host,
                        result.port,
                        use_tls=result.port in TLS_PORTS,
                        timeout=cfg.timeout + 1.0,
                    )
                    if info:
                        self._emit(context, OP_HTTP, f"{host}:{result.port}", Outcome.SUCCESS, info)

    # -- DNS ------------------------------------------------------------------

    def _op_dns_host(self, context: RunContext, domain: str, cfg: ReconConfig) -> None:
        addresses = dnsenum.resolve_host(domain, cfg.timeout + 1.0)
        if addresses:
            self._emit(
                context, OP_DNS, domain, Outcome.SUCCESS,
                {"record": "A/AAAA", "addresses": addresses},
            )
        else:
            self._emit(context, OP_DNS, domain, Outcome.FAIL, {"reason": "no A/AAAA record"})

        resolver = cfg.dns_resolver or dnsenum.system_resolver()
        if resolver:
            records = dnsenum.enumerate_records(domain, resolver, timeout=cfg.timeout + 1.0)
            if records:
                self._emit(
                    context, OP_DNS, domain, Outcome.SUCCESS,
                    {"resolver": resolver, "records": records},
                )

        if cfg.dns_subdomains:
            words = dnsenum.load_subdomain_wordlist()
            found = dnsenum.brute_subdomains(
                domain, words, timeout=cfg.timeout, workers=cfg.workers
            )
            self._stats["subdomains"] += len(found)
            for fqdn, ips in found:
                self._emit(
                    context, OP_DNS, fqdn, Outcome.SUCCESS,
                    {"discovered_subdomain": True, "addresses": ips},
                )

    def _op_reverse_dns(self, context: RunContext, ip: str, cfg: ReconConfig) -> None:
        name = dnsenum.reverse_dns(ip, cfg.timeout + 1.0)
        if name:
            self._emit(context, OP_REVDNS, ip, Outcome.SUCCESS, {"ptr": name})

    # -- emission -------------------------------------------------------------

    def _emit(
        self,
        context: RunContext,
        ref: TechniqueRef,
        target: str,
        outcome: Outcome,
        details: dict[str, Any],
    ) -> None:
        attack_id, technique_name = ref
        context.record(
            target=target,
            outcome=outcome,
            details=details,
            attack_id=attack_id,
            technique_name=technique_name,
        )
