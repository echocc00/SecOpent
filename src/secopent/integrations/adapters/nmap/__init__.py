"""nmap adapter: service/OS scan + NSE vuln scripts (§8.2, network domain).

nmap is GPL-licensed. Per §8.2 of the main design, GPL tools are invoked as
independent subprocesses (never embedded as a library in the SecOpent
process). The manifest carries `license="GPL"` and an
`independent_process` marker in `permissions` so the runner / profile
selector can enforce the subprocess-only boundary at the policy layer.

Parser input: nmap XML output (`-sV -sC -oX /out/nmap.xml`). Each
`<host>` element with `<ports>` yields one Observation per open `<port>`
whose `asset_identity` is `ip:port`. `<service>` attributes (name,
product, version) are preserved in `raw.service`. NSE `<script>` elements
are surfaced in `raw.scripts` and, when the script output references a
CVE, the parser extracts the CVE into the Observation's `cve` tuple so
the CoverageMatrix can credit the corresponding network coverage item.

The parser uses stdlib `xml.etree.ElementTree` only - no external XML
dependency. On any parse failure it returns an empty tuple rather than
raising, so a malformed tool stream never takes down the runner.
"""
from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree as ET

from secopent.domain.adapters.contracts import (
    AdapterManifest,
    AdapterSource,
    AdapterUpstream,
    CoverageDomain,
    Observation,
    Severity,
)
from secopent.domain.policy.models import RiskClass

_PARSER_ENTRYPOINT = "secopent_adapters.nmap:parse"
_ADAPTER_VERSION = "1.0.0"
_UPSTREAM_VERSION = "7.94"

# NSE script ids commonly associated with vulnerability disclosure. When a
# script in this set emits output, we scan that output for CVE references
# and credit any CVE found to the port's Observation.
_VULN_SCRIPT_IDS: frozenset[str] = frozenset(
    {
        "ssl-heartbleed",
        "ssl-ccs",
        "ssl-poodle",
        "smb-vuln",
        "vulners",
        "http-vuln-cve",
        "ftp-vsftpd-backdoor",
        "ssh-hostkey",
        "ms-sql-empty-password",
    }
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def manifest() -> AdapterManifest:
    """Return the nmap AdapterManifest.

    nmap is GPL-licensed and per §8.2 MUST be invoked as an independent
    subprocess, never embedded as a library. Both facts are surfaced on
    the manifest so the runner / profile selector can enforce the
    subprocess-only boundary at policy time.
    """
    return AdapterManifest(
        id="nmap",
        version=_ADAPTER_VERSION,
        adapter_api_version="v1",
        license="GPL-2.0-or-later",
        upstream=AdapterUpstream(
            name="nmap",
            url="https://nmap.org/",
            version=_UPSTREAM_VERSION,
            digest="sha256:nmap-" + _UPSTREAM_VERSION,
        ),
        risk_class=RiskClass.LOW,
        coverage_domain=(CoverageDomain.NETWORK,),
        input_schema="schema://nmap/input.json",
        output_schema="schema://nmap/output.xml",
        network_policy="scoped-egress",
        parser=_PARSER_ENTRYPOINT,
        fixtures=(
            "fixtures/positive.xml",
            "fixtures/negative.xml",
            "fixtures/timeout.txt",
            "fixtures/malformed.xml",
        ),
        permissions=("network.connect", "independent_process"),
    )


def _extract_cves(text: str) -> tuple[str, ...]:
    """Extract unique CVE IDs from a free-text script output, preserving order."""
    seen: dict[str, None] = {}
    for match in _CVE_RE.findall(text):
        cve = match.upper()
        if cve not in seen:
            seen[cve] = None
    return tuple(seen)


def _host_addresses(host_elem: ET.Element) -> tuple[list[str], str | None]:
    """Return (ipv4_list, hostname_primary) for a <host> element."""
    ips: list[str] = []
    hostname: str | None = None
    for addr in host_elem.findall("address"):
        addrtype = addr.get("addrtype", "")
        if addrtype == "ipv4":
            ips.append(addr.get("addr", ""))
    # Prefer the first <hostname> under <hostnames>.
    for hn in host_elem.iter("hostname"):
        name = hn.get("name")
        if name:
            hostname = name
            break
    return ips, hostname


def _parse_service(port_elem: ET.Element) -> dict[str, str]:
    """Extract service attributes from a <port> element."""
    svc = port_elem.find("service")
    if svc is None:
        return {}
    out: dict[str, str] = {}
    for key in ("name", "product", "version", "extrainfo", "tunnel"):
        val = svc.get(key)
        if val:
            out[key] = val
    return out


def _parse_scripts(port_elem: ET.Element) -> list[dict[str, str]]:
    """Extract NSE <script> elements from a <port> element."""
    scripts: list[dict[str, str]] = []
    for script in port_elem.findall("script"):
        sid = script.get("id", "")
        out = script.get("output", "")
        scripts.append({"id": sid, "output": out})
    return scripts


def parse(
    *, stdout: str, source: AdapterSource, artifacts: dict[str, bytes]
) -> tuple[Observation, ...]:
    """Parse nmap XML (-oX) stdout into Observation records.

    Each open `<port>` on each up `<host>` becomes one Observation whose
    `asset_identity` is `ip:port` and whose `raw` carries the service
    attributes and any NSE `<script>` results. When an NSE vuln script
    emits output referencing a CVE, the CVE is extracted into the
    Observation's `cve` tuple.
    """
    if not stdout or not stdout.strip():
        return ()
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        return ()

    observations: list[Observation] = []
    seen: set[str] = set()
    idx = 0
    for host in root.iter("host"):
        # Status check: skip hosts explicitly marked down.
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue
        ips, hostname = _host_addresses(host)
        if not ips:
            continue
        ip = ips[0]
        for port in host.iter("port"):
            portid = port.get("portid")
            proto = port.get("protocol", "tcp")
            state_elem = port.find("state")
            if state_elem is not None and state_elem.get("state") != "open":
                continue
            if not portid:
                continue
            asset_identity = f"{ip}:{portid}"
            if asset_identity in seen:
                continue
            seen.add(asset_identity)
            service = _parse_service(port)
            scripts = _parse_scripts(port)
            # Extract CVEs from vuln-class NSE scripts.
            cves: set[str] = set()
            cwes: set[str] = set()
            for sc in scripts:
                sid = sc.get("id", "")
                out = sc.get("output", "")
                if sid in _VULN_SCRIPT_IDS or out:
                    cves.update(_extract_cves(out))
            # Light heuristic: ssl-heartbleed / ssl-poodle map to CWE-319
            # (Cleartext Transmission of Sensitive Information) or CWE-310
            # (Cryptographic Issues). We surface CWE-310 for the SSL vuln
            # family so CoverageMatrix can credit the crypto coverage item.
            for sc in scripts:
                sid = sc.get("id", "")
                if sid.startswith("ssl-") and sc.get("output"):
                    cwes.add("CWE-310")
            title = f"open port: {asset_identity}"
            if service.get("name"):
                title = f"open {service['name']} port: {asset_identity}"
            raw: dict[str, Any] = {
                "ip": ip,
                "port": portid,
                "protocol": proto,
                "hostname": hostname or "",
                "service": service,
                "scripts": scripts,
            }
            observations.append(
                Observation(
                    external_id=f"nmap:{asset_identity}:{idx}",
                    asset_identity=asset_identity,
                    source=source,
                    rule_id="nmap.open_port",
                    rule_version=_UPSTREAM_VERSION,
                    coverage_domain=CoverageDomain.NETWORK,
                    title=title,
                    severity=Severity.INFO,
                    confidence=0.95,
                    cwe=tuple(sorted(cwes)),
                    cve=tuple(sorted(cves)),
                    owasp=(),
                    raw=raw,
                )
            )
            idx += 1
    return tuple(observations)
