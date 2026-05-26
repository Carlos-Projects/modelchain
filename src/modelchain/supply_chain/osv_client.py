from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from modelchain.models import VulnerabilityEntry


@dataclass
class OSVQueryResult:
    query_package: str
    query_version: str
    vulnerabilities: list[VulnerabilityEntry]
    queried_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class OSVClient:
    """Client for the OSV.dev vulnerability database API."""

    BASE_URL = "https://api.osv.dev/v1"

    def __init__(self, timeout: float = 30.0):
        self._client = httpx.Client(base_url=self.BASE_URL, timeout=timeout)

    def query_package(self, name: str, version: str) -> list[VulnerabilityEntry]:
        payload = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        try:
            resp = self._client.post("/query", json=payload)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, httpx.TimeoutException) as e:
            return [
                VulnerabilityEntry(
                    id=f"OSV-ERROR-{name}",
                    package_name=name,
                    affected_versions=version,
                    severity="LOW",
                    description=f"OSV query failed: {e}",
                )
            ]
        return self._parse_response(data, name, version)

    def query_batch(self, packages: list[dict[str, str]]) -> list[OSVQueryResult]:
        results: list[OSVQueryResult] = []
        for pkg in packages:
            vulns = self.query_package(pkg["name"], pkg["version"])
            results.append(OSVQueryResult(
                query_package=pkg["name"],
                query_version=pkg["version"],
                vulnerabilities=vulns,
            ))
        return results

    def query_from_metadata(self, deps: list[dict[str, str]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for dep in deps:
            vulns = self.query_package(dep["name"], dep["version"])
            for vuln in vulns:
                results.append({
                    "vulnerability_id": vuln.id,
                    "package": vuln.package_name,
                    "installed_version": dep["version"],
                    "affected_versions": vuln.affected_versions,
                    "severity": vuln.severity,
                    "cvss_score": vuln.cvss_score,
                    "description": vuln.description,
                    "fix_version": vuln.fix_version or "",
                    "references": vuln.references,
                    "source": "osv.dev",
                })
        return results

    def close(self) -> None:
        self._client.close()

    def _parse_response(self, data: dict[str, Any], name: str, version: str) -> list[VulnerabilityEntry]:
        vulns: list[VulnerabilityEntry] = []
        for item in data.get("vulns", []):
            vuln_id = item.get("id", "OSV-UNKNOWN")
            summary = item.get("summary", "") or ""
            details = item.get("details", "") or ""
            description = f"{summary}\n{details}".strip()[:500]

            severity = "MEDIUM"
            cvss_score: float | None = None
            for se in item.get("severity", []):
                if se.get("type") == "CVSS":
                    try:
                        score = float(se.get("score", "0"))
                        cvss_score = score
                        severity = self._cvss_to_severity(score)
                    except (ValueError, TypeError):
                        pass

            fix_version = ""
            for aff in item.get("affected", []):
                for vr in aff.get("ranges", []):
                    for event in vr.get("events", []):
                        if "fixed" in event:
                            fix_version = event["fixed"]

            refs = [r.get("url", "") for r in item.get("references", [])]

            vulns.append(VulnerabilityEntry(
                id=vuln_id,
                package_name=name,
                affected_versions=version,
                severity=severity,
                description=description,
                cvss_score=cvss_score,
                fix_version=fix_version or None,
                references=refs,
            ))
        return vulns

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"

    def __enter__(self) -> OSVClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
