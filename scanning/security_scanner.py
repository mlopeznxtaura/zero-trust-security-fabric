"""
Security scanning: Semgrep SAST, Nuclei DAST, OWASP ZAP integration.
Run in CI to catch vulnerabilities before they reach production.
SDKs: semgrep, nuclei (via subprocess), httpx
"""
import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass


@dataclass
class ScanFinding:
    tool: str
    severity: str           # critical, high, medium, low, informational
    title: str
    description: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    cwe: Optional[str] = None
    url: Optional[str] = None
    fix: Optional[str] = None


class SemgrepScanner:
    """
    Semgrep SAST — static analysis for security vulnerabilities in source code.
    Runs Semgrep with security rulesets and parses findings.
    """

    RULESETS = [
        "p/security-audit",
        "p/secrets",
        "p/owasp-top-ten",
        "p/python",
        "p/flask",
        "p/django",
        "p/fastapi",
    ]

    def __init__(self, semgrep_path: str = "semgrep"):
        self.semgrep_path = semgrep_path
        self._check_semgrep()

    def _check_semgrep(self):
        try:
            result = subprocess.run([self.semgrep_path, "--version"],
                                    capture_output=True, text=True, timeout=10)
            print(f"[Semgrep] {result.stdout.strip()}")
        except FileNotFoundError:
            print("[Semgrep] Not found. Install: pip install semgrep")

    def scan_path(
        self,
        target_path: str,
        rulesets: Optional[List[str]] = None,
        output_json: bool = True,
        timeout: int = 120,
    ) -> List[ScanFinding]:
        """Run Semgrep on a path and return findings."""
        rulesets = rulesets or ["p/secrets", "p/security-audit"]
        config_args = []
        for ruleset in rulesets:
            config_args.extend(["--config", ruleset])

        cmd = [self.semgrep_path, *config_args, "--json", target_path]
        print(f"[Semgrep] Scanning {target_path} with {len(rulesets)} rulesets...")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        findings = []

        try:
            data = json.loads(result.stdout)
            for r in data.get("results", []):
                severity = r.get("extra", {}).get("severity", "WARNING").lower()
                severity = {"warning": "medium", "error": "high", "info": "low"}.get(severity, severity)
                findings.append(ScanFinding(
                    tool="semgrep",
                    severity=severity,
                    title=r.get("check_id", ""),
                    description=r.get("extra", {}).get("message", ""),
                    file_path=r.get("path"),
                    line=r.get("start", {}).get("line"),
                    fix=r.get("extra", {}).get("fix"),
                ))
        except json.JSONDecodeError:
            print(f"[Semgrep] JSON parse error: {result.stderr[:200]}")

        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        print(f"[Semgrep] {len(findings)} findings: {sev_counts}")
        return findings

    def scan_string(self, code: str, language: str = "python") -> List[ScanFinding]:
        """Scan a code snippet directly."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=f".{language}", delete=False) as f:
            f.write(code)
            path = f.name
        try:
            return self.scan_path(path, rulesets=["p/security-audit", "p/secrets"])
        finally:
            os.unlink(path)


class NucleiScanner:
    """
    Nuclei DAST — network-level vulnerability scanner.
    Runs Nuclei templates against live HTTP targets.
    """

    TEMPLATE_GROUPS = [
        "cves", "vulnerabilities", "exposed-panels",
        "misconfigurations", "default-logins", "exposures",
    ]

    def __init__(self, nuclei_path: str = "nuclei"):
        self.nuclei_path = nuclei_path
        self._check_nuclei()

    def _check_nuclei(self):
        try:
            result = subprocess.run([self.nuclei_path, "-version"],
                                    capture_output=True, text=True, timeout=10)
            print(f"[Nuclei] {result.stdout.strip() or result.stderr.strip()}")
        except FileNotFoundError:
            print("[Nuclei] Not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

    def scan_target(
        self,
        target_url: str,
        template_groups: Optional[List[str]] = None,
        severity: str = "medium,high,critical",
        timeout: int = 300,
        rate_limit: int = 50,
    ) -> List[ScanFinding]:
        """Run Nuclei scan against a URL. Returns list of findings."""
        groups = template_groups or ["misconfigurations", "exposed-panels", "default-logins"]
        tag_args = []
        for group in groups:
            tag_args.extend(["-tags", group])

        cmd = [
            self.nuclei_path,
            "-u", target_url,
            *tag_args,
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-json",
            "-silent",
        ]
        print(f"[Nuclei] Scanning {target_url} | groups={groups}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        findings = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append(ScanFinding(
                    tool="nuclei",
                    severity=data.get("info", {}).get("severity", "medium"),
                    title=data.get("info", {}).get("name", ""),
                    description=data.get("info", {}).get("description", ""),
                    url=data.get("matched-at", target_url),
                    cwe=data.get("info", {}).get("classification", {}).get("cwe-id", [""])[0],
                ))
            except json.JSONDecodeError:
                continue

        sev_counts = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        print(f"[Nuclei] {len(findings)} findings: {sev_counts}")
        return findings


class SecurityScanOrchestrator:
    """
    Orchestrate SAST + DAST scans. Generate unified security report.
    """

    def __init__(self):
        self.semgrep = SemgrepScanner()
        self.nuclei = NucleiScanner()
        self.all_findings: List[ScanFinding] = []

    def run_full_scan(
        self,
        code_path: Optional[str] = None,
        target_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        if code_path:
            sast = self.semgrep.scan_path(code_path)
            self.all_findings.extend(sast)

        if target_url:
            dast = self.nuclei.scan_target(target_url)
            self.all_findings.extend(dast)

        return self._generate_report()

    def _generate_report(self) -> Dict[str, Any]:
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in self.all_findings:
            sev = f.severity.lower() if f.severity.lower() in by_severity else "informational"
            by_severity[sev] += 1

        risk_score = (
            by_severity["critical"] * 10 +
            by_severity["high"] * 5 +
            by_severity["medium"] * 2 +
            by_severity["low"] * 1
        )

        return {
            "total_findings": len(self.all_findings),
            "by_severity": by_severity,
            "risk_score": risk_score,
            "pass": risk_score == 0,
            "findings": [
                {"tool": f.tool, "severity": f.severity, "title": f.title,
                 "file": f.file_path, "line": f.line, "url": f.url}
                for f in self.all_findings[:50]
            ],
        }
