"""GitHub repository sync and SCALIBR scan orchestration."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .config import RepoScanningConfig

log = logging.getLogger(__name__)


@dataclass
class RepoFinding:
    vulnerability_id: str
    severity: str
    package_name: str = ""
    details: Dict[str, Any] | None = None


@dataclass
class RepoScanResult:
    repo_name: str
    repo_url: str
    local_path: str
    status: str
    result_path: str
    vulnerability_count: int
    findings: List[RepoFinding]


class RepoScanner:
    """Downloads GitHub repositories and scans them with SCALIBR."""

    def __init__(self, config: RepoScanningConfig):
        self.config = config
        self.workspace_dir = Path(config.local_workspace)
        self.results_dir = Path(config.results_dir)

    def is_enabled(self) -> bool:
        return self.config.enabled

    def _run(self, args: list[str], cwd: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess:
        log.debug("Running command: %s", args)
        return subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

    def _repo_path(self, repo_name: str) -> Path:
        return self.workspace_dir / repo_name.replace("/", "__")

    def _resolve_account(self) -> str:
        if self.config.github_account:
            return self.config.github_account
        proc = self._run(["gh", "api", "user", "--jq", ".login"])
        account = proc.stdout.strip()
        if not account:
            raise RuntimeError("Unable to resolve GitHub account from gh auth state.")
        return account

    def list_repos(self) -> List[Dict[str, Any]]:
        account = self._resolve_account()
        proc = self._run(
            [
                "gh",
                "repo",
                "list",
                account,
                "--limit",
                str(self.config.repo_limit),
                "--json",
                "nameWithOwner,url,isPrivate,isArchived",
            ]
        )
        repos = json.loads(proc.stdout or "[]")
        filtered = []
        for repo in repos:
            if repo.get("isArchived") and not self.config.include_archived:
                continue
            if repo.get("isPrivate") and not self.config.include_private:
                continue
            filtered.append(repo)
        return filtered

    def sync_repo(self, repo: Dict[str, Any]) -> Path:
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        repo_path = self._repo_path(repo["nameWithOwner"])
        if (repo_path / ".git").exists():
            self._run(["git", "-C", str(repo_path), "pull", "--ff-only"])
            return repo_path

        self._run(["gh", "repo", "clone", repo["nameWithOwner"], str(repo_path)])
        return repo_path

    def scan_repo(self, repo: Dict[str, Any]) -> RepoScanResult:
        repo_path = self.sync_repo(repo)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        result_path = self.results_dir / f"{repo['nameWithOwner'].replace('/', '__')}-{timestamp}.textproto"

        args = [
            self.config.scalibr_binary,
            "scan",
            "--root",
            str(repo_path),
            "--result",
            str(result_path),
        ]
        if self.config.use_gitignore:
            args.append("--use-gitignore")

        try:
            self._run(args, timeout=self.config.scan_timeout_seconds)
        except subprocess.CalledProcessError as exc:
            message = exc.stderr.strip() or exc.stdout.strip() or "SCALIBR scan failed"
            raise RuntimeError(message) from exc

        findings = self.parse_scan_result(result_path)
        return RepoScanResult(
            repo_name=repo["nameWithOwner"],
            repo_url=repo["url"],
            local_path=str(repo_path),
            status="COMPLETED",
            result_path=str(result_path),
            vulnerability_count=len(findings),
            findings=findings,
        )

    def run_all(self) -> List[RepoScanResult]:
        results: List[RepoScanResult] = []
        for repo in self.list_repos():
            try:
                results.append(self.scan_repo(repo))
            except Exception as exc:
                log.error("Repo scan failed for %s: %s", repo.get("nameWithOwner"), exc)
                results.append(
                    RepoScanResult(
                        repo_name=repo["nameWithOwner"],
                        repo_url=repo["url"],
                        local_path=str(self._repo_path(repo["nameWithOwner"])),
                        status="FAILED",
                        result_path="",
                        vulnerability_count=0,
                        findings=[],
                    )
                )
        return results

    @staticmethod
    def parse_scan_result(result_path: str | Path) -> List[RepoFinding]:
        text = Path(result_path).read_text(encoding="utf-8")
        findings: List[RepoFinding] = []

        package_blocks = re.findall(r"package_vulns\s*\{(.*?)\n\}", text, flags=re.DOTALL)
        for block in package_blocks:
            vuln_id = ""
            match = re.search(r'\bid:\s*"([^"]+)"', block)
            if match:
                vuln_id = match.group(1)
            else:
                publisher = re.search(r'publisher:\s*"([^"]+)"', block)
                reference = re.search(r'reference:\s*"([^"]+)"', block)
                if publisher and reference:
                    vuln_id = f"{publisher.group(1)}-{reference.group(1)}"
            severity_match = re.search(r'severity:\s*"([^"]+)"', block)
            package_match = re.search(r'package_id:\s*"([^"]+)"', block)
            findings.append(
                RepoFinding(
                    vulnerability_id=vuln_id or "UNKNOWN",
                    severity=(severity_match.group(1).lower() if severity_match else "unknown"),
                    package_name=(package_match.group(1) if package_match else ""),
                    details={"kind": "package_vuln"},
                )
            )

        generic_blocks = re.findall(r"generic_findings\s*\{(.*?)\n\}", text, flags=re.DOTALL)
        for block in generic_blocks:
            publisher = re.search(r'publisher:\s*"([^"]+)"', block)
            reference = re.search(r'reference:\s*"([^"]+)"', block)
            title = re.search(r'title:\s*"([^"]+)"', block)
            severity_match = re.search(r"\bsev:\s*([A-Z_]+)", block)
            if publisher and reference:
                finding_id = f"{publisher.group(1)}-{reference.group(1)}"
            elif title:
                finding_id = title.group(1)
            else:
                finding_id = "GENERIC_FINDING"
            findings.append(
                RepoFinding(
                    vulnerability_id=finding_id,
                    severity=(severity_match.group(1).lower() if severity_match else "unknown"),
                    details={"kind": "generic_finding"},
                )
            )

        return findings
