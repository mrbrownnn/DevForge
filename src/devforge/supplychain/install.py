"""Skill installation: fetch, verify, inspect, gate, install, lock.

The safety property this module exists to provide, stated plainly:

    **DevForge never executes an installed skill.**

A skill is instructions. There is no code path that runs a file a skill shipped -
no install hook, no postinstall, no interpreter invocation. Executable content is
*quarantined*: recorded in the report and in the lockfile, kept out of the active
directory unless a human passes ``--with-scripts``, and even then never run by
DevForge. That is what lets a user install a skill without handing it the machine.

The pipeline
------------

1. resolve the catalogue entry
2. refuse an unpinned install (a name is not an identity)
3. fetch the tree with ``git`` at that exact commit
4. verify the checkout matches the pin
5. compute a content hash of what actually arrived
6. compare against the catalogue hash, if one was recorded
7. inspect the tree: scripts, installers, network, secrets, encoded payloads
8. classify risk and derive the permissions the content implies
9. refuse CRITICAL outright; gate anything above the policy ceiling
10. install into an isolated per-skill directory, quarantining executables
11. write the security report
12. write ``skills.lock`` - and never move a pin without being asked

Update is the same pipeline with one extra rule: a pinned skill is never silently
upgraded. ``update`` requires an explicit new commit or ``--to-head``, reports the
pin change, and re-runs every check against the new tree.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from devforge.core.errors import DevForgeError
from devforge.core.models import utcnow
from devforge.observability.logging import RunLogger, null_logger
from devforge.policy.engine import PolicyEngine
from devforge.supplychain.catalog import SecurityStatus, SkillEntry, SourceType
from devforge.supplychain.fetch import FetchedSource, fetch_git_source, resolve_head
from devforge.supplychain.inspect import SCRIPT_SUFFIXES, inspect_skill
from devforge.supplychain.quality import RepoSignals, detect_license, quality_summary, score_skill
from devforge.supplychain.risk import RiskAssessment, SkillRisk, classify, render_report

LOCKFILE_NAME = "skills.lock"
INSTALL_DIRNAME = "installed-skills"
QUARANTINE_DIRNAME = "quarantine"
REPORT_DIRNAME = "security-reports"

#: Installation is refused above this level unless a human approves it.
DEFAULT_RISK_CEILING = SkillRisk.LOW

#: Permissions implied by what the content demonstrably does.
PERMISSION_BY_CAPABILITY = {
    "local script execution": "process_execution",
    "remote code execution": "process_execution",
    "package installation": "process_execution",
    "network access": "network",
    "network egress": "network",
    "credential access": "credential_read",
    "reads credentials from the environment": "credential_read",
    "destructive operation": "filesystem_delete",
    "install/session hook": "process_execution",
}


class InstallError(DevForgeError):
    """Installation was refused or could not complete."""


class ApprovalRequiredError(InstallError):
    """The risk exceeds the policy ceiling and no approval was given."""


class LockEntry(BaseModel):
    """One installed skill, pinned by commit *and* by content."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str = "0.0.0"
    source: str
    source_type: SourceType = SourceType.GIT
    repository: str = ""
    commit_sha: str = ""
    path: str = "."
    content_hash: str = ""
    license: str | None = None
    risk_level: str = SkillRisk.LOW
    security_status: SecurityStatus = SecurityStatus.UNAUDITED
    required_permissions: list[str] = Field(default_factory=list)
    quarantined_files: list[str] = Field(default_factory=list)
    installed_at: datetime = Field(default_factory=utcnow)
    installed_by: str = ""
    approved_by: str = ""
    report_path: str | None = None
    quality_grade: str = ""

    def differs_from(self, other: LockEntry) -> list[str]:
        changes = []
        if self.commit_sha != other.commit_sha:
            changes.append(f"commit {self.commit_sha[:8]} -> {other.commit_sha[:8]}")
        if self.content_hash != other.content_hash:
            changes.append("content hash changed")
        if self.risk_level != other.risk_level:
            changes.append(f"risk {self.risk_level} -> {other.risk_level}")
        if self.license != other.license:
            changes.append(f"license {self.license} -> {other.license}")
        return changes


class Lockfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    updated_at: datetime = Field(default_factory=utcnow)
    skills: list[LockEntry] = Field(default_factory=list)

    def entry(self, name: str) -> LockEntry | None:
        return next((skill for skill in self.skills if skill.name == name), None)

    def upsert(self, entry: LockEntry) -> None:
        self.skills = [skill for skill in self.skills if skill.name != entry.name]
        self.skills.append(entry)
        self.skills.sort(key=lambda skill: skill.name)
        self.updated_at = utcnow()

    def remove(self, name: str) -> bool:
        before = len(self.skills)
        self.skills = [skill for skill in self.skills if skill.name != name]
        self.updated_at = utcnow()
        return len(self.skills) != before


def lockfile_path(project_root: Path) -> Path:
    """At the project root, not inside ``.devforge``: a lockfile is meant to be committed."""
    return Path(project_root) / LOCKFILE_NAME


def load_lockfile(project_root: Path) -> Lockfile:
    path = lockfile_path(project_root)
    if not path.is_file():
        return Lockfile()
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise InstallError(f"invalid YAML in {path}: {exc}") from exc
    return Lockfile.model_validate(raw)


def save_lockfile(project_root: Path, lock: Lockfile) -> Path:
    path = lockfile_path(project_root)
    payload = json.loads(lock.model_dump_json())
    header = (
        "# DevForge skill lockfile - commit this file.\n"
        "#\n"
        "# Each entry pins a skill by commit SHA *and* by content hash. A pin is never\n"
        "# moved implicitly: `devforge skill update` requires an explicit target and\n"
        "# re-runs every security check against the new tree.\n"
    )
    path.write_text(header + yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return path


def install_root(project_root: Path) -> Path:
    return Path(project_root) / ".devforge" / INSTALL_DIRNAME


def skill_dir(project_root: Path, name: str) -> Path:
    return install_root(project_root) / name


def report_dir(project_root: Path) -> Path:
    return Path(project_root) / ".devforge" / REPORT_DIRNAME


@dataclass
class InstallPlan:
    """Everything decided before anything is written."""

    entry: SkillEntry
    source: FetchedSource
    assessment: RiskAssessment
    license_name: str | None
    quality_grade: str
    required_permissions: list[str]
    executable_files: list[str] = field(default_factory=list)
    hash_matches_catalog: bool | None = None

    @property
    def needs_approval(self) -> bool:
        return self.assessment.requires_approval

    @property
    def blocked(self) -> bool:
        return self.assessment.blocked


@dataclass
class InstallResult:
    entry: LockEntry
    plan: InstallPlan
    installed_path: Path
    report_path: Path
    quarantined: list[str]
    replaced: list[str] = field(default_factory=list)


def derive_permissions(assessment: RiskAssessment) -> list[str]:
    """Permissions implied by what the content does, not by what it claims."""
    permissions = {
        PERMISSION_BY_CAPABILITY[capability]
        for capability in assessment.capabilities
        if capability in PERMISSION_BY_CAPABILITY
    }
    return sorted(permissions)


def executable_files(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in SCRIPT_SUFFIXES
    )


class SkillInstaller:
    """Runs the pipeline. Every refusal is a value, not an exception, until the end."""

    def __init__(
        self,
        project_root: Path,
        *,
        policy: PolicyEngine,
        logger: RunLogger | None = None,
        risk_ceiling: str = DEFAULT_RISK_CEILING,
    ) -> None:
        self.project_root = Path(project_root)
        self.policy = policy
        self.logger = logger or null_logger()
        self.risk_ceiling = risk_ceiling

    # -- planning ---------------------------------------------------------------

    async def plan(
        self,
        entry: SkillEntry,
        *,
        commit: str | None = None,
        signals: RepoSignals | None = None,
    ) -> InstallPlan:
        """Steps 1-8: fetch, verify, hash, inspect, classify. Writes nothing."""
        if entry.source_type is not SourceType.GIT:
            raise InstallError(
                f"source type '{entry.source_type.value}' is not implemented; "
                "only git sources can be installed"
            )

        target = commit or entry.commit_sha
        if target is None:
            raise InstallError(
                f"skill '{entry.name}' has no pinned commit. A name is not an identity - "
                "pin it in the catalogue, or pass an explicit commit."
            )

        self.logger.info(
            "skill.fetch", skill=entry.name, repository=entry.repository, commit=target[:12]
        )
        source = await fetch_git_source(
            entry.repository or entry.source,
            policy=self.policy,
            commit=target,
            subpath=entry.path,
        )

        hash_matches = None
        if entry.content_hash:
            hash_matches = entry.content_hash == source.content_hash
            if not hash_matches:
                source.cleanup()
                raise InstallError(
                    f"content hash mismatch for '{entry.name}': catalogue records "
                    f"{entry.content_hash}, fetched tree hashes to {source.content_hash}. "
                    "The reviewed tree and the served tree are not the same."
                )

        report = inspect_skill(source.skill_root)
        assessment = classify(report)
        license_name = detect_license(source.skill_root) or entry.license
        quality = score_skill(
            source.skill_root,
            assessment=assessment,
            license_name=license_name,
            capabilities=entry.capabilities,
            dependencies=entry.dependencies,
            supported_runtimes=entry.supported_runtimes,
            signals=signals,
        )

        for warning in source.warnings:
            self.logger.warn("skill.fetch_warning", skill=entry.name, detail=warning)

        self.logger.info(
            "skill.inspect",
            skill=entry.name,
            commit=source.commit_sha[:12],
            content_hash=source.content_hash,
            risk=assessment.level,
            findings=assessment.counts(),
            quality=quality.grade,
        )

        return InstallPlan(
            entry=entry,
            source=source,
            assessment=assessment,
            license_name=license_name,
            quality_grade=quality_summary(quality),
            required_permissions=derive_permissions(assessment),
            executable_files=executable_files(source.skill_root),
            hash_matches_catalog=hash_matches,
        )

    # -- installation -----------------------------------------------------------

    def install(
        self,
        plan: InstallPlan,
        *,
        approved_by: str = "",
        with_scripts: bool = False,
        installed_by: str = "",
    ) -> InstallResult:
        """Steps 9-12: gate, install, report, lock."""
        entry = plan.entry

        if plan.blocked:
            self._write_report(plan)
            raise InstallError(
                f"'{entry.name}' is CRITICAL and will not be installed: "
                f"{'; '.join(plan.assessment.reasons)}. A report was written for review."
            )

        if plan.assessment.exceeds(self.risk_ceiling) and not approved_by:
            self._write_report(plan)
            raise ApprovalRequiredError(
                f"'{entry.name}' is {plan.assessment.level}, above the ceiling "
                f"{self.risk_ceiling}. Review the report, then re-run with --approve-by NAME."
            )

        target = skill_dir(self.project_root, entry.name)
        replaced = []
        if target.exists():
            replaced = sorted(p.name for p in target.iterdir())
            shutil.rmtree(target)
        target.mkdir(parents=True, exist_ok=True)

        quarantine = target / QUARANTINE_DIRNAME
        quarantined: list[str] = []

        for path in sorted(plan.source.skill_root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(plan.source.skill_root)
            executable = path.suffix.lower() in SCRIPT_SUFFIXES

            if executable and not with_scripts:
                # Quarantined: kept for review, never placed where a reader would
                # mistake it for active content, and never run by DevForge.
                destination = quarantine / relative
                quarantined.append(relative.as_posix())
            else:
                destination = target / relative
                if executable:
                    quarantined.append(relative.as_posix())

            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)

        if quarantined and not with_scripts:
            (quarantine / "README.devforge.md").write_text(
                "# Quarantined files\n\n"
                "These files shipped with the skill and are executable. DevForge copied them\n"
                "here for review and does **not** place them in the active skill directory.\n"
                "DevForge never executes skill content in any case - see\n"
                "docs/security/skills.md.\n\n"
                + "\n".join(f"- `{name}`" for name in quarantined)
                + "\n",
                encoding="utf-8",
            )

        report_path = self._write_report(plan)

        lock_entry = LockEntry(
            name=entry.name,
            version=entry.version,
            source=entry.source,
            source_type=entry.source_type,
            repository=entry.repository,
            commit_sha=plan.source.commit_sha,
            path=entry.path,
            content_hash=plan.source.content_hash,
            license=plan.license_name,
            risk_level=plan.assessment.level,
            security_status=(
                SecurityStatus.AUDITED_CLEAN
                if not plan.assessment.findings
                else SecurityStatus.AUDITED_WITH_FINDINGS
            ),
            required_permissions=plan.required_permissions,
            quarantined_files=quarantined,
            installed_by=installed_by,
            approved_by=approved_by,
            report_path=str(report_path.relative_to(self.project_root)).replace("\\", "/"),
            quality_grade=plan.quality_grade,
        )

        lock = load_lockfile(self.project_root)
        lock.upsert(lock_entry)
        save_lockfile(self.project_root, lock)

        self.logger.info(
            "skill.install",
            skill=entry.name,
            commit=plan.source.commit_sha[:12],
            content_hash=plan.source.content_hash,
            risk=plan.assessment.level,
            quarantined=len(quarantined),
            approved_by=approved_by or None,
        )

        return InstallResult(
            entry=lock_entry,
            plan=plan,
            installed_path=target,
            report_path=report_path,
            quarantined=quarantined,
            replaced=replaced,
        )

    def _write_report(self, plan: InstallPlan) -> Path:
        directory = report_dir(self.project_root)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{plan.entry.name}-{plan.source.commit_sha[:12]}.md"
        path.write_text(
            render_report(
                skill=plan.entry.name,
                repository=plan.entry.repository or plan.entry.source,
                commit=plan.source.commit_sha,
                assessment=plan.assessment,
                license_name=plan.license_name,
                quality_summary=plan.quality_grade,
            ),
            encoding="utf-8",
        )
        return path

    # -- update / remove --------------------------------------------------------

    async def resolve_update_target(self, entry: SkillEntry, *, to_head: bool) -> str:
        """A pin is never moved implicitly."""
        if to_head:
            return await resolve_head(entry.repository or entry.source, policy=self.policy)
        if entry.commit_sha is None:
            raise InstallError(
                f"'{entry.name}' has no catalogue pin to update to. Pass --commit or --to-head."
            )
        return entry.commit_sha

    def remove(self, name: str) -> tuple[bool, Path]:
        target = skill_dir(self.project_root, name)
        existed = target.exists()
        if existed:
            shutil.rmtree(target)
        lock = load_lockfile(self.project_root)
        removed = lock.remove(name)
        if removed:
            save_lockfile(self.project_root, lock)
        self.logger.info("skill.remove", skill=name, removed=existed or removed)
        return (existed or removed), target


def verify_installed(project_root: Path, entry: LockEntry) -> list[str]:
    """Re-hash an installed skill and report drift.

    Catches the case the lockfile exists to catch: content changing under a pin
    that still says everything is fine.
    """
    from devforge.supplychain.registry import content_hash

    problems: list[str] = []
    target = skill_dir(project_root, entry.name)
    if not target.is_dir():
        return [f"{entry.name}: installed directory is missing"]

    active = target
    quarantine = target / QUARANTINE_DIRNAME
    if quarantine.exists() and entry.quarantined_files:
        # The active tree is what the lockfile hash covers only when nothing was
        # quarantined; otherwise report the split rather than a false mismatch.
        problems.append(
            f"{entry.name}: {len(entry.quarantined_files)} quarantined file(s) are held "
            "outside the active tree, so the installed hash differs from the source hash by design"
        )
        return problems

    observed = content_hash(active)
    if observed != entry.content_hash:
        problems.append(
            f"{entry.name}: content changed since install "
            f"(locked {entry.content_hash[:23]}..., found {observed[:23]}...)"
        )
    return problems
