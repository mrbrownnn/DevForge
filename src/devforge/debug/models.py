"""Domain models for autonomous debugging and repair.

Debugging in DevForge is not a prompt that says "find the bug". It is a pipeline
with named, inspectable intermediate products:

``Reproduction``
    Proof the defect exists and that observing it is repeatable. A bug that
    cannot be reproduced cannot be verified as fixed, so this comes first and a
    non-deterministic reproduction is reported as such rather than averaged away.
``EvidenceBundle``
    What was actually observed - traces, logs, failing tests, the diff, the
    source around the failure, browser console and network errors. Every item
    records where it came from and whether it was truncated or redacted.
``Diagnosis``
    A root cause and a hypothesis, stated separately from the evidence so a
    reviewer can see which claims are observed and which are inferred.
``RepairReport``
    Diagnosis + changed files + tests + verification result, in one artifact.
    The brief's rule is "no silent modifications"; this model is what makes that
    checkable, and :class:`PatchReview` is what makes it trustworthy.

Everything here is data. The collectors, the guard and the verifiers all produce
these types, so a report can be rendered, persisted and diffed without any of
them knowing about each other.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class EvidenceKind(str, Enum):
    """The categories the brief requires evidence collection to cover."""

    STACK_TRACE = "stack_trace"
    LOG = "log"
    TEST_FAILURE = "test_failure"
    DIFF = "diff"
    SOURCE = "source"
    RUNTIME_STATE = "runtime_state"
    BROWSER_CONSOLE = "browser_console"
    NETWORK_ERROR = "network_error"


class Evidence(BaseModel):
    """One observation, with its provenance.

    ``redacted`` and ``truncated`` are recorded rather than hidden: a reader who
    cannot see why the evidence looks incomplete will assume it is complete.
    """

    model_config = ConfigDict(extra="forbid")

    kind: EvidenceKind
    label: str
    content: str = ""
    #: Where this came from - a path, a command, a URL. Never a secret.
    source: str = ""
    truncated: bool = False
    redacted: bool = False

    def render(self) -> str:
        notes = []
        if self.truncated:
            notes.append("truncated")
        if self.redacted:
            notes.append("secrets redacted")
        suffix = f" ({', '.join(notes)})" if notes else ""
        head = f"### {self.label}{suffix}"
        origin = f"\n_source: `{self.source}`_" if self.source else ""
        body = self.content.strip() or "(empty)"
        return f"{head}{origin}\n\n```\n{body}\n```"


class EvidenceBundle(BaseModel):
    """Everything collected for one defect, plus what could not be collected.

    ``refused`` is as important as ``items``. When the policy engine declines to
    read a path - ``.env``, a key file, something outside the workspace - the
    bundle says so. Silently omitting it would let a reader conclude the file was
    irrelevant rather than off limits.
    """

    model_config = ConfigDict(extra="forbid")

    items: list[Evidence] = Field(default_factory=list)
    refused: list[str] = Field(default_factory=list)

    def of(self, kind: EvidenceKind) -> list[Evidence]:
        return [item for item in self.items if item.kind is kind]

    def kinds(self) -> list[EvidenceKind]:
        seen: list[EvidenceKind] = []
        for item in self.items:
            if item.kind not in seen:
                seen.append(item.kind)
        return seen

    def add(self, evidence: Evidence | None) -> None:
        if evidence is not None:
            self.items.append(evidence)

    def render(self) -> str:
        if not self.items and not self.refused:
            return "No evidence was collected."
        lines = ["## Evidence", ""]
        lines.append(
            f"{len(self.items)} item(s) across {len(self.kinds())} "
            f"categor{'y' if len(self.kinds()) == 1 else 'ies'}."
        )
        lines.append("")
        for item in self.items:
            lines.append(item.render())
            lines.append("")
        if self.refused:
            lines.append("### Not collected")
            lines.append("")
            lines.append("The permission policy refused these; they were not read:")
            lines.append("")
            lines += [f"- {entry}" for entry in self.refused]
            lines.append("")
        return "\n".join(lines).strip() + "\n"


class ReproductionOutcome(str, Enum):
    """Did running the reproduction actually show the defect, every time?"""

    #: Failed on every attempt - the ideal starting point.
    DETERMINISTIC = "deterministic"
    #: Failed on some attempts. A fix cannot be proven against this.
    FLAKY = "flaky"
    #: Never failed. Either it is already fixed or the command is wrong.
    NOT_REPRODUCED = "not_reproduced"
    #: Could not be attempted - policy refused it, or the binary is missing.
    UNAVAILABLE = "unavailable"

    @property
    def usable(self) -> bool:
        """Only a deterministic reproduction supports a verifiable repair."""
        return self is ReproductionOutcome.DETERMINISTIC


class ReproductionAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exit_code: int | None = None
    duration_ms: int = 0
    failed: bool = False
    output_excerpt: str = ""


class Reproduction(BaseModel):
    """The result of trying to make the defect happen on demand."""

    model_config = ConfigDict(extra="forbid")

    argv: list[str] = Field(default_factory=list)
    outcome: ReproductionOutcome = ReproductionOutcome.UNAVAILABLE
    attempts: list[ReproductionAttempt] = Field(default_factory=list)
    summary: str = ""

    @property
    def failure_output(self) -> str:
        """Output from the first failing attempt - what diagnosis works from."""
        for attempt in self.attempts:
            if attempt.failed:
                return attempt.output_excerpt
        return ""

    def render(self) -> str:
        command = " ".join(self.argv) or "(none)"
        lines = [
            "## Reproduction",
            "",
            f"- command: `{command}`",
            f"- outcome: **{self.outcome.value}**",
            f"- attempts: {len(self.attempts)}"
            f" ({sum(1 for a in self.attempts if a.failed)} failed)",
            f"- {self.summary}" if self.summary else "",
            "",
        ]
        if self.failure_output:
            lines += ["```", self.failure_output.strip(), "```", ""]
        return "\n".join(line for line in lines if line is not None)


class Severity(str, Enum):
    INFO = "info"
    MINOR = "minor"
    MAJOR = "major"


class PatchCategory(str, Enum):
    """The suspicious-patch patterns the brief names, plus what they generalise to.

    These are the ways a repair can "succeed" while making the software worse:
    the check that would have caught the bug is gone, so the suite is green and
    nothing is fixed.
    """

    ASSERTION_REMOVED = "assertion_removed"
    TEST_DISABLED = "test_disabled"
    TEST_DELETED = "test_deleted"
    AUTH_DISABLED = "auth_disabled"
    VALIDATION_BYPASSED = "validation_bypassed"
    EXCEPTION_SWALLOWED = "exception_swallowed"
    SECURITY_CHECK_OFF = "security_check_off"
    POLICY_WEAKENED = "policy_weakened"
    SECRET_INTRODUCED = "secret_introduced"
    SCOPE_ESCAPE = "scope_escape"


#: Why each category matters, in one line, shown in reports.
CATEGORY_RATIONALE: dict[PatchCategory, str] = {
    PatchCategory.ASSERTION_REMOVED: (
        "an assertion is the only thing a test proves; deleting it makes the test pass "
        "without making the code correct"
    ),
    PatchCategory.TEST_DISABLED: (
        "a skipped or xfailed test reports success while checking nothing"
    ),
    PatchCategory.TEST_DELETED: "the coverage that would catch a regression is gone",
    PatchCategory.AUTH_DISABLED: "authentication or authorisation was turned off or bypassed",
    PatchCategory.VALIDATION_BYPASSED: "input validation was removed, weakened or short-circuited",
    PatchCategory.EXCEPTION_SWALLOWED: (
        "a broad except that passes hides the failure instead of fixing it"
    ),
    PatchCategory.SECURITY_CHECK_OFF: (
        "a security control (certificate verification, sandboxing, escaping) was disabled"
    ),
    PatchCategory.POLICY_WEAKENED: (
        "the repair edited DevForge's own permission or approval policy, which is how a "
        "patch grants itself privileges"
    ),
    PatchCategory.SECRET_INTRODUCED: "a credential-shaped literal was added to the source",
    PatchCategory.SCOPE_ESCAPE: "the patch touches files outside the workspace under repair",
}


class PatchFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: PatchCategory
    severity: Severity
    file: str
    line: int = 0
    #: The offending diff line, already redacted.
    evidence: str = ""
    detail: str = ""

    def describe(self) -> str:
        where = f"{self.file}:{self.line}" if self.line else self.file
        return f"[{self.severity.value}] {self.category.value} at {where}: {self.detail}"


class PatchVerdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    #: Nothing to review - an empty diff is not a clean bill of health.
    EMPTY = "empty"


class PatchReview(BaseModel):
    """The result of reading a patch for the ways it could be cheating."""

    model_config = ConfigDict(extra="forbid")

    findings: list[PatchFinding] = Field(default_factory=list)
    files_changed: list[str] = Field(default_factory=list)
    lines_added: int = 0
    lines_removed: int = 0

    @property
    def major(self) -> list[PatchFinding]:
        return [f for f in self.findings if f.severity is Severity.MAJOR]

    @property
    def minor(self) -> list[PatchFinding]:
        return [f for f in self.findings if f.severity is Severity.MINOR]

    def verdict(self) -> PatchVerdict:
        if not self.files_changed and not self.findings:
            return PatchVerdict.EMPTY
        return PatchVerdict.SUSPICIOUS if self.major else PatchVerdict.CLEAN

    def render(self) -> str:
        lines = [
            "## Patch review",
            "",
            f"- files changed: {len(self.files_changed)}",
            f"- lines: +{self.lines_added} / -{self.lines_removed}",
            f"- verdict: **{self.verdict().value}**",
            "",
        ]
        if not self.findings:
            lines += ["No suspicious patterns detected.", ""]
        else:
            lines += ["| severity | pattern | location | detail |", "| --- | --- | --- | --- |"]
            for finding in self.findings:
                where = f"{finding.file}:{finding.line}" if finding.line else finding.file
                lines.append(
                    f"| {finding.severity.value} | {finding.category.value} "
                    f"| `{where}` | {finding.detail} |"
                )
            lines.append("")
            seen: list[PatchCategory] = []
            for finding in self.findings:
                if finding.category not in seen:
                    seen.append(finding.category)
            lines.append("Why these matter:")
            lines.append("")
            lines += [f"- `{c.value}` - {CATEGORY_RATIONALE[c]}" for c in seen]
            lines.append("")
        lines += [
            "This review reads the diff for known cheating patterns. It is a filter, "
            "not a proof of correctness: a patch it calls clean can still be wrong.",
            "",
        ]
        return "\n".join(lines)


class Diagnosis(BaseModel):
    """What is believed to be wrong, kept separate from what was observed."""

    model_config = ConfigDict(extra="forbid")

    summary: str = ""
    root_cause: str = ""
    hypothesis: str = ""
    #: Files the diagnosis implicates, workspace-relative.
    suspect_files: list[str] = Field(default_factory=list)
    confidence: str = "unstated"

    @property
    def stated(self) -> bool:
        return bool(self.summary.strip() or self.root_cause.strip())

    def render(self) -> str:
        lines = ["## Diagnosis", ""]
        lines.append(self.summary.strip() or "_No summary given._")
        lines.append("")
        if self.root_cause:
            lines += ["**Root cause.** " + self.root_cause.strip(), ""]
        if self.hypothesis:
            lines += ["**Hypothesis.** " + self.hypothesis.strip(), ""]
        if self.suspect_files:
            lines += ["Implicated files:", ""]
            lines += [f"- `{path}`" for path in self.suspect_files]
            lines.append("")
        lines += [f"Confidence: {self.confidence}.", ""]
        return "\n".join(lines)


class RepairOutcome(str, Enum):
    REPAIRED = "repaired"
    NOT_REPAIRED = "not_repaired"
    #: A patch made the tests pass by weakening them. Worse than no patch.
    REJECTED_SUSPICIOUS = "rejected_suspicious"
    NOT_REPRODUCED = "not_reproduced"
    UNAVAILABLE = "unavailable"

    @property
    def success(self) -> bool:
        return self is RepairOutcome.REPAIRED


class VerificationSummary(BaseModel):
    """A verifier outcome, flattened so a report does not depend on the engine."""

    model_config = ConfigDict(extra="forbid")

    name: str
    status: str
    summary: str = ""
    required: bool = True

    @property
    def passed(self) -> bool:
        return self.status == "passed"


class RepairReport(BaseModel):
    """The artifact every repair must produce.

    The brief lists four required parts - diagnosis, changed files, tests,
    verification result - and :meth:`missing_parts` is the machine-checkable form
    of that requirement. ``RepairVerifier`` fails a step whose report is
    incomplete, which is what "no silent modifications" means operationally.
    """

    model_config = ConfigDict(extra="forbid")

    bug: str = ""
    outcome: RepairOutcome = RepairOutcome.NOT_REPAIRED
    reproduction: Reproduction = Field(default_factory=Reproduction)
    evidence: EvidenceBundle = Field(default_factory=EvidenceBundle)
    diagnosis: Diagnosis = Field(default_factory=Diagnosis)
    review: PatchReview = Field(default_factory=PatchReview)
    #: Test files or test ids added or changed to prove the fix.
    tests: list[str] = Field(default_factory=list)
    verification: list[VerificationSummary] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def missing_parts(self) -> list[str]:
        missing = []
        if not self.diagnosis.stated:
            missing.append("diagnosis")
        if not self.review.files_changed:
            missing.append("changed files")
        if not self.tests:
            missing.append("tests")
        if not self.verification:
            missing.append("verification result")
        return missing

    @property
    def complete(self) -> bool:
        return not self.missing_parts()

    def render(self) -> str:
        lines = [
            f"# Repair report: {self.bug or 'unnamed defect'}",
            "",
            f"Outcome: **{self.outcome.value}**",
            "",
        ]
        missing = self.missing_parts()
        if missing:
            lines += [
                f"> **Incomplete report.** Missing: {', '.join(missing)}. "
                "A repair that does not state all four is a silent modification.",
                "",
            ]
        lines.append(self.reproduction.render())
        lines.append(self.diagnosis.render())
        lines.append(self.evidence.render())
        lines.append("")
        lines.append(self.review.render())

        lines += ["## Changed files", ""]
        lines += (
            [f"- `{path}`" for path in self.review.files_changed]
            if self.review.files_changed
            else ["_None recorded._"]
        )
        lines += ["", "## Tests", ""]
        lines += [f"- `{name}`" for name in self.tests] if self.tests else ["_None recorded._"]

        lines += ["", "## Verification", ""]
        if self.verification:
            lines += ["| verifier | required | status | summary |", "| --- | --- | --- | --- |"]
            for entry in self.verification:
                lines.append(
                    f"| {entry.name} | {'yes' if entry.required else 'no'} "
                    f"| {entry.status} | {entry.summary} |"
                )
        else:
            lines.append("_No verification was run._")

        if self.notes:
            lines += ["", "## Notes", ""] + [f"- {note}" for note in self.notes]

        lines += [
            "",
            "## What this report does not say",
            "",
            "It does not say the defect class is eliminated. It says one reproduction "
            "now passes, the suite is green, and the patch shows no known cheating "
            "pattern. Related inputs that were never exercised remain unverified.",
            "",
        ]
        return "\n".join(lines)
