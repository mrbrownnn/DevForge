"""A runtime that drives any external agent CLI described by a profile.

One implementation, many providers. The differences between agent CLIs are a
subcommand, a flag name and an output format - all of which are data
(:mod:`devforge.runtime.cli_profile`), so this class holds the parts that are
genuinely the same: spawn with a timeout, bound the output, parse a result, and be
honest about what happened.

Three behaviours are worth stating, because each is a place where an adapter can
quietly lie about a run:

**A missing binary is unavailable, never a failure of the agent.** ``devforge
doctor`` reports it as not installed; a run refuses to start rather than producing an
``AgentResult`` that looks like the model declined.

**An unverified invocation shape says so.** A profile whose flags have not been
exercised here still runs, but ``availability()`` reports the difference. A wrong
flag produces an error from somebody else's binary, which otherwise reads as DevForge
being broken.

**Token counts that the tool does not report stay ``None``.** Not zero. The evaluation
layer distinguishes "no tokens were used" from "nobody measured", and collapsing them
would put a fabricated number in a cost report.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from typing import Any

from devforge.core.errors import RuntimeExecutionError
from devforge.core.models import AgentInvocation, AgentResult, AgentResultStatus
from devforge.runtime.base import AgentRuntime, RuntimeAvailability, RuntimeContext
from devforge.runtime.capabilities import Capability, RuntimeCapabilities
from devforge.runtime.cli_profile import CliRuntimeProfile, OutputFormat

MAX_OUTPUT_CHARS = 200_000
VERSION_TIMEOUT_S = 20


class ExternalCliRuntime(AgentRuntime):
    """Executes an agent by running an external CLI described by a profile."""

    def __init__(self, profile: CliRuntimeProfile, *, model: str | None = None) -> None:
        self.profile = profile
        self.name = profile.id
        self.model = model

    def describe(self) -> str:
        return self.profile.description or self.profile.name

    # -- capabilities -----------------------------------------------------------

    def capabilities(self) -> RuntimeCapabilities:
        """What the adapter actually drives, not what the tool can do.

        Only ``TOOLS`` is claimed: the CLI runs its own tools inside a turn, outside
        DevForge's policy engine. Structured output is claimed only when the profile
        asks for a machine-readable format, because otherwise the adapter is parsing
        prose and should not pretend otherwise.
        """
        status = self.availability()
        capabilities = {Capability.TOOLS}
        if self.profile.output.format is OutputFormat.JSON:
            capabilities.add(Capability.STRUCTURED_OUTPUT)

        note = (
            "Billed model calls. The CLI executes its own tools inside a turn, so "
            "those calls are governed by that tool's permission system rather than "
            "by DevForge policy."
        )
        if not self.profile.confidence.trustworthy:
            note += (
                f" The invocation shape for this profile is '{self.profile.confidence.value}' "
                "and has not been exercised by DevForge."
            )

        return RuntimeCapabilities(
            name=self.name,
            version=status.version or "unknown",
            capabilities=capabilities,
            notes=note,
        )

    # -- availability -----------------------------------------------------------

    def _resolve_binary(self) -> str | None:
        return shutil.which(self.profile.binary)

    def availability(self) -> RuntimeAvailability:
        path = self._resolve_binary()
        if path is None:
            return RuntimeAvailability(
                available=False,
                detail=f"'{self.profile.binary}' not found on PATH - install {self.profile.name}",
            )

        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv from a validated profile
                [path, *self.profile.version_args],
                capture_output=True,
                text=True,
                timeout=VERSION_TIMEOUT_S,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return RuntimeAvailability(available=False, detail=f"could not run '{path}': {exc}")

        if proc.returncode != 0:
            return RuntimeAvailability(
                available=False,
                detail=(
                    f"'{path} {' '.join(self.profile.version_args)}' exited "
                    f"{proc.returncode}"
                ),
            )

        detail = path
        if not self.profile.confidence.trustworthy:
            detail += f" (invocation shape: {self.profile.confidence.value}, unverified here)"
        return RuntimeAvailability(
            available=True, detail=detail, version=proc.stdout.strip().splitlines()[0][:80]
        )

    # -- execution --------------------------------------------------------------

    async def execute(self, invocation: AgentInvocation, context: RuntimeContext) -> AgentResult:
        binary = self._resolve_binary()
        if binary is None:
            raise RuntimeExecutionError(
                f"runtime '{self.name}' is unavailable: {self.availability().detail}"
            )

        argv, stdin_body = self.profile.build_argv(
            binary,
            invocation.prompt,
            model=self.model,
            system_prompt=invocation.system_prompt,
        )

        context.logger.info(
            "runtime.invoke",
            runtime=self.name,
            agent=invocation.agent,
            step=invocation.step_id,
            attempt=invocation.attempt,
            mode=invocation.mode.value,
            confidence=self.profile.confidence.value,
        )

        started = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(context.workspace),
                stdin=asyncio.subprocess.PIPE if stdin_body else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:  # the binary vanished between the check and the spawn
            raise RuntimeExecutionError(f"failed to start '{binary}': {exc}") from exc

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(stdin_body.encode("utf-8") if stdin_body else None),
                timeout=invocation.timeout_s,
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            return AgentResult(
                invocation_id=invocation.invocation_id,
                runtime=self.name,
                status=AgentResultStatus.ERROR,
                summary="runtime timed out",
                error=f"'{self.profile.binary}' exceeded the {invocation.timeout_s}s timeout",
                duration_ms=int((time.monotonic() - started) * 1000),
            )

        return self.parse_result(
            invocation,
            stdout=stdout_bytes.decode("utf-8", errors="replace")[:MAX_OUTPUT_CHARS],
            stderr=stderr_bytes.decode("utf-8", errors="replace")[:MAX_OUTPUT_CHARS],
            returncode=process.returncode or 0,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    # -- parsing ----------------------------------------------------------------

    def parse_result(
        self,
        invocation: AgentInvocation,
        *,
        stdout: str,
        stderr: str,
        returncode: int,
        duration_ms: int,
    ) -> AgentResult:
        """Turn the process outcome into a structured result.

        A non-zero exit is an error even when stdout parses: the tool said it failed,
        and believing the payload over the exit code is how a failed run gets recorded
        as a successful one.
        """
        spec = self.profile.output
        ok = returncode in spec.success_exit_codes

        payload: dict[str, Any] | None = None
        if spec.format is OutputFormat.JSON:
            payload = _parse_json(stdout)

        output = stdout.strip()
        error = ""
        metadata: dict[str, Any] = {
            "exit_code": returncode,
            "profile_confidence": self.profile.confidence.value,
        }

        if payload is not None:
            output = _first(payload, spec.text_keys) or output
            error = _first(payload, spec.error_keys) or ""
            session = _first(payload, spec.session_keys)
            if session:
                metadata["session_id"] = session
            tokens = _first_int(payload, spec.token_keys)
            # Absent stays absent. The evaluation layer reads None as "unmeasured".
            if tokens is not None:
                metadata["total_tokens"] = tokens
        elif spec.format is OutputFormat.JSON and ok:
            # The profile promised JSON and the tool produced something else. That is
            # a profile problem, and saying so beats silently treating prose as a result.
            error = (
                f"expected JSON from '{self.profile.binary}' but could not parse it; "
                f"the '{self.profile.id}' profile may declare the wrong output format"
            )
            ok = False

        if not ok and not error:
            error = stderr.strip() or f"'{self.profile.binary}' exited {returncode}"

        return AgentResult(
            invocation_id=invocation.invocation_id,
            runtime=self.name,
            status=AgentResultStatus.OK if ok else AgentResultStatus.ERROR,
            summary=_summarise(output) if ok else "runtime reported a failure",
            output=output,
            error=error,
            duration_ms=duration_ms,
            metadata=metadata,
        )


def _parse_json(stdout: str) -> dict[str, Any] | None:
    """Parse a JSON document, or the last JSON object of a JSON-lines stream.

    Several tools emit one JSON object per event and put the result last. Trying the
    whole document first and falling back to the final line handles both without the
    profile having to describe which.
    """
    text = stdout.strip()
    if not text:
        return None
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {"result": value}
    except json.JSONDecodeError:
        pass

    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _first(payload: dict[str, Any], keys: list[str]) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
        if isinstance(value, dict | list) and value:
            return json.dumps(value)
    return ""


def _first_int(payload: dict[str, Any], keys: list[str]) -> int | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, dict):
            nested = _first_int(value, keys)
            if nested is not None:
                return nested
    # Usage totals are commonly nested one level down under a container key.
    usage = payload.get("usage")
    if isinstance(usage, dict):
        return _first_int(usage, keys)
    return None


def _summarise(output: str, limit: int = 200) -> str:
    text = " ".join(output.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def runtime_factories(project_root: Any = None) -> dict[str, Any]:
    """Name -> zero-argument factory, for every discovered CLI profile.

    Returned as factories so that constructing one - which probes the filesystem -
    is deferred until a run actually needs it, matching how the registry treats the
    runtimes it already knows.
    """
    from devforge.runtime.cli_profile import discover_profiles

    def make(profile: CliRuntimeProfile):
        return lambda: ExternalCliRuntime(profile)

    return {profile.id: make(profile) for profile in discover_profiles(project_root)}
