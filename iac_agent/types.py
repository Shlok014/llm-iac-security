"""Shared types and errors.

The important design decision here is that scanner failure is an *exception*, not a
value. The original implementation returned a success-shaped dict when Checkov produced
no output, which meant a scanner that never ran was reported as "no issues found". Every
failure path in this package must be impossible to mistake for a clean result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class IaCType(str, Enum):
    TERRAFORM = "terraform"
    DOCKERFILE = "dockerfile"

    @property
    def checkov_framework(self) -> str:
        return self.value

    @property
    def output_name(self) -> str:
        """Filename a remediated file must be written under.

        Load-bearing: both Checkov and Trivy select their Dockerfile rules by *filename*.
        Writing a remediated Dockerfile to `fixed.tf` (as the original code did) makes the
        scanner apply Terraform rules to it, find nothing, and report a clean pass.
        """
        return "fixed.tf" if self is IaCType.TERRAFORM else "Dockerfile"

    @property
    def fence_tags(self) -> tuple[str, ...]:
        if self is IaCType.TERRAFORM:
            return ("hcl", "terraform", "tf")
        return ("dockerfile", "docker")


class IaCAgentError(Exception):
    """Base for every error this package raises."""


class ScannerError(IaCAgentError):
    """A scanner could not be run, or produced output we cannot trust.

    Never catch this and substitute an empty finding list — that reintroduces the
    fail-open bug this package exists to eliminate.
    """


class LLMError(IaCAgentError):
    """The model call failed. Deliberately not returned as a string."""


class UnsupportedFileError(IaCAgentError):
    """The input is not a file type we can route to a scanner."""


@dataclass(frozen=True)
class Finding:
    """One normalised scanner finding, comparable across Checkov and Trivy."""

    rule_id: str
    severity: str
    resource: str
    message: str
    scanner: str
    file: str = ""
    line: int | None = None
    guideline: str = ""

    def key(self) -> tuple[str, str]:
        """Identity for set arithmetic (before/after deltas)."""
        return (self.rule_id, self.resource)


@dataclass
class ScanResult:
    """Outcome of scanning one file with one scanner."""

    scanner: str
    target: Path
    iac_type: IaCType
    failed: list[Finding] = field(default_factory=list)
    passed_count: int = 0
    parse_errors: int = 0

    @property
    def failed_count(self) -> int:
        return len(self.failed)

    @property
    def parsed_cleanly(self) -> bool:
        return self.parse_errors == 0

    def keys(self) -> set[tuple[str, str]]:
        return {f.key() for f in self.failed}


def detect_iac_type(path: str | Path) -> IaCType:
    """Route a file to its IaC type by name.

    Dockerfiles are matched by filename rather than extension because that is what the
    scanners themselves do.
    """
    p = Path(path)
    name = p.name.lower()
    if p.suffix == ".tf" or name.endswith(".tf"):
        return IaCType.TERRAFORM
    if "dockerfile" in name:
        return IaCType.DOCKERFILE
    raise UnsupportedFileError(
        f"Cannot determine IaC type for {p.name!r}. "
        "Supported: *.tf (Terraform) and Dockerfile / *.Dockerfile."
    )
