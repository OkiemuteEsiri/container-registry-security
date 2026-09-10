from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class ImageRecord:
    registry: str
    repository: str
    digest: str
    pushed_at: str
    signed: bool
    sbom_present: bool
    immutable_tag: bool
    public: bool
    critical_vulnerabilities: int
    high_vulnerabilities: int
    base_image_supported: bool
    owner: str

    def validate(self) -> None:
        if not self.registry or not self.repository or not self.digest:
            raise ValueError("registry, repository and digest are required")
        if not self.digest.startswith("sha256:"):
            raise ValueError("digest must use sha256")
        if self.critical_vulnerabilities < 0 or self.high_vulnerabilities < 0:
            raise ValueError("vulnerability counts cannot be negative")
        parse_utc(self.pushed_at)


@dataclass(frozen=True)
class Finding:
    control_id: str
    severity: str
    resource: str
    title: str
    evidence: str
    remediation: str
    attack_techniques: tuple[str, ...] = ()

    def validate(self) -> None:
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
        if not self.control_id or not self.resource:
            raise ValueError("control_id and resource are required")


def validate_unique_images(images: Iterable[ImageRecord]) -> list[ImageRecord]:
    validated = list(images)
    seen: set[tuple[str, str, str]] = set()
    for image in validated:
        image.validate()
        key = (image.registry, image.repository, image.digest)
        if key in seen:
            raise ValueError(f"duplicate image identity: {key}")
        seen.add(key)
    return validated
