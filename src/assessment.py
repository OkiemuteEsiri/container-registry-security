from __future__ import annotations

from datetime import datetime, timezone
from .models import Finding, ImageRecord, parse_utc, validate_unique_images

SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 7, "critical": 10}


def _resource(image: ImageRecord) -> str:
    return f"{image.registry}/{image.repository}@{image.digest[:19]}"


def assess_image(image: ImageRecord, now: datetime | None = None) -> list[Finding]:
    image.validate()
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []
    resource = _resource(image)

    def add(control: str, severity: str, title: str, evidence: str, remediation: str, techniques=()):
        finding = Finding(control, severity, resource, title, evidence, remediation, tuple(techniques))
        finding.validate()
        findings.append(finding)

    if image.public:
        add("REG-001", "high", "Registry image is publicly accessible", "public=true", "Restrict repository visibility and validate intended consumers.", ("T1195.002",))
    if not image.signed:
        add("REG-002", "high", "Image lacks trusted signature", "signed=false", "Sign release images and enforce signature verification at admission/deployment.", ("T1195.002",))
    if not image.sbom_present:
        add("REG-003", "medium", "SBOM is missing", "sbom_present=false", "Generate and retain an SBOM for each immutable digest.")
    if not image.immutable_tag:
        add("REG-004", "medium", "Tag mutability is permitted", "immutable_tag=false", "Enable immutable release tags and deploy by digest.", ("T1195.002",))
    if image.critical_vulnerabilities > 0:
        add("REG-005", "critical", "Critical vulnerabilities present", f"critical_vulnerabilities={image.critical_vulnerabilities}", "Rebuild from remediated packages/base image, rescan, and replace the affected digest.", ("T1190",))
    elif image.high_vulnerabilities >= 5:
        add("REG-006", "high", "High vulnerability concentration", f"high_vulnerabilities={image.high_vulnerabilities}", "Prioritize package/base-image remediation and rescan before promotion.", ("T1190",))
    if not image.base_image_supported:
        add("REG-007", "high", "Unsupported base image", "base_image_supported=false", "Migrate to a supported minimal base image and rebuild.")
    if not image.owner.strip():
        add("REG-008", "medium", "Image ownership is undefined", "owner is empty", "Assign an accountable service owner and remediation queue.")
    age_days = (now - parse_utc(image.pushed_at)).days
    if age_days > 180:
        add("REG-009", "medium", "Stale image exceeds review window", f"age_days={age_days}", "Confirm active use, rebuild on a current base, or retire the artifact.")
    return findings


def assess(images: list[ImageRecord], now: datetime | None = None) -> dict:
    images = validate_unique_images(images)
    findings = [finding for image in images for finding in assess_image(image, now)]
    total_weight = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    posture_score = max(0, round(100 - min(100, total_weight * 2.5)))
    counts = {severity: sum(f.severity == severity for f in findings) for severity in SEVERITY_WEIGHT}
    return {"images_assessed": len(images), "finding_count": len(findings), "severity_counts": counts, "posture_score": posture_score, "findings": findings}
