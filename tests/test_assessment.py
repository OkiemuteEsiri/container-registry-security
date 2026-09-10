import unittest
from datetime import datetime, timezone

from src.assessment import assess, assess_image
from src.models import ImageRecord


NOW = datetime(2026, 9, 10, tzinfo=timezone.utc)


def image(**overrides):
    base = dict(
        registry="registry.example.internal",
        repository="service",
        digest="sha256:" + "a" * 64,
        pushed_at="2026-09-01T00:00:00Z",
        signed=True,
        sbom_present=True,
        immutable_tag=True,
        public=False,
        critical_vulnerabilities=0,
        high_vulnerabilities=0,
        base_image_supported=True,
        owner="team-a",
    )
    base.update(overrides)
    return ImageRecord(**base)


class AssessmentTests(unittest.TestCase):
    def test_secure_image_has_no_findings(self):
        self.assertEqual([], assess_image(image(), NOW))

    def test_public_unsigned_image_generates_supply_chain_findings(self):
        findings = assess_image(image(public=True, signed=False), NOW)
        ids = {f.control_id for f in findings}
        self.assertIn("REG-001", ids)
        self.assertIn("REG-002", ids)

    def test_critical_vulnerability_is_critical(self):
        findings = assess_image(image(critical_vulnerabilities=1), NOW)
        finding = next(f for f in findings if f.control_id == "REG-005")
        self.assertEqual("critical", finding.severity)

    def test_high_concentration_rule_applies_without_critical(self):
        ids = {f.control_id for f in assess_image(image(high_vulnerabilities=6), NOW)}
        self.assertIn("REG-006", ids)

    def test_stale_image_is_detected(self):
        ids = {f.control_id for f in assess_image(image(pushed_at="2025-01-01T00:00:00Z"), NOW)}
        self.assertIn("REG-009", ids)

    def test_duplicate_image_identity_rejected(self):
        with self.assertRaises(ValueError):
            assess([image(), image()], NOW)

    def test_invalid_digest_rejected(self):
        with self.assertRaises(ValueError):
            assess_image(image(digest="latest"), NOW)

    def test_posture_score_decreases_with_findings(self):
        secure = assess([image()], NOW)
        risky = assess([image(public=True, signed=False, critical_vulnerabilities=1)], NOW)
        self.assertGreater(secure["posture_score"], risky["posture_score"])


if __name__ == "__main__":
    unittest.main()
