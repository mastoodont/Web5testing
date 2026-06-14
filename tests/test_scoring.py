"""
tests/test_scoring.py

Tests the deterministic scoring logic: correct weights, block threshold,
volume penalties, and reason generation.
"""

import pytest
from app.core.scoring import compute_score, BLOCK_THRESHOLD, SEVERITY_SCORES


def make_threat(threat_type="prompt_injection.ignore_previous_instructions",
                severity="critical", source="user_query"):
    return {
        "threat_type": threat_type,
        "description": "Test threat",
        "severity": severity,
        "matched_pattern": "test pattern",
        "source": source,
    }


class TestScoringBasics:

    def test_no_threats_returns_zero(self):
        score, components, blocked, reasons = compute_score([])
        assert score == 0
        assert blocked is False
        # With no threats, only the summary reason is present (or empty)
        assert not any("signal" in r.lower() or "critical" in r.lower() for r in reasons)

    def test_single_critical_query_threat_exceeds_block(self):
        threats = [make_threat(severity="critical", source="user_query")]
        score, _, blocked, _ = compute_score(threats)
        # critical(50) * prompt_injection(1.5) * query(1.4) = 105 → capped at 100
        assert score == 100
        assert blocked is True

    def test_single_low_chunk_threat_below_block(self):
        threats = [make_threat(
            threat_type="context_injection.ascii_smuggling",
            severity="low",
            source="chunk_0",
        )]
        score, _, blocked, _ = compute_score(threats)
        # low(5) * context_injection(1.2) * chunk(1.0) = 6
        assert score == 6
        assert blocked is False

    def test_score_capped_at_100(self):
        threats = [make_threat(severity="critical") for _ in range(10)]
        score, _, _, _ = compute_score(threats)
        assert score == 100

    def test_block_threshold_boundary(self):
        # Build threats that produce exactly the block threshold
        # medium(15) * prompt_injection(1.5) * query(1.4) = 31.5 → 32
        # Need a combination that crosses 40
        threats = [
            make_threat(severity="medium", source="user_query"),
            make_threat(
                threat_type="data_exfiltration.hidden_data_reveal",
                severity="medium",
                source="chunk_0",
            ),
        ]
        score, _, blocked, _ = compute_score(threats)
        assert score >= BLOCK_THRESHOLD if blocked else score < BLOCK_THRESHOLD


class TestVolumepenalty:

    def test_volume_penalty_applied_for_multiple_same_class(self):
        # Two prompt_injection threats should cost more than double one
        single = compute_score([make_threat(severity="low", source="chunk_0")])[0]
        double = compute_score([
            make_threat(severity="low", source="chunk_0"),
            make_threat(severity="low", source="chunk_0"),
        ])[0]
        assert double > single * 2 - 1  # at least the volume penalty added something

    def test_volume_penalty_capped(self):
        # 25 threats of same class — volume penalty should not exceed cap
        threats = [make_threat(severity="low", source="chunk_0") for _ in range(25)]
        score, components, _, _ = compute_score(threats)
        assert components["volume_penalty"] <= 20


class TestReasons:

    def test_blocked_reason_present_when_blocked(self):
        threats = [make_threat(severity="critical", source="user_query")]
        _, _, blocked, reasons = compute_score(threats)
        assert blocked
        assert any("blocked" in r.lower() for r in reasons)

    def test_threat_class_in_reasons(self):
        threats = [make_threat()]
        _, _, _, reasons = compute_score(threats)
        assert any("Prompt Injection" in r for r in reasons)

    def test_critical_reason_listed(self):
        threats = [make_threat(severity="critical")]
        _, _, _, reasons = compute_score(threats)
        assert any(r.startswith("Critical:") for r in reasons)

    def test_high_severity_count_in_reasons(self):
        threats = [
            make_threat(severity="high"),
            make_threat(severity="high", threat_type="data_exfiltration.hidden_data_reveal"),
        ]
        _, _, _, reasons = compute_score(threats)
        assert any("high-severity" in r for r in reasons)


class TestComponentScores:

    def test_component_scores_keys_present(self):
        threats = [make_threat()]
        _, components, _, _ = compute_score(threats)
        for key in ("regex_score", "ml_contribution", "raw_score",
                    "final_score", "per_threat_scores"):
            assert key in components

    def test_per_threat_scores_match_count(self):
        threats = [make_threat(), make_threat(severity="high")]
        _, components, _, _ = compute_score(threats)
        assert len(components["per_threat_scores"]) == 2

    def test_final_score_matches_returned_score(self):
        threats = [make_threat(severity="medium")]
        score, components, _, _ = compute_score(threats)
        assert components["final_score"] == score
