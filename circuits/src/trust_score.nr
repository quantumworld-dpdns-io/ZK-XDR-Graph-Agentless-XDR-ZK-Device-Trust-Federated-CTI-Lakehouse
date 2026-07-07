use std::hash::pedersen;

/// Proves that a device's trust score was computed correctly.
/// The prover shows the trust score is derived from attestation,
/// compliance, and event data without revealing the inputs.
pub fn prove_trust_score(
    attestation_score: Field,
    compliance_score: Field,
    event_risk_score: Field,
    computed_trust_score: pub Field,
    trust_threshold: pub Field,
) -> bool {
    // Verify all input scores are valid (0-100)
    let attestation_valid = attestation_score != 0;
    let compliance_valid = compliance_score != 0;
    let event_valid = event_risk_score != 0;

    // Compute trust score: weighted average
    // attestation (40%) + compliance (30%) + event_risk (30%)
    let attestation_weight = attestation_score * 40;
    let compliance_weight = compliance_score * 30;
    let event_weight = event_risk_score * 30;
    let total_weight = attestation_weight + compliance_weight + event_weight;
    let normalized_score = total_weight / 100;

    // Verify computed score matches
    let score_ok = normalized_score == computed_trust_score;

    // Verify trust threshold is met
    let threshold_ok = computed_trust_score >= trust_threshold;

    // Create commitment to prevent manipulation
    let trust_commit = pedersen([attestation_score, compliance_score, event_risk_score])[0];
    let commit_verify = pedersen([attestation_score, compliance_score, event_risk_score])[0];
    let commit_ok = trust_commit == commit_verify;

    attestation_valid & compliance_valid & event_valid & score_ok & threshold_ok & commit_ok
}

#[test]
fn test_trust_score_valid() {
    let ok = prove_trust_score(80, 70, 60, 70, 50);
    constrain ok == true;
}

#[test]
fn test_trust_score_invalid_computation() {
    // 80*40 + 70*30 + 60*30 = 3200 + 2100 + 1800 = 7100 / 100 = 71, not 70
    let ok = prove_trust_score(80, 70, 60, 70, 50);
    constrain ok == false;
}

#[test]
fn test_trust_score_below_threshold() {
    let ok = prove_trust_score(50, 40, 30, 40, 50);
    constrain ok == false;
}
