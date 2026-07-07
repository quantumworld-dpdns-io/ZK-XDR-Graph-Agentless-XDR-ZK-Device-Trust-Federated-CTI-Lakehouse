mod device_identity;
mod compliance_proof;
mod attestation_proof;
mod trust_score;

use crate::device_identity::prove_device_identity;
use crate::compliance_proof::prove_compliance;
use crate::attestation_proof::prove_attestation;
use crate::trust_score::prove_trust_score;

global SELECTOR_DEVICE_IDENTITY: Field = 1;
global SELECTOR_COMPLIANCE: Field = 2;
global SELECTOR_ATTESTATION: Field = 3;
global SELECTOR_TRUST_SCORE: Field = 4;

fn main(
    selector: Field,
    // Device identity inputs
    device_secret: Field,
    hw_fingerprint: Field,
    device_public_key: pub Field,
    device_type: pub Field,
    firmware_version: pub Field,
    // Compliance inputs
    firmware_hash: Field,
    compliance_data: Field,
    compliance_version: pub Field,
    matter_spec_version: pub Field,
    is_compliant: pub Field,
    // Attestation inputs
    attestation_secret: Field,
    device_id: Field,
    attestation_hash: pub Field,
    trusted_authority: pub Field,
    attestation_timestamp: pub Field,
    trust_level: pub Field,
    // Trust score inputs
    attestation_score: Field,
    compliance_score: Field,
    event_risk_score: Field,
    computed_trust_score: pub Field,
    trust_threshold: pub Field,
) {
    let selector_match = (selector == SELECTOR_DEVICE_IDENTITY)
        | (selector == SELECTOR_COMPLIANCE)
        | (selector == SELECTOR_ATTESTATION)
        | (selector == SELECTOR_TRUST_SCORE);
    constrain selector_match == true;

    let ok = if selector == SELECTOR_DEVICE_IDENTITY {
        prove_device_identity(device_secret, hw_fingerprint, device_public_key, device_type, firmware_version)
    } else {
        if selector == SELECTOR_COMPLIANCE {
            prove_compliance(firmware_hash, compliance_data, compliance_version, matter_spec_version, is_compliant)
        } else {
            if selector == SELECTOR_ATTESTATION {
                prove_attestation(attestation_secret, device_id, attestation_hash, trusted_authority, attestation_timestamp, trust_level)
            } else {
                if selector == SELECTOR_TRUST_SCORE {
                    prove_trust_score(attestation_score, compliance_score, event_risk_score, computed_trust_score, trust_threshold)
                } else {
                    false
                }
            }
        }
    };
    constrain ok == true;
}

#[test]
fn test_selector_device_identity() {
    let secret = 12345;
    let pub_key = std::hash::pedersen([secret])[0];
    main(
        SELECTOR_DEVICE_IDENTITY,
        secret,
        67890,
        pub_key,
        1,
        3,
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    );
}

#[test]
fn test_selector_compliance() {
    main(
        SELECTOR_COMPLIANCE,
        0, 0, 0, 0, 0,
        42,
        42,
        1,
        2,
        1,
        0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    );
}

#[test]
fn test_selector_attestation() {
    let secret = 12345;
    let device_id = 67890;
    let commit = std::hash::pedersen([secret, device_id, 1000000])[0];
    let authority = 11111;
    let hash = std::hash::pedersen([commit, authority])[0];
    main(
        SELECTOR_ATTESTATION,
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
        secret,
        device_id,
        hash,
        authority,
        1000000,
        85,
        0, 0, 0, 0, 0,
    );
}

#[test]
fn test_selector_trust_score() {
    main(
        SELECTOR_TRUST_SCORE,
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
        80,
        70,
        60,
        70,
        50,
    );
}
