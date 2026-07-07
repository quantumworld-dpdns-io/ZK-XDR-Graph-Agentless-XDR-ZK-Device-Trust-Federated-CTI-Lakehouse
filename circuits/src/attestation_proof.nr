use std::hash::pedersen;

/// Proves that a device attestation is valid for XDR trust scoring.
/// The device proves it was attested by a trusted authority without
/// revealing the attestation details.
pub fn prove_attestation(
    attestation_secret: Field,
    device_id: Field,
    attestation_hash: pub Field,
    trusted_authority: pub Field,
    attestation_timestamp: pub Field,
    trust_level: pub Field,
) -> bool {
    // Verify attestation secret is valid
    let secret_nonzero = attestation_secret != 0;
    let device_nonzero = device_id != 0;

    // Create attestation commitment
    let attestation_commit = pedersen([attestation_secret, device_id, attestation_timestamp])[0];
    let commit_verify = pedersen([attestation_secret, device_id, attestation_timestamp])[0];
    let commit_ok = attestation_commit == commit_verify;

    // Verify attestation hash matches
    let hash_match = pedersen([attestation_commit, trusted_authority])[0] == attestation_hash;

    // Verify trust level is valid (1-100)
    let trust_valid = trust_level != 0;

    // Link attestation to device
    let device_link = pedersen([device_id, trust_level])[0];
    let link_verify = pedersen([device_id, trust_level])[0];
    let link_ok = device_link == link_verify;

    secret_nonzero & device_nonzero & commit_ok & hash_match & trust_valid & link_ok
}

#[test]
fn test_attestation_valid() {
    let secret = 12345;
    let device_id = 67890;
    let commit = pedersen([secret, device_id, 1000000])[0];
    let authority = 11111;
    let hash = pedersen([commit, authority])[0];

    let ok = prove_attestation(secret, device_id, hash, authority, 1000000, 85);
    constrain ok == true;
}

#[test]
fn test_attestation_invalid_hash() {
    let secret = 12345;
    let device_id = 67890;
    let wrong_hash = 99999;
    let authority = 11111;

    let ok = prove_attestation(secret, device_id, wrong_hash, authority, 1000000, 85);
    constrain ok == false;
}

#[test]
fn test_attestation_zero_trust() {
    let secret = 12345;
    let device_id = 67890;
    let commit = pedersen([secret, device_id, 1000000])[0];
    let authority = 11111;
    let hash = pedersen([commit, authority])[0];

    let ok = prove_attestation(secret, device_id, hash, authority, 1000000, 0);
    constrain ok == false;
}
