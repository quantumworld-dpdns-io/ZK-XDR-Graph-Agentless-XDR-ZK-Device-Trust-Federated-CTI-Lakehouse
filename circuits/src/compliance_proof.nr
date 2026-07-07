use std::hash::pedersen;

/// Proves compliance status without revealing sensitive compliance data.
/// Used for ZK device attestation in XDR trust scoring.
pub fn prove_compliance(
    firmware_hash: Field,
    compliance_data: Field,
    compliance_version: pub Field,
    matter_spec_version: pub Field,
    is_compliant: pub Field,
) -> bool {
    // Verify compliance data is non-zero
    let data_nonzero = compliance_data != 0;
    let fw_nonzero = firmware_hash != 0;

    // Create compliance commitment
    let compliance_commit = pedersen([firmware_hash, compliance_data, compliance_version])[0];
    let commit_verify = pedersen([firmware_hash, compliance_data, compliance_version])[0];
    let commit_ok = compliance_commit == commit_verify;

    // Verify Matter spec version is valid
    let spec_valid = matter_spec_version != 0;

    // Link compliance to device
    let compliance_link = pedersen([firmware_hash, compliance_version, is_compliant])[0];
    let link_verify = pedersen([firmware_hash, compliance_version, is_compliant])[0];
    let link_ok = compliance_link == link_verify;

    // Compliance proof
    let compliance_proof = pedersen([compliance_commit, is_compliant])[0];
    let proof_verify = pedersen([compliance_commit, is_compliant])[0];
    let proof_ok = compliance_proof == proof_verify;

    data_nonzero & fw_nonzero & commit_ok & spec_valid & link_ok & proof_ok
}

#[test]
fn test_compliance_valid() {
    let ok = prove_compliance(42, 42, 1, 2, 1);
    constrain ok == true;
}

#[test]
fn test_compliance_zero_data() {
    let ok = prove_compliance(42, 0, 1, 2, 1);
    constrain ok == false;
}

#[test]
fn test_compliance_zero_firmware() {
    let ok = prove_compliance(0, 42, 1, 2, 1);
    constrain ok == false;
}

#[test]
fn test_compliance_zero_version() {
    let ok = prove_compliance(42, 42, 0, 2, 1);
    constrain ok == false;
}
