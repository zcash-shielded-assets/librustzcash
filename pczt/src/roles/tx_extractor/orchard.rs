use orchard::{Bundle, bundle::Authorized, circuit::{OrchardCircuitVersion, VerifyingKey}};
use rand_core::OsRng;
use zcash_protocol::{consensus::BranchId, value::ZatBalance};

pub(super) fn verify_bundle(
    bundle: &Bundle<Authorized, ZatBalance>,
    orchard_vk: Option<&VerifyingKey>,
    sighash: [u8; 32],
    consensus_branch_id: BranchId,
) -> Result<(), OrchardError> {
    match orchard_vk {
        Some(vk) => verify_bundle_with_key(bundle, vk, sighash),
        None => {
            let vk = if consensus_branch_id == BranchId::Nu7 {
                VerifyingKey::build_zsa()
            } else {
                VerifyingKey::build(bundle.bundle_version().circuit_version())
            };
            verify_bundle_with_key(bundle, &vk, sighash)
        }
    }
}

fn verify_bundle_with_key(
    bundle: &Bundle<Authorized, ZatBalance>,
    vk: &VerifyingKey,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    let mut validator = orchard::bundle::BatchValidator::new(vk);
    validator
        .add_bundle(bundle, sighash)
        .map_err(|_| OrchardError::InvalidProof)?;

    if validator.validate(OsRng) {
        Ok(())
    } else {
        Err(OrchardError::InvalidProof)
    }
}

#[derive(Debug)]
pub enum OrchardError {
    Extract(orchard::pczt::TxExtractorError),
    InvalidProof,
}
