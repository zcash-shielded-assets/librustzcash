use orchard::{Bundle, bundle::Authorized, circuit::{OrchardCircuitVersion, VerifyingKey}};
use rand_core::OsRng;
use zcash_protocol::{consensus::BranchId, value::ZatBalance};

pub(super) fn verify_bundle(
    bundle: &Bundle<Authorized, ZatBalance>,
    orchard_vk: Option<&VerifyingKey>,
    sighash: [u8; 32],
    consensus_branch_id: BranchId,
) -> Result<(), OrchardError> {
    let is_zsa = consensus_branch_id == BranchId::Nu7;
    match orchard_vk {
        Some(vk) => verify_bundle_with_key(bundle, vk, sighash, is_zsa),
        None => {
            let vk = if is_zsa {
                VerifyingKey::build_zsa()
            } else {
                VerifyingKey::build(bundle.bundle_version().circuit_version())
            };
            verify_bundle_with_key(bundle, &vk, sighash, is_zsa)
        }
    }
}

fn verify_bundle_with_key(
    bundle: &Bundle<Authorized, ZatBalance>,
    vk: &VerifyingKey,
    sighash: [u8; 32],
    is_zsa: bool,
) -> Result<(), OrchardError> {
    let mut validator = orchard::bundle::BatchValidator::new(vk);
    if is_zsa {
        validator
            .add_bundle_zsa(bundle, sighash)
            .map_err(|_| OrchardError::InvalidProof)?;
    } else {
        validator
            .add_bundle(bundle, sighash)
            .map_err(|_| OrchardError::InvalidProof)?;
    }

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
