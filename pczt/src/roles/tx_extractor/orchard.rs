use orchard::{Bundle, bundle::Authorized, circuit::VerifyingKey};
use rand_core::OsRng;
use zcash_protocol::value::ZatBalance;

pub(super) fn verify_bundle(
    bundle: &Bundle<Authorized, ZatBalance>,
    orchard_vk: Option<&VerifyingKey>,
    sighash: [u8; 32],
) -> Result<(), OrchardError> {
    let is_zsa = bundle.bundle_version().is_zsa();
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
        #[cfg(feature = "zsa")]
        let enable_zsa = bundle.flags().zsa_enabled();
        #[cfg(not(feature = "zsa"))]
        let enable_zsa = false;
        validator.add_bundle_zsa(bundle, sighash, enable_zsa);
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
