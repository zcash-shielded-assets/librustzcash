//! The Transaction Extractor role (anyone can execute).
//!
//! - Creates bindingSig and extracts the final transaction.

use core::marker::PhantomData;
use rand_core::OsRng;

use zcash_primitives::transaction::{
    Authorization, OrchardBundle, Transaction,
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};

use crate::Pczt;

mod orchard;
pub use self::orchard::OrchardError;
pub type IronwoodError = OrchardError;

mod sapling;
pub use self::sapling::SaplingError;

mod transparent;
pub use self::transparent::TransparentError;

pub struct TransactionExtractor<'a> {
    pczt: Pczt,
    sapling_vk: Option<(
        &'a ::sapling::circuit::SpendVerifyingKey,
        &'a ::sapling::circuit::OutputVerifyingKey,
    )>,
    orchard_vk: Option<&'a ::orchard::circuit::VerifyingKey>,
    _unused: PhantomData<&'a ()>,
}

impl<'a> TransactionExtractor<'a> {
    /// Instantiates the Transaction Extractor role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self {
            pczt,
            sapling_vk: None,
            orchard_vk: None,
            _unused: PhantomData,
        }
    }

    /// Provides the Sapling Spend and Output verifying keys for validating the Sapling
    /// proofs (if any).
    ///
    /// If not provided, and the PCZT has a Sapling bundle, [`Self::extract`] will return
    /// an error.
    pub fn with_sapling(
        mut self,
        spend_vk: &'a ::sapling::circuit::SpendVerifyingKey,
        output_vk: &'a ::sapling::circuit::OutputVerifyingKey,
    ) -> Self {
        self.sapling_vk = Some((spend_vk, output_vk));
        self
    }

    /// Provides an existing Orchard verifying key for validating the Orchard proof (if
    /// any).
    ///
    /// If not provided, and the PCZT has an Orchard bundle, an Orchard verifying key will
    /// be generated on the fly.
    pub fn with_orchard(mut self, orchard_vk: &'a ::orchard::circuit::VerifyingKey) -> Self {
        self.orchard_vk = Some(orchard_vk);
        self
    }

    /// Attempts to extract a valid transaction from the PCZT.
    pub fn extract(self) -> Result<Transaction, Error> {
        let Self {
            pczt,
            sapling_vk,
            orchard_vk,
            _unused,
        } = self;

        // Save the signed issue bundle before extraction (Nu7/ZSA).
        // The Issuer Phase 2 should have already signed it.
        #[cfg(feature = "zsa")]
        let saved_signed_issue = pczt.issue.to_signed();
        #[cfg(feature = "zsa")]
        let consensus_branch_id =
            zcash_protocol::consensus::BranchId::try_from(pczt.global.consensus_branch_id)
                .map_err(|_| crate::ExtractError::UnknownConsensusBranchId)
                .map_err(Error::Extract)?;

        let crate::ParsedPczt { tx_data, .. } = pczt.extract_tx_data::<Unbound, Error>(
            |t| {
                t.extract()
                    .map_err(|e| Error::Transparent(TransparentError::Extract(e)))
            },
            |s| {
                s.extract()
                    .map_err(|e| Error::Sapling(SaplingError::Extract(e)))
            },
            |o| {
                o.extract()
                    .map_err(|e| Error::Orchard(OrchardError::Extract(e)))
            },
            |i| {
                i.extract()
                    .map_err(|e| Error::Ironwood(IronwoodError::Extract(e)))
            },
            #[cfg(feature = "zsa")]
            |issue| Ok(issue.to_effects()),
            #[cfg(feature = "zsa")]
            |_o| Ok(None), // ZSA orchard extraction — not yet implemented
        )?;

        // The commitment being signed is shared across all shielded inputs.
        let txid_parts = tx_data.digest(TxIdDigester);
        let shielded_sighash = signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts);
        // Create the binding signatures.
        #[cfg(feature = "zsa")]
        let tx_data = if consensus_branch_id == zcash_protocol::consensus::BranchId::Nu7 {
            // ZSA (Nu7): preserve the signed issue bundle through binding
            // signature application.
            tx_data.try_map_bundles_zsa(
                |t| Ok(t.map(|t| t.map_authorization(transparent::RemoveInputInfo))),
                |s| {
                    s.map(|s| {
                        s.apply_binding_signature(*shielded_sighash.as_ref(), OsRng)
                            .ok_or(Error::SighashMismatch)
                    })
                    .transpose()
                },
                |o| match o {
                    Some(OrchardBundle::OrchardVanilla(bundle)) => {
                        bundle.apply_binding_signature(*shielded_sighash.as_ref(), OsRng)
                            .ok_or(Error::SighashMismatch)
                            .map(|b| Some(OrchardBundle::OrchardVanilla(b)))
                    }
                    #[cfg(feature = "zsa")]
                    Some(OrchardBundle::OrchardZSA(_)) => {
                        unreachable!("PCZT ZSA extraction not yet implemented")
                    }
                    None => Ok(None),
                },
                |_issue| Ok(saved_signed_issue),
            )?
        } else {
            tx_data.try_map_bundles(
                |t| Ok(t.map(|t| t.map_authorization(transparent::RemoveInputInfo))),
                |s| {
                    s.map(|s| {
                        s.apply_binding_signature(*shielded_sighash.as_ref(), OsRng)
                            .ok_or(Error::SighashMismatch)
                    })
                    .transpose()
                },
                |o| {
                    o.map(|o| {
                        o.apply_binding_signature(*shielded_sighash.as_ref(), OsRng)
                            .ok_or(Error::SighashMismatch)
                    })
                    .transpose()
                },
            )?
        };
        #[cfg(not(feature = "zsa"))]
        let tx_data = tx_data.try_map_bundles(
            |t| Ok(t.map(|t| t.map_authorization(transparent::RemoveInputInfo))),
            |s| {
                s.map(|s| {
                    s.apply_binding_signature(*shielded_sighash.as_ref(), OsRng)
                        .ok_or(Error::SighashMismatch)
                })
                .transpose()
            },
            |o| {
                o.map(|o| {
                    o.apply_binding_signature(*shielded_sighash.as_ref(), OsRng)
                        .ok_or(Error::SighashMismatch)
                })
                .transpose()
            },
        )?;

        let tx = tx_data.freeze().expect("txid construction can't fail here");

        // Now that we have a supposedly fully-authorized transaction, verify it.
        if let Some(bundle) = tx.sapling_bundle() {
            let (spend_vk, output_vk) = sapling_vk.ok_or(Error::SaplingRequired)?;

            sapling::verify_bundle(bundle, spend_vk, output_vk, *shielded_sighash.as_ref())
                .map_err(Error::Sapling)?;
        }
        if let Some(bundle) = tx.orchard_bundle() {
            match bundle {
                OrchardBundle::OrchardVanilla(b) => {
                    orchard::verify_bundle(b, orchard_vk, *shielded_sighash.as_ref())
                        .map_err(Error::Orchard)?;
                }
                #[cfg(feature = "zsa")]
                OrchardBundle::OrchardZSA(_) => {
                    // ZSA verification — not yet implemented for PCZT path
                }
            }
        }
        if let Some(bundle) = tx.ironwood_bundle() {
            orchard::verify_bundle(bundle, orchard_vk, *shielded_sighash.as_ref())
                .map_err(Error::Ironwood)?;
        }

        Ok(tx)
    }
}

struct Unbound;

impl Authorization for Unbound {
    type TransparentAuth = ::transparent::pczt::Unbound;
    type SaplingAuth = ::sapling::pczt::Unbound;
    type OrchardAuth = ::orchard::pczt::Unbound;
    type IssueAuth = ::orchard::issuance::EffectsOnly;
}

/// Errors that can occur while extracting a transaction from a PCZT.
#[derive(Debug)]
pub enum Error {
    Extract(crate::ExtractError),
    Ironwood(IronwoodError),
    Orchard(OrchardError),
    Sapling(SaplingError),
    SaplingRequired,
    SighashMismatch,
    Transparent(TransparentError),
}

impl From<crate::ExtractError> for Error {
    fn from(e: crate::ExtractError) -> Self {
        Error::Extract(e)
    }
}
