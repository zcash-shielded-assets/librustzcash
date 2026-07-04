//! ZSA issuance builder stubs — work in progress.

use alloc::vec::Vec;
use orchard::{issuance::IssueAuth, note::AssetBase, value::NoteValue, Address};
use rand_core::RngCore;

/// Builder for ZSA issuance actions (work in progress).
pub struct ZsaBuilder {
    _private: (),
}

impl ZsaBuilder {
    /// Creates a new ZSA issuance builder.
    pub fn new(_isk: impl Into<Vec<u8>>) -> Self {
        ZsaBuilder { _private: () }
    }

    /// Adds an issue output.
    pub fn add_issue_output(
        &mut self,
        _desc_hash: [u8; 32],
        _address: Address,
        _value: NoteValue,
        _first_issuance: bool,
        _rng: &mut impl RngCore,
    ) -> Result<(), &'static str> {
        Ok(())
    }

    /// Finalizes an asset.
    pub fn finalize_asset(&mut self, _desc_hash: &[u8; 32]) -> Result<(), &'static str> {
        Ok(())
    }

    /// Builds the issuance bundle awaiting sighash.
    pub fn build_awaiting_sighash<T: IssueAuth>(
        self,
        _rng: impl RngCore,
    ) -> Result<
        (
            orchard::issuance::IssueBundle<orchard::issuance::AwaitingSighash>,
            Vec<AssetBase>,
            Vec<bool>,
        ),
        &'static str,
    > {
        unimplemented!("ZSA issuance not yet implemented")
    }
}
