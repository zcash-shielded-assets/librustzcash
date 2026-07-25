use orchard::circuit::ProvingKey;
use rand_core::OsRng;

use crate::Pczt;

impl super::Prover {
    pub fn create_orchard_proof(self, pk: &ProvingKey) -> Result<Self, OrchardError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
            issue,
        } = self.pczt;

        let bundle_version = crate::orchard::orchard_bundle_version(&global)
            .ok_or(OrchardError::UnsupportedConsensusBranchId)?;

        #[cfg(feature = "zsa")]
        let is_nu7 = u32::from(
            zcash_protocol::consensus::BranchId::try_from(global.consensus_branch_id)
                .unwrap_or(zcash_protocol::consensus::BranchId::Nu5),
        ) == u32::from(zcash_protocol::consensus::BranchId::Nu7);

        let orchard_raw = {
            #[cfg(feature = "zsa")]
            if is_nu7 {
                let mut b = orchard
                    .into_parsed_with_version_zsa(bundle_version)
                    .map_err(OrchardError::Parser)?;
                b.create_proof(pk, OsRng).map_err(OrchardError::Prover)?;
                crate::orchard::Bundle::serialize_from(b)
            } else {
                let mut b = orchard
                    .into_parsed_with_version(bundle_version)
                    .map_err(OrchardError::Parser)?;
                b.create_proof(pk, OsRng).map_err(OrchardError::Prover)?;
                crate::orchard::Bundle::serialize_from(b)
            }
            #[cfg(not(feature = "zsa"))]
            {
                let mut b = orchard
                    .into_parsed_with_version(bundle_version)
                    .map_err(OrchardError::Parser)?;
                b.create_proof(pk, OsRng).map_err(OrchardError::Prover)?;
                crate::orchard::Bundle::serialize_from(b)
            }
        };

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard: orchard_raw,
                ironwood,
                issue,
            },
        })
    }

    pub fn create_ironwood_proof(self, pk: &ProvingKey) -> Result<Self, IronwoodError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
            issue,
        } = self.pczt;

        let mut bundle = ironwood
            .into_ironwood_parsed()
            .map_err(IronwoodError::Parser)?;

        bundle
            .create_proof(pk, OsRng)
            .map_err(IronwoodError::Prover)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
                ironwood: crate::orchard::Bundle::serialize_from(bundle),
                issue,
            },
        })
    }
}

/// Errors that can occur while creating Orchard proofs for a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    Parser(orchard::pczt::ParseError),
    Prover(orchard::pczt::ProverError),
    /// The PCZT's consensus branch ID is unrecognized, or predates NU5 (under which
    /// the Orchard protocol is not supported).
    UnsupportedConsensusBranchId,
}

/// Errors that can occur while creating Ironwood proofs for a PCZT.
#[derive(Debug)]
pub enum IronwoodError {
    Parser(orchard::pczt::ParseError),
    Prover(orchard::pczt::ProverError),
}
