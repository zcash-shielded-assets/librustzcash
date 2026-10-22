use crate::consensus::{BlockHeight, NetworkType, NetworkUpgrade, OrchardMode, Parameters};

/// a `LocalNetwork` setup should define the activation heights
/// of network upgrades. `None` is considered as "not activated"
/// These heights are not validated. Callers shall initialized
/// them according to the settings used on the Full Nodes they
/// are connecting to.
///
/// Example:
///     Regtest Zcashd using the following `zcash.conf`
///     ```
///     ## NUPARAMS
///     nuparams=5ba81b19:1 # Overwinter
///     nuparams=76b809bb:1 # Sapling
///     nuparams=2bb40e60:1 # Blossom
///     nuparams=f5b9230b:1 # Heartwood
///     nuparams=e9ff75a6:1 # Canopy
///     nuparams=c2d6d0b4:1 # NU5
///     nuparams=c8e71055:1 # NU6
///     ```
///     would use the following `LocalNetwork` struct
///     ```
///     let regtest = LocalNetwork {
///         overwinter: Some(BlockHeight::from_u32(1)),
///         sapling: Some(BlockHeight::from_u32(1)),
///         blossom: Some(BlockHeight::from_u32(1)),
///         heartwood: Some(BlockHeight::from_u32(1)),
///         canopy: Some(BlockHeight::from_u32(1)),
///         nu5: Some(BlockHeight::from_u32(1)),
///         nu6: Some(BlockHeight::from_u32(1)),
///         nu6_1: Some(BlockHeight::from_u32(1)),
///         nu6_2: Some(BlockHeight::from_u32(1)),
///         nu6_3: Some(BlockHeight::from_u32(1)),
///         zsa: Some(BlockHeight::from_u32(1)),
///         orchard_mode: OrchardMode::Zsa,
///         nu7: None,
///         #[cfg(zcash_unstable = "nutachyon")]
///         nu_tachyon: Some(BlockHeight::from_u32(1)),
///     };
///     ```
///
#[derive(Clone, PartialEq, Eq, Copy, Debug, Hash)]
pub struct LocalNetwork {
    pub overwinter: Option<BlockHeight>,
    pub sapling: Option<BlockHeight>,
    pub blossom: Option<BlockHeight>,
    pub heartwood: Option<BlockHeight>,
    pub canopy: Option<BlockHeight>,
    pub nu5: Option<BlockHeight>,
    pub nu6: Option<BlockHeight>,
    pub nu6_1: Option<BlockHeight>,
    pub nu6_2: Option<BlockHeight>,
    pub nu6_3: Option<BlockHeight>,
    /// Activation height of the deployed ZSA protocol (formerly called NU7).
    pub zsa: Option<BlockHeight>,
    /// The Orchard protocol variant for this network.
    pub orchard_mode: OrchardMode,
    /// The NU7 activation height for this network, or `None` if NU7 never activates.
    pub nu7: Option<BlockHeight>,
    #[cfg(zcash_unstable = "nutachyon")]
    pub nu_tachyon: Option<BlockHeight>,
}

/// Parameters implementation for `LocalNetwork`
impl Parameters for LocalNetwork {
    fn network_type(&self) -> NetworkType {
        NetworkType::Regtest
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Overwinter => self.overwinter,
            NetworkUpgrade::Sapling => self.sapling,
            NetworkUpgrade::Blossom => self.blossom,
            NetworkUpgrade::Heartwood => self.heartwood,
            NetworkUpgrade::Canopy => self.canopy,
            NetworkUpgrade::Nu5 => self.nu5,
            NetworkUpgrade::Nu6 => self.nu6,
            NetworkUpgrade::Nu6_1 => self.nu6_1,
            NetworkUpgrade::Nu6_2 => self.nu6_2,
            NetworkUpgrade::Nu6_3 => self.nu6_3,
            NetworkUpgrade::Zsa => self.zsa,
            NetworkUpgrade::Nu7 => self.nu7,
            #[cfg(zcash_unstable = "nutachyon")]
            NetworkUpgrade::NuTachyon => self.nu_tachyon,
        }
    }

    fn orchard_mode(&self) -> OrchardMode {
        self.orchard_mode
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        consensus::{BlockHeight, NetworkConstants, NetworkUpgrade, OrchardMode, Parameters},
        constants,
        local_consensus::LocalNetwork,
    };

    #[test]
    // The references are the point of this test: `Parameters` is implemented for `&P`.
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn zsa_identity_and_mode_survive_parameter_references() {
        use crate::consensus::BranchId;

        const ZSA_BRANCH_ID: u32 = 0x7719_0ad8;
        let network = LocalNetwork {
            overwinter: None,
            sapling: None,
            blossom: None,
            heartwood: None,
            canopy: None,
            nu5: None,
            nu6: None,
            nu6_1: None,
            nu6_2: None,
            nu6_3: None,
            zsa: Some(BlockHeight::from_u32(1)),
            nu7: None,
            #[cfg(zcash_unstable = "nutachyon")]
            nu_tachyon: None,
            orchard_mode: OrchardMode::Zsa,
        };
        fn mode<P: Parameters>(params: P) -> OrchardMode {
            params.orchard_mode()
        }
        assert_eq!(mode(network), OrchardMode::Zsa);
        assert_eq!(mode(&network), OrchardMode::Zsa);
        assert_eq!(mode(&&network), OrchardMode::Zsa);
        assert_eq!(
            BranchId::for_height(&network, BlockHeight::from_u32(1)),
            BranchId::Zsa
        );
        assert_eq!(u32::from(BranchId::Zsa), ZSA_BRANCH_ID);
        assert_eq!(BranchId::try_from(ZSA_BRANCH_ID), Ok(BranchId::Zsa));
    }

    #[test]
    fn regtest_nu_activation() {
        let expected_overwinter = BlockHeight::from_u32(1);
        let expected_sapling = BlockHeight::from_u32(2);
        let expected_blossom = BlockHeight::from_u32(3);
        let expected_heartwood = BlockHeight::from_u32(4);
        let expected_canopy = BlockHeight::from_u32(5);
        let expected_nu5 = BlockHeight::from_u32(6);
        let expected_nu6 = BlockHeight::from_u32(7);
        let expected_nu6_1 = BlockHeight::from_u32(8);
        let expected_nu6_2 = BlockHeight::from_u32(9);
        let expected_nu6_3 = BlockHeight::from_u32(10);
        let expected_nu7 = BlockHeight::from_u32(11);
        #[cfg(zcash_unstable = "nutachyon")]
        let expected_nu_tachyon = BlockHeight::from_u32(12);

        let regtest = LocalNetwork {
            overwinter: Some(expected_overwinter),
            sapling: Some(expected_sapling),
            blossom: Some(expected_blossom),
            heartwood: Some(expected_heartwood),
            canopy: Some(expected_canopy),
            nu5: Some(expected_nu5),
            nu6: Some(expected_nu6),
            nu6_1: Some(expected_nu6_1),
            nu6_2: Some(expected_nu6_2),
            nu6_3: Some(expected_nu6_3),
            zsa: None,
            orchard_mode: OrchardMode::Normal,
            nu7: Some(expected_nu7),
            #[cfg(zcash_unstable = "nutachyon")]
            nu_tachyon: Some(expected_nu_tachyon),
        };

        assert!(regtest.is_nu_active(NetworkUpgrade::Overwinter, expected_overwinter));
        assert!(regtest.is_nu_active(NetworkUpgrade::Sapling, expected_sapling));
        assert!(regtest.is_nu_active(NetworkUpgrade::Blossom, expected_blossom));
        assert!(regtest.is_nu_active(NetworkUpgrade::Heartwood, expected_heartwood));
        assert!(regtest.is_nu_active(NetworkUpgrade::Canopy, expected_canopy));
        assert!(regtest.is_nu_active(NetworkUpgrade::Nu5, expected_nu5));
        assert!(regtest.is_nu_active(NetworkUpgrade::Nu6, expected_nu6));
        assert!(regtest.is_nu_active(NetworkUpgrade::Nu6_1, expected_nu6_1));
        assert!(regtest.is_nu_active(NetworkUpgrade::Nu6_2, expected_nu6_2));
        assert!(regtest.is_nu_active(NetworkUpgrade::Nu6_3, expected_nu6_3));
        // nu7 must not be activated at or below the nu6_3 height
        assert!(!regtest.is_nu_active(NetworkUpgrade::Zsa, expected_nu6_3));
        assert!(!regtest.is_nu_active(NetworkUpgrade::Nu7, expected_nu6_3));
        #[cfg(zcash_unstable = "nutachyon")]
        {
            assert!(!regtest.is_nu_active(NetworkUpgrade::NuTachyon, expected_nu6_3));
            assert!(regtest.is_nu_active(NetworkUpgrade::NuTachyon, expected_nu_tachyon));
        }
    }

    #[test]
    fn regtest_activation_heights() {
        let expected_overwinter = BlockHeight::from_u32(1);
        let expected_sapling = BlockHeight::from_u32(2);
        let expected_blossom = BlockHeight::from_u32(3);
        let expected_heartwood = BlockHeight::from_u32(4);
        let expected_canopy = BlockHeight::from_u32(5);
        let expected_nu5 = BlockHeight::from_u32(6);
        let expected_nu6 = BlockHeight::from_u32(7);
        let expected_nu6_1 = BlockHeight::from_u32(8);
        let expected_nu6_2 = BlockHeight::from_u32(9);
        let expected_nu6_3 = BlockHeight::from_u32(10);
        let expected_nu7 = BlockHeight::from_u32(11);
        #[cfg(zcash_unstable = "nutachyon")]
        let expected_nu_tachyon = BlockHeight::from_u32(12);

        let regtest = LocalNetwork {
            overwinter: Some(expected_overwinter),
            sapling: Some(expected_sapling),
            blossom: Some(expected_blossom),
            heartwood: Some(expected_heartwood),
            canopy: Some(expected_canopy),
            nu5: Some(expected_nu5),
            nu6: Some(expected_nu6),
            nu6_1: Some(expected_nu6_1),
            nu6_2: Some(expected_nu6_2),
            nu6_3: Some(expected_nu6_3),
            zsa: None,
            orchard_mode: OrchardMode::Normal,
            nu7: Some(expected_nu7),
            #[cfg(zcash_unstable = "nutachyon")]
            nu_tachyon: Some(expected_nu_tachyon),
        };

        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Overwinter),
            Some(expected_overwinter)
        );
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Sapling),
            Some(expected_sapling)
        );
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Blossom),
            Some(expected_blossom)
        );
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Heartwood),
            Some(expected_heartwood)
        );
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Canopy),
            Some(expected_canopy)
        );
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Nu5),
            Some(expected_nu5)
        );
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Nu6),
            Some(expected_nu6)
        );
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Nu6_1),
            Some(expected_nu6_1)
        );
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Nu6_2),
            Some(expected_nu6_2)
        );
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Nu6_3),
            Some(expected_nu6_3)
        );
        assert_eq!(regtest.activation_height(NetworkUpgrade::Zsa), None);
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::Nu7),
            Some(expected_nu7)
        );
        #[cfg(zcash_unstable = "nutachyon")]
        assert_eq!(
            regtest.activation_height(NetworkUpgrade::NuTachyon),
            Some(expected_nu_tachyon)
        );
    }

    #[test]
    fn regtests_constants() {
        let expected_overwinter = BlockHeight::from_u32(1);
        let expected_sapling = BlockHeight::from_u32(2);
        let expected_blossom = BlockHeight::from_u32(3);
        let expected_heartwood = BlockHeight::from_u32(4);
        let expected_canopy = BlockHeight::from_u32(5);
        let expected_nu5 = BlockHeight::from_u32(6);
        let expected_nu6 = BlockHeight::from_u32(7);
        let expected_nu6_1 = BlockHeight::from_u32(8);
        let expected_nu6_2 = BlockHeight::from_u32(9);
        let expected_nu6_3 = BlockHeight::from_u32(10);
        let expected_nu7 = BlockHeight::from_u32(11);
        #[cfg(zcash_unstable = "nutachyon")]
        let expected_nu_tachyon = BlockHeight::from_u32(12);

        let regtest = LocalNetwork {
            overwinter: Some(expected_overwinter),
            sapling: Some(expected_sapling),
            blossom: Some(expected_blossom),
            heartwood: Some(expected_heartwood),
            canopy: Some(expected_canopy),
            nu5: Some(expected_nu5),
            nu6: Some(expected_nu6),
            nu6_1: Some(expected_nu6_1),
            nu6_2: Some(expected_nu6_2),
            nu6_3: Some(expected_nu6_3),
            zsa: None,
            orchard_mode: OrchardMode::Normal,
            nu7: Some(expected_nu7),
            #[cfg(zcash_unstable = "nutachyon")]
            nu_tachyon: Some(expected_nu_tachyon),
        };

        assert_eq!(regtest.coin_type(), constants::regtest::COIN_TYPE);
    }
}
