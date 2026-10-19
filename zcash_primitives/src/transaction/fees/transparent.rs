//! Types related to computation of fees and change related to the transparent components
//! of a transaction.

use core::convert::Infallible;

use crate::transaction::fees::zip317::P2PKH_STANDARD_INPUT_SIZE;
use transparent::{
    address::Script,
    bundle::{OutPoint, TxOut},
};
use zcash_protocol::value::Zatoshis;
use zcash_script::{script, solver};

#[cfg(feature = "transparent-inputs")]
use transparent::builder::{SpendInfo, TransparentInputInfo};

/// The size of a transparent input, or the outpoint corresponding to the input
/// if the size of the script required to spend that input is unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputSize {
    /// The txin size is known.
    Known(usize),
    /// The size of the script required to spend this input (and therefore the txin size)
    /// is unknown.
    Unknown(OutPoint),
}

impl InputSize {
    /// An `InputSize` corresponding to the upper bound on the size of a P2PKH input used by ZIP 317.
    pub const STANDARD_P2PKH: InputSize = InputSize::Known(P2PKH_STANDARD_INPUT_SIZE);
}

/// This trait provides a minimized view of a transparent input suitable for use in
/// fee and change computation.
pub trait InputView: core::fmt::Debug {
    /// The outpoint to which the input refers.
    fn outpoint(&self) -> &OutPoint;

    /// The previous output being spent.
    fn coin(&self) -> &TxOut;

    /// The size of this transparent input in a transaction, as used in [ZIP 317].
    ///
    /// [ZIP 317]: https://zips.z.cash/zip-0317#rationale-for-the-chosen-parameters
    fn serialized_size(&self) -> InputSize {
        match script::PubKey::parse(&self.coin().script_pubkey().0)
            .ok()
            .as_ref()
            .and_then(solver::standard)
        {
            Some(solver::ScriptKind::PubKeyHash { .. }) => InputSize::STANDARD_P2PKH,
            _ => InputSize::Unknown(self.outpoint().clone()),
        }
    }
}

#[cfg(feature = "transparent-inputs")]
impl InputView for TransparentInputInfo {
    fn outpoint(&self) -> &OutPoint {
        self.outpoint()
    }

    fn coin(&self) -> &TxOut {
        self.coin()
    }

    fn serialized_size(&self) -> InputSize {
        // For P2PKH inputs, return the ZIP 317 standard size (150 bytes) rather than the
        // exact serialized size (which is one byte smaller). The proposal layer accounts
        // for fees using the standard size; the builder must agree, otherwise a
        // shielding transaction with enough P2PKH inputs to cross a
        // `ceildiv(t_in_total_size, 150)` boundary will fail with `ChangeRequired`.
        //
        // A coin paying to the uncompressed encoding of its key pushes 32 more bytes of
        // pubkey in its `script_sig`, which `serialized_len` accounts for; the standard
        // size is then a floor rather than the answer.
        match self.spend_info() {
            SpendInfo::P2pkh { .. } => self
                .serialized_len()
                .map_or(InputSize::STANDARD_P2PKH, |len| {
                    InputSize::Known(len.max(P2PKH_STANDARD_INPUT_SIZE))
                }),
            SpendInfo::P2sh { .. } => self.serialized_len().map_or(
                InputSize::Unknown(self.outpoint().clone()),
                InputSize::Known,
            ),
        }
    }
}

impl InputView for Infallible {
    fn outpoint(&self) -> &OutPoint {
        unreachable!()
    }
    fn coin(&self) -> &TxOut {
        unreachable!()
    }
}

/// This trait provides a minimized view of a transparent output suitable for use in
/// fee and change computation.
pub trait OutputView: core::fmt::Debug {
    /// Returns the value of the output being created.
    fn value(&self) -> Zatoshis;

    /// Returns the script corresponding to the newly created output.
    fn script_pubkey(&self) -> &Script;

    /// Returns the serialized size of the txout.
    fn serialized_size(&self) -> usize {
        // The serialized size of a transparent `TxOut` is the serialized size of an amount
        // plus the serialized size of the script pubkey.
        8 + self.script_pubkey().serialized_size()
    }
}

impl OutputView for TxOut {
    fn value(&self) -> Zatoshis {
        self.value()
    }

    fn script_pubkey(&self) -> &Script {
        self.script_pubkey()
    }
}

#[cfg(all(test, feature = "transparent-inputs"))]
mod tests {
    use transparent::{
        address::TransparentAddress,
        builder::{SpendInfo, TransparentInputInfo},
        bundle::{OutPoint, TxOut},
        util::hash160,
    };
    use zcash_protocol::value::Zatoshis;

    use super::{InputSize, InputView, P2PKH_STANDARD_INPUT_SIZE};

    /// A P2PKH input spending a coin that pays to `pubkey_bytes`, one encoding of
    /// `pubkey`.
    fn p2pkh_input(pubkey: secp256k1::PublicKey, pubkey_bytes: &[u8]) -> TransparentInputInfo {
        let addr = TransparentAddress::PublicKeyHash(hash160::hash(pubkey_bytes));
        let coin = TxOut::new(Zatoshis::const_from_u64(10_000), addr.script().into());
        TransparentInputInfo::from_parts(
            OutPoint::new([0; 32], 0),
            coin,
            SpendInfo::P2pkh { pubkey },
        )
        .expect("the coin pays to this key")
    }

    #[test]
    fn p2pkh_input_size_follows_the_pubkey_encoding() {
        let sk = secp256k1::SecretKey::from_secret_bytes([1; 32]).unwrap();
        let pubkey = sk.public_key();
        let compressed = p2pkh_input(pubkey, &pubkey.serialize());
        let uncompressed = p2pkh_input(pubkey, &pubkey.serialize_uncompressed());

        // A compressed-key coin is priced at the ZIP 317 standard size, which rounds its
        // exact size up by one byte.
        assert_eq!(compressed.serialized_size(), InputSize::STANDARD_P2PKH);
        // An uncompressed-key coin pushes 32 more bytes of pubkey, so it is priced at
        // its exact size, above the standard one.
        let expected = compressed.serialized_len().unwrap() + 32;
        assert!(expected > P2PKH_STANDARD_INPUT_SIZE);
        assert_eq!(uncompressed.serialized_size(), InputSize::Known(expected));
    }
}
