use blake2b_simd::Hash as Blake2bHash;

use ::transparent::sighash::TransparentAuthorizingContext;

use crate::transaction::{
    Authorization, TransactionData, TxDigests, sighash::SignableInput, txid::to_hash_zsa,
};

/// ZSA (Nu7) V6 signature hash.
///
/// Uses `to_hash_zsa` which includes the issue bundle digest as the final
/// term, instead of Ironwood's `to_hash_v6` which uses an ironwood digest.
/// This mirrors the txid computation (`to_txid` uses `to_hash_zsa` for Nu7).
pub fn zsa_v6_signature_hash<
    TA: TransparentAuthorizingContext,
    A: Authorization<TransparentAuth = TA>,
>(
    tx: &TransactionData<A>,
    signable_input: &SignableInput<'_>,
    txid_parts: &TxDigests<Blake2bHash>,
) -> Blake2bHash {
    to_hash_zsa(
        tx.consensus_branch_id,
        txid_parts.header_digest,
        crate::transaction::sighash_v5::transparent_sig_digest(
            tx.transparent_bundle
                .as_ref()
                .zip(txid_parts.transparent_digests.as_ref()),
            signable_input,
        ),
        txid_parts.sapling_digest,
        txid_parts.orchard_digest,
        txid_parts.issue_digest,
    )
}
