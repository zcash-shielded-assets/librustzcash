//! ZSA (Nu7) V6 orchard bundle serialization — ported from Zebra's format.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use nonempty::NonEmpty;
use orchard::bundle::{Authorized, BundleVersion, Flags};
use orchard::primitives::redpallas::{self, Binding, SigType, SpendAuth};
use orchard::tree::Anchor;
use zcash_encoding::{Array, CompactSize, Vector};
use zcash_protocol::value::ZatBalance;

use crate::encoding::{ReadBytesExt, WriteBytesExt};
use crate::transaction::Transaction;

fn read_versioned_sig<R: Read, T: SigType>(mut reader: R) -> io::Result<redpallas::Signature<T>> {
    let sighash_info_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    if sighash_info_bytes != [0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid sighash V0",
        ));
    }
    let mut sig = [0u8; 64];
    reader.read_exact(&mut sig)?;
    Ok(redpallas::Signature::from(sig))
}

fn write_versioned_sig<W: Write, T: SigType>(
    mut writer: W,
    sig: &redpallas::Signature<T>,
) -> io::Result<()> {
    Vector::write(&mut writer, &[0u8; 1], |w, b| w.write_u8(*b))?;
    writer.write_all(&<[u8; 64]>::from(sig))
}

/// Reads an Orchard bundle from the ZSA V6 transaction format.
/// Also returns raw 612-byte ZSA enc_ciphertexts per action for decryption.
#[allow(clippy::type_complexity)]
pub fn read_v6_bundle_zsa<R: Read>(
    mut reader: R,
) -> io::Result<(
    Option<orchard::Bundle<Authorized, ZatBalance>>,
    Vec<Vec<u8>>,
)> {
    let n_action_groups = CompactSize::read(&mut reader)?;
    if n_action_groups == 0 {
        return Ok((None, Vec::new()));
    }
    if n_action_groups != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "V6 transaction must contain exactly one action group",
        ));
    }

    // Read actions in ZSA format
    let (actions_without_auth, raw_enc_ciphertexts) = {
        let mut actions = Vec::new();
        let mut raw_encs = Vec::new();
        let count = CompactSize::read(&mut reader)?;
        for _ in 0..count {
            let (action, raw_enc) = read_action_zsa(&mut reader)?;
            actions.push(action);
            raw_encs.push(raw_enc);
        }
        (actions, raw_encs)
    };
    if actions_without_auth.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "An action group must contain at least one action",
        ));
    }

    let flags = {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        // ZSA uses the pre-Ironwood (0.14) orchard crate which has a single-arg
        // Flags::from_byte(byte). The 0.15 orchard adds BundleVersion-based
        // validation. Mask bit 2 (cross-address) which orchard_v2 rejects for
        // the Orchard pool. Use InsecureV1 to skip canonical proof-size
        // enforcement (ZSA circuit has PER_ACTION=2400 vs vanilla 2272).
        Flags::from_byte(b[0] & !0b0000_0100, BundleVersion::orchard_insecure_v1())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid Orchard flags"))?
    };
    let anchor = {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        Option::from(Anchor::from_bytes(bytes))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid anchor"))?
    };
    let n_ag_expiry_height = reader.read_u32_le()?;
    if n_ag_expiry_height != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nAGExpiryHeight field must be set to zero",
        ));
    }
    // burn
    let burn_count = CompactSize::read(&mut reader)?;
    for _ in 0..burn_count {
        let mut _asset = [0u8; 32];
        reader.read_exact(&mut _asset)?;
        let _value = reader.read_u64_le()?;
    }
    // proof
    let proof_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    // versioned spend auth sigs
    let actions = NonEmpty::from_vec(
        actions_without_auth
            .into_iter()
            .map(|a| a.try_map(|_| read_versioned_sig::<_, SpendAuth>(&mut reader)))
            .collect::<Result<Vec<_>, _>>()?,
    )
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no actions"))?;

    let value_balance = Transaction::read_amount(&mut reader)?;
    let binding_sig = read_versioned_sig::<_, Binding>(&mut reader)?;

    let authorization =
        orchard::bundle::Authorized::from_parts(orchard::Proof::new(proof_bytes), binding_sig);

    orchard::Bundle::try_from_parts(
        actions,
        flags,
        value_balance,
        anchor,
        authorization,
        BundleVersion::orchard_insecure_v1(),
    )
    .map(Some)
    .map(|b| (b, raw_enc_ciphertexts))
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Writes an Orchard bundle in the ZSA V6 transaction format.
///
/// `raw_enc_ciphertexts` contains the full 612-byte ZSA enc_ciphertext per action
/// (as captured during `read_v6_bundle_zsa`), or is empty if not available (e.g.
/// from the PCZT extraction path). When available, these are used verbatim instead
/// of zero-padding the 32-byte asset field.
pub fn write_v6_bundle_zsa<W: Write>(
    mut writer: W,
    bundle: Option<&crate::transaction::OrchardBundle<Authorized>>,
    raw_enc_ciphertexts: &[Vec<u8>],
) -> io::Result<()> {
    use crate::transaction::OrchardBundle;

    if let Some(bundle) = bundle {
        CompactSize::write(&mut writer, 1usize)?; // nActionGroups

        match bundle {
            OrchardBundle::OrchardVanilla(bundle) => {
                CompactSize::write(&mut writer, bundle.actions().len())?;
                for (i, act) in bundle.actions().iter().enumerate() {
                    let raw_enc = raw_enc_ciphertexts.get(i).map(|v| v.as_slice());
                    write_action_zsa(&mut writer, act, raw_enc)?;
                }
                let flags_byte =
                    bundle
                        .flags()
                        .to_byte(bundle.bundle_version())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "flags not encodable")
                        })?;
                writer.write_u8(flags_byte)?;
                writer.write_all(&bundle.anchor().to_bytes())?;
                writer.write_u32_le(0)?; // nAGExpiryHeight
                CompactSize::write(&mut writer, 0usize)?; // burn

                Vector::write(
                    &mut writer,
                    bundle.authorization().proof().as_ref(),
                    |w, b| w.write_u8(*b),
                )?;
                Array::write(
                    &mut writer,
                    bundle.actions().iter().map(|a| a.authorization()),
                    |w, auth| write_versioned_sig(w, auth),
                )?;
                writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;
                write_versioned_sig(&mut writer, bundle.authorization().binding_signature())?;
            }
            #[cfg(feature = "zsa")]
            OrchardBundle::OrchardZSA(bundle) => {
                CompactSize::write(&mut writer, bundle.actions().len())?;
                for (i, act) in bundle.actions().iter().enumerate() {
                    let raw_enc = raw_enc_ciphertexts.get(i).map(|v| v.as_slice());
                    super::orchard::write_value_commitment(&mut writer, act.cv_net())?;
                    super::orchard::write_nullifier(&mut writer, act.nullifier())?;
                    super::orchard::write_verification_key(&mut writer, act.rk())?;
                    super::orchard::write_cmx(&mut writer, act.cmx())?;
                    let nc = act.encrypted_note();
                    if let Some(raw_enc) = raw_enc {
                        writer.write_all(&nc.epk_bytes)?;
                        writer.write_all(raw_enc)?;
                        writer.write_all(&nc.out_ciphertext)?;
                    } else {
                        writer.write_all(&nc.epk_bytes)?;
                        writer.write_all(&nc.enc_ciphertext.as_ref()[..84])?;
                        writer.write_all(&nc.enc_ciphertext.as_ref()[84..])?;
                        writer.write_all(&nc.out_ciphertext)?;
                    }
                }
                let flags_byte =
                    bundle
                        .flags()
                        .to_byte(bundle.bundle_version())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "flags not encodable")
                        })?;
                writer.write_u8(flags_byte)?;
                writer.write_all(&bundle.anchor().to_bytes())?;
                writer.write_u32_le(0)?; // nAGExpiryHeight
                CompactSize::write(&mut writer, 0usize)?; // burn

                Vector::write(
                    &mut writer,
                    bundle.authorization().proof().as_ref(),
                    |w, b| w.write_u8(*b),
                )?;
                Array::write(
                    &mut writer,
                    bundle.actions().iter().map(|a| a.authorization()),
                    |w, auth| write_versioned_sig(w, auth),
                )?;
                writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;
                write_versioned_sig(&mut writer, bundle.authorization().binding_signature())?;
            }
        }
    } else {
        CompactSize::write(&mut writer, 0usize)?;
    }

    Ok(())
}

/// Read a single ZSA action: cv(32) + nf(32) + rk(32) + cmx(32) + epk(32) + enc_ciphertext(612) + out_ciphertext(80)
/// Returns the vanilla action (with stripped ciphertext) and the raw 612-byte ZSA enc_ciphertext.
fn read_action_zsa<R: Read>(mut reader: R) -> io::Result<(orchard::Action<()>, Vec<u8>)> {
    use zcash_note_encryption::note_bytes::NoteBytesData;

    let cv = super::orchard::read_value_commitment(&mut reader)?;
    let nf = super::orchard::read_nullifier(&mut reader)?;
    let rk = super::orchard::read_verification_key(&mut reader)?;
    let cmx = super::orchard::read_cmx(&mut reader)?;

    // ZSA transmitted note ciphertext: epk(32) + enc(612) + out(80) = 724 bytes
    let mut epk = [0u8; 32];
    let mut zsa_enc = [0u8; 612];
    let mut out = [0u8; 80];
    reader.read_exact(&mut epk)?;
    reader.read_exact(&mut zsa_enc)?;
    reader.read_exact(&mut out)?;

    // Save the raw 612-byte ZSA enc_ciphertext for later ZSA-aware decryption.
    let raw_enc = zsa_enc.to_vec();

    // Convert to vanilla TransmittedNoteCiphertext by stripping the 32-byte asset.
    let mut vanilla_enc = NoteBytesData([0u8; 580]);
    vanilla_enc.0[..52].copy_from_slice(&zsa_enc[..52]); // compact vanilla
    vanilla_enc.0[52..].copy_from_slice(&zsa_enc[84..]); // memo(512) + tag(16)

    let nc = orchard::note::TransmittedNoteCiphertext::<orchard::note_encryption::OrchardDomain> {
        epk_bytes: epk,
        enc_ciphertext: vanilla_enc,
        out_ciphertext: out,
    };

    let action = orchard::Action::from_parts(nf, rk, cmx, nc, cv, ())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ZSA action"))?;
    Ok((action, raw_enc))
}

/// Write a single ZSA action: cv+nf+rk+cmx+epk+enc612+out80
///
/// If `raw_enc_ciphertext` is provided (612 bytes from wire deserialization or
/// PCZT extraction), it is written verbatim, preserving the encrypted asset field.
/// Otherwise, the vanilla 580-byte ciphertext from the action is expanded with
/// a zero-filled asset placeholder (correct for ZEC, but wrong for non-ZEC ZSA
/// assets until the PCZT extraction path is updated to capture the raw bytes).
fn write_action_zsa<W: Write>(
    mut writer: W,
    act: &orchard::Action<<Authorized as orchard::bundle::Authorization>::SpendAuth>,
    raw_enc_ciphertext: Option<&[u8]>,
) -> io::Result<()> {
    super::orchard::write_value_commitment(&mut writer, act.cv_net())?;
    super::orchard::write_nullifier(&mut writer, act.nullifier())?;
    super::orchard::write_verification_key(&mut writer, act.rk())?;
    super::orchard::write_cmx(&mut writer, act.cmx())?;

    let nc = act.encrypted_note();

    if let Some(raw_enc) = raw_enc_ciphertext {
        // Use the full 612-byte ZSA enc_ciphertext verbatim (includes
        // the encrypted 32-byte asset). This path is used when the raw
        // ciphertext was captured during wire deserialization or will be
        // captured during PCZT extraction.
        debug_assert_eq!(
            raw_enc.len(),
            612,
            "ZSA raw enc_ciphertext must be 612 bytes"
        );
        writer.write_all(&nc.epk_bytes)?;
        writer.write_all(raw_enc)?;
        writer.write_all(&nc.out_ciphertext)?;
    } else {
        // Fallback: expand the vanilla 580-byte ciphertext with zero-filled
        // asset placeholder. Correct for ZEC (asset = identity point) but
        // wrong for non-ZEC ZSA assets.
        //   Vanilla layout: compact(52) + memo(512) + tag(16) = 580
        //   ZSA layout:     compact(52) + asset(32)  + memo(512) + tag(16) = 612
        writer.write_all(&nc.epk_bytes)?;
        writer.write_all(&nc.enc_ciphertext.as_ref()[..52])?; // compact vanilla (52)
        writer.write_all(&[0u8; 32])?; // ZSA asset placeholder (32)
        writer.write_all(&nc.enc_ciphertext.as_ref()[52..])?; // memo(512) + tag(16)
        writer.write_all(&nc.out_ciphertext)?;
    }
    Ok(())
}
