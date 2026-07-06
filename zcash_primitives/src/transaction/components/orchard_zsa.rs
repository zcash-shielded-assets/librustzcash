//! ZSA (Nu7) V6 orchard bundle serialization — ported from Zebra's format.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use nonempty::NonEmpty;
use orchard::bundle::{Authorized, Bundle, BundleVersion, Flags};
use orchard::primitives::redpallas::{self, SigType, Signature, SpendAuth, Binding};
use orchard::tree::Anchor;
use zcash_encoding::{Array, CompactSize, Vector};
use zcash_protocol::value::ZatBalance;

use crate::encoding::{ReadBytesExt, WriteBytesExt};
use crate::transaction::Transaction;

const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;

fn read_versioned_sig<R: Read, T: SigType>(
    mut reader: R,
) -> io::Result<redpallas::Signature<T>> {
    let sighash_info_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
    if sighash_info_bytes != [0] {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid sighash V0"));
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
pub fn read_v6_bundle_zsa<R: Read>(
    mut reader: R,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    let n_action_groups = CompactSize::read(&mut reader)?;
    if n_action_groups == 0 {
        return Ok(None);
    }
    if n_action_groups != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "V6 transaction must contain exactly one action group",
        ));
    }

    // Read actions in ZSA format
    let actions_without_auth = Vector::read(&mut reader, |r| read_action_zsa(r))?;
    if actions_without_auth.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "An action group must contain at least one action",
        ));
    }

    let flags = {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b)?;
        Flags::from_byte(b[0], BundleVersion::orchard_v2())
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

    let authorization = orchard::bundle::Authorized::from_parts(
        orchard::Proof::new(proof_bytes),
        binding_sig,
    );

    orchard::Bundle::try_from_parts(actions, flags, value_balance, anchor, authorization, BundleVersion::orchard_v2())
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Writes an Orchard bundle in the ZSA V6 transaction format.
pub fn write_v6_bundle_zsa<W: Write>(
    mut writer: W,
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        CompactSize::write(&mut writer, 1usize)?; // nActionGroups
        Vector::write_nonempty(&mut writer, bundle.actions(), |w, a| {
            write_action_zsa(w, a)
        })?;

        let flags_byte = bundle.flags().to_byte(bundle.bundle_version()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "flags not encodable")
        })?;
        writer.write_u8(flags_byte)?;
        writer.write_all(&bundle.anchor().to_bytes())?;
        writer.write_u32_le(0)?; // nAGExpiryHeight
        CompactSize::write(&mut writer, 0usize)?; // burn

        Vector::write(&mut writer, bundle.authorization().proof().as_ref(), |w, b| w.write_u8(*b))?;

        Array::write(&mut writer, bundle.actions().iter().map(|a| a.authorization()), |w, auth| {
            write_versioned_sig(w, auth)
        })?;

        writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;
        write_versioned_sig(&mut writer, bundle.authorization().binding_signature())?;
    } else {
        CompactSize::write(&mut writer, 0usize)?;
    }

    Ok(())
}

/// Read a single ZSA action: cv(32) + nf(32) + rk(32) + cmx(32) + epk(32) + enc_ciphertext(84) + out_ciphertext(80)
fn read_action_zsa<R: Read>(mut reader: R) -> io::Result<orchard::Action<()>> {
    let cv = super::orchard::read_value_commitment(&mut reader)?;
    let nf = super::orchard::read_nullifier(&mut reader)?;
    let rk = super::orchard::read_verification_key(&mut reader)?;
    let cmx = super::orchard::read_cmx(&mut reader)?;
    // ZSA ciphertext: epk(32) + enc(84) + out(80)
    let mut zsa_ciphertext = [0u8; 32 + 84 + 80];
    reader.read_exact(&mut zsa_ciphertext)?;
    // Convert ZSA→vanilla: epk(32) + enc(52) + out(80) — drop 32-byte asset from enc
    let mut vanilla_buf = Vec::new();
    vanilla_buf.extend_from_slice(&zsa_ciphertext[..32]); // epk
    vanilla_buf.extend_from_slice(&zsa_ciphertext[32..32+52]); // enc (vanilla portion)
    vanilla_buf.extend_from_slice(&zsa_ciphertext[32+84..]); // out (80 bytes)
    let nc = super::orchard::read_note_ciphertext(&mut vanilla_buf.as_slice())?;
    orchard::Action::from_parts(nf, rk, cmx, nc, cv, ()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid ZSA action")
    })
}

/// Write a single ZSA action: cv+nf+rk+cmx+epk+enc84+out80
fn write_action_zsa<W: Write>(
    mut writer: W,
    act: &orchard::Action<<Authorized as orchard::bundle::Authorization>::SpendAuth>,
) -> io::Result<()> {
    super::orchard::write_value_commitment(&mut writer, act.cv_net())?;
    super::orchard::write_nullifier(&mut writer, act.nullifier())?;
    super::orchard::write_verification_key(&mut writer, act.rk())?;
    super::orchard::write_cmx(&mut writer, act.cmx())?;

    let nc = act.encrypted_note();
    // epk: 32 bytes
    writer.write_all(&nc.epk_bytes)?;
    // enc_ciphertext: pad 52→84 bytes with zeros (ZSA asset)
    writer.write_all(nc.enc_ciphertext.as_ref())?;
    writer.write_all(&[0u8; 32])?;
    // out_ciphertext: 80 bytes
    writer.write_all(&nc.out_ciphertext)?;
    Ok(())
}
