//! Shared helpers for parsing signing keys out of COSE-encoded structures.

use coset::{
    CoseKey,
    iana::{self, EnumI64},
};
use zeroize::Zeroizing;

use crate::CoseKeyConversionError;

/// Length of an uncompressed SEC1 encoded P-256 public key (0x04 || X || Y).
#[cfg(feature = "aws-lc-rs")]
pub const P256_UNCOMPRESSED_LEN: usize = 65;
/// Length of a P-256 field element (X or Y coordinate, or the D scalar).
pub const P256_FIELD_LEN: usize = 32;
/// Length of an Ed25519 seed / public key.
pub const ED25519_KEY_LEN: usize = 32;

/// Assemble the uncompressed SEC1 encoding `0x04 || X || Y` for a P-256 point.
#[cfg(feature = "aws-lc-rs")]
pub fn p256_uncompressed(
    x: &[u8; P256_FIELD_LEN],
    y: &[u8; P256_FIELD_LEN],
) -> [u8; P256_UNCOMPRESSED_LEN] {
    let mut out = [0u8; P256_UNCOMPRESSED_LEN];
    out[0] = 0x04;
    out[1..1 + P256_FIELD_LEN].copy_from_slice(x);
    out[1 + P256_FIELD_LEN..].copy_from_slice(y);
    out
}

/// Split a 65-byte uncompressed SEC1 P-256 point back into `(X, Y)` references.
#[cfg(feature = "aws-lc-rs")]
pub fn split_p256_uncompressed(
    bytes: &[u8; P256_UNCOMPRESSED_LEN],
) -> (&[u8; P256_FIELD_LEN], &[u8; P256_FIELD_LEN]) {
    let x = (&bytes[1..1 + P256_FIELD_LEN])
        .try_into()
        .expect("slice length matches array");
    let y = (&bytes[1 + P256_FIELD_LEN..])
        .try_into()
        .expect("slice length matches array");
    (x, y)
}

/// Extract the P-256 `X` and `Y` coordinates from an EC2 COSE key. Requires both to be present.
#[cfg(feature = "aws-lc-rs")]
pub fn extract_p256_xy(
    cose_key: &CoseKey,
) -> Result<([u8; P256_FIELD_LEN], [u8; P256_FIELD_LEN]), CoseKeyConversionError> {
    let (mut x, mut y) = (None, None);
    for (key, value) in &cose_key.params {
        if let coset::Label::Int(i) = key {
            let key = iana::Ec2KeyParameter::from_i64(*i)
                .ok_or(CoseKeyConversionError::InvalidCredential)?;
            match key {
                iana::Ec2KeyParameter::X => {
                    if value.as_bytes().and_then(|v| x.replace(v)).is_some() {
                        log::warn!("Cose key has multiple entries for X coordinate");
                    }
                }
                iana::Ec2KeyParameter::Y => {
                    if value.as_bytes().and_then(|v| y.replace(v)).is_some() {
                        log::warn!("Cose key has multiple entries for Y coordinate");
                    }
                }
                _ => (),
            }
        }
    }
    let (Some(x), Some(y)) = (x, y) else {
        return Err(CoseKeyConversionError::InvalidCredential);
    };
    let x: [u8; P256_FIELD_LEN] = x
        .as_slice()
        .try_into()
        .map_err(|_| CoseKeyConversionError::InvalidCredential)?;
    let y: [u8; P256_FIELD_LEN] = y
        .as_slice()
        .try_into()
        .map_err(|_| CoseKeyConversionError::InvalidCredential)?;
    Ok((x, y))
}

/// Extract the P-256 `D` scalar from an EC2 COSE key, wrapped so it zeroizes on drop.
pub fn extract_p256_d(
    cose_key: &CoseKey,
) -> Result<Zeroizing<[u8; P256_FIELD_LEN]>, CoseKeyConversionError> {
    let bytes = cose_key
        .params
        .iter()
        .find_map(|(k, v)| {
            if let coset::Label::Int(i) = k {
                iana::Ec2KeyParameter::from_i64(*i)
                    .filter(|p| p == &iana::Ec2KeyParameter::D)
                    .and_then(|_| v.as_bytes())
            } else {
                None
            }
        })
        .ok_or(CoseKeyConversionError::InvalidCredential)?;
    if bytes.len() != P256_FIELD_LEN {
        return Err(CoseKeyConversionError::InvalidCredential);
    }
    let mut d: Zeroizing<[u8; P256_FIELD_LEN]> = Zeroizing::new([0u8; P256_FIELD_LEN]);
    d.copy_from_slice(bytes);
    Ok(d)
}

/// Extract the Ed25519 public key `X` from an OKP COSE key. Requires it to be present.
#[cfg(feature = "aws-lc-rs")]
pub fn extract_okp_x(cose_key: &CoseKey) -> Result<[u8; ED25519_KEY_LEN], CoseKeyConversionError> {
    find_okp_x(cose_key)?.ok_or(CoseKeyConversionError::InvalidCredential)
}

/// Extract the Ed25519 public key `X` from an OKP COSE key if present.
#[cfg(feature = "aws-lc-rs")]
pub fn find_okp_x(
    cose_key: &CoseKey,
) -> Result<Option<[u8; ED25519_KEY_LEN]>, CoseKeyConversionError> {
    let mut x = None;
    for (key, value) in &cose_key.params {
        if let coset::Label::Int(i) = key {
            let key = iana::OkpKeyParameter::from_i64(*i)
                .ok_or(CoseKeyConversionError::InvalidCredential)?;
            if key == iana::OkpKeyParameter::X
                && value.as_bytes().and_then(|v| x.replace(v)).is_some()
            {
                log::warn!("Cose key has multiple entries for X coordinate");
            }
        }
    }
    match x {
        Some(bytes) => bytes
            .as_slice()
            .try_into()
            .map(Some)
            .map_err(|_| CoseKeyConversionError::InvalidCredential),
        None => Ok(None),
    }
}

/// Extract the Ed25519 `D` seed from an OKP COSE key, wrapped so it zeroizes on drop.
pub fn extract_okp_d(
    cose_key: &CoseKey,
) -> Result<Zeroizing<[u8; ED25519_KEY_LEN]>, CoseKeyConversionError> {
    let bytes = cose_key
        .params
        .iter()
        .find_map(|(k, v)| {
            let coset::Label::Int(i) = k else {
                return None;
            };
            iana::OkpKeyParameter::from_i64(*i)
                .filter(|p| *p == iana::OkpKeyParameter::D)
                .and_then(|_| v.as_bytes())
        })
        .ok_or(CoseKeyConversionError::InvalidCredential)?;
    if bytes.len() != ED25519_KEY_LEN {
        return Err(CoseKeyConversionError::InvalidCredential);
    }
    let mut seed: Zeroizing<[u8; ED25519_KEY_LEN]> = Zeroizing::new([0u8; ED25519_KEY_LEN]);
    seed.copy_from_slice(bytes);
    Ok(seed)
}

/// Look up the `crv` value in an EC2 COSE key.
#[cfg(feature = "aws-lc-rs")]
pub fn find_ec2_crv(cose_key: &CoseKey) -> Result<Option<i64>, CoseKeyConversionError> {
    find_crv(cose_key, iana::Ec2KeyParameter::Crv.to_i64())
}

/// Look up the `crv` value in an OKP COSE key.
#[cfg(feature = "aws-lc-rs")]
pub fn find_okp_crv(cose_key: &CoseKey) -> Result<Option<i64>, CoseKeyConversionError> {
    find_crv(cose_key, iana::OkpKeyParameter::Crv.to_i64())
}

#[cfg(feature = "aws-lc-rs")]
fn find_crv(cose_key: &CoseKey, crv_label: i64) -> Result<Option<i64>, CoseKeyConversionError> {
    let Some(value) = cose_key.params.iter().find_map(|(k, v)| match k {
        coset::Label::Int(i) if *i == crv_label => Some(v),
        _ => None,
    }) else {
        return Ok(None);
    };
    let crv: i64 = value
        .as_integer()
        .ok_or(CoseKeyConversionError::InvalidCredential)?
        .try_into()
        .map_err(|_| CoseKeyConversionError::InvalidCredential)?;
    Ok(Some(crv))
}
