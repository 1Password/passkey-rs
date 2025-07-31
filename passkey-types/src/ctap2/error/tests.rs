use crate::ctap2::error::{ExtensionError, U2FError, UnknownSpecError, VendorError};

use super::{Ctap2Error, StatusCode};

#[test]
fn from_byte_conversions() {
    // Assert success defaults to ctap2
    let success = StatusCode::from(0x00);
    assert_eq!(success, Ctap2Error::Ok.into());

    let invalid_len = StatusCode::from(0x03);
    assert_eq!(invalid_len, U2FError::InvalidLength.into());

    let unsupported_alg = StatusCode::from(0x26);
    assert_eq!(unsupported_alg, Ctap2Error::UnsupportedAlgorithm.into());

    let unknown = StatusCode::from(0x1B);
    assert_eq!(unknown, UnknownSpecError(0x1B).into());

    let first_extension_err = StatusCode::from(0xE0);
    assert_eq!(first_extension_err, ExtensionError(0xE0).into());
    let last_extension_err = StatusCode::from(0xEF);
    assert_eq!(last_extension_err, ExtensionError(0xEF).into());

    let first_vendor_err = StatusCode::from(0xF0);
    assert_eq!(first_vendor_err, VendorError(0xF0).into());
    let last_vendor_err = StatusCode::from(0xFF);
    assert_eq!(last_vendor_err, VendorError(0xFF).into());
}

#[test]
fn all_byte_values() {
    // iterate through all byte values, it should not panic. Iterating through 256 cases should
    // be fairly quick
    for i in u8::MIN..=u8::MAX {
        let _code = StatusCode::from(i);
    }
}
