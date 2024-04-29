//! Utilitie functions for encoding datatypes in a consistent way accross the `passkey` libraries
//! with a mind on global webauthn ecosystem support.

use data_encoding::{Specification, BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD};

/// Convert bytes to base64 without padding
pub fn base64(data: &[u8]) -> String {
    BASE64_NOPAD.encode(data)
}

/// Convert bytes to base64url without padding
pub fn base64url(data: &[u8]) -> String {
    BASE64URL_NOPAD.encode(data)
}

/// Try parsing from base64 with or without padding
pub(crate) fn try_from_base64(input: &str) -> Option<Vec<u8>> {
    let padding = BASE64.specification().padding.unwrap();
    let sane_string = input.trim_end_matches(padding);
    BASE64_NOPAD.decode(sane_string.as_bytes()).ok()
}

/// Try parsing from base64url with or without padding
pub fn try_from_base64url(input: &str) -> Option<Vec<u8>> {
    let specs = BASE64URL.specification();
    let padding = specs.padding.unwrap();
    let specs = Specification {
        check_trailing_bits: false,
        padding: None,
        ..specs
    };
    let encoding = specs.encoding().unwrap();
    let sane_string = input.trim_end_matches(padding);
    encoding.decode(sane_string.as_bytes()).ok()
}
