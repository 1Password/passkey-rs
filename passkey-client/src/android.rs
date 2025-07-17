use nom::{
    IResult,
    bytes::complete::{tag, take_while_m_n},
    character::is_hex_digit,
    combinator::map_res,
    multi::separated_list1,
};
use std::{borrow::Cow, fmt::Debug, str::from_utf8};
use url::Url;

#[derive(Debug, Clone)]
/// An Unverified asset link.
pub struct UnverifiedAssetLink<'a> {
    /// Application package name.
    package_name: Cow<'a, str>,
    /// Fingerprint to compare.
    sha256_cert_fingerprint: Vec<u8>,
    /// Host to lookup the well known asset link.
    host: Cow<'a, str>,
    /// When sourced from the application statement list or parsed from host for passkeys.
    asset_link_url: Url,
}

impl<'a> UnverifiedAssetLink<'a> {
    /// Create a new [`UnverifiedAssetLink`].
    pub fn new(
        package_name: impl Into<Cow<'a, str>>,
        sha256_cert_fingerprint: &str,
        host: impl Into<Cow<'a, str>>,
        asset_link_url: Url,
    ) -> Result<Self, ValidationError> {
        // Is this correct?
        // It looks like you can set your own url path.
        // https://developers.google.com/digital-asset-links/v1/statements#scaling-to-dozens-of-statements-or-more
        if !valid_asset_link_url(&asset_link_url) {
            return Err(ValidationError::InvalidAssetLinkUrl);
        }
        let host = host.into();

        valid_fingerprint(sha256_cert_fingerprint).map(|sha256_cert_fingerprint| Self {
            package_name: package_name.into(),
            sha256_cert_fingerprint,
            host,
            asset_link_url,
        })
    }

    /// Fingerprint of the application's signing certificate
    pub fn sha256_cert_fingerprint(&self) -> &[u8] {
        self.sha256_cert_fingerprint.as_slice()
    }

    /// The application's package name
    pub fn package_name(&self) -> &str {
        &self.package_name
    }

    /// The host to lookup the well-known assetlinks
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the digital asset Url for validation
    pub fn asset_link_url(&self) -> Url {
        self.asset_link_url.clone()
    }
}

/// Digital asset fingerprint validation error.
#[derive(Debug)]
pub enum ValidationError {
    /// The fingerprint could not be parsed.
    ParseFailed(String),
    /// The fingerprint had an invalid length.
    InvalidLength,
    /// The asset link url is not secure or incorrect path.
    InvalidAssetLinkUrl,
}

impl<T> From<nom::Err<nom::error::Error<T>>> for ValidationError {
    fn from(value: nom::Err<nom::error::Error<T>>) -> Self {
        let code_msg = value.map(|err| format!("{:?}", err.code));
        let message = match code_msg {
            nom::Err::Incomplete(_) => "Parsing incomplete".to_owned(),
            nom::Err::Error(msg) => format!("Parsing error: {msg}"),
            nom::Err::Failure(msg) => format!("Parsing failure: {msg}"),
        };

        ValidationError::ParseFailed(message)
    }
}

/// Make sure we have an expected fingerprint. Characters have to be uppercase.
///
/// <https://developer.android.com/training/app-links/verify-android-applinks#fix-errors>
/// * Having a lower case signature in assetlinks.json. The signature should be
///   in upper case.
pub fn valid_fingerprint(fingerprint: &str) -> Result<Vec<u8>, ValidationError> {
    #[derive(Debug)]
    enum HexError {
        Utf8,
        ParseInt,
    }

    fn parse_fingerprint(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        separated_list1(
            tag(":"),
            map_res(
                take_while_m_n(2, 2, |c| is_hex_digit(c) && !c.is_ascii_lowercase()),
                |hex| {
                    u8::from_str_radix(from_utf8(hex).map_err(|_| HexError::Utf8)?, 16)
                        .map_err(|_| HexError::ParseInt)
                },
            ),
        )(input)
    }

    let (left, parsed) = parse_fingerprint(fingerprint.as_bytes())?;

    (left.is_empty() && parsed.len() == 32)
        .then_some(parsed)
        .ok_or(ValidationError::InvalidLength)
}

/// Check for secure and expected path.
fn valid_asset_link_url(url: &Url) -> bool {
    url.scheme() == "https" && url.path() == "/.well-known/assetlinks.json"
}

#[cfg(test)]
mod test {
    use super::{ValidationError, valid_asset_link_url, valid_fingerprint};
    use url::Url;

    #[test]
    fn check_valid_fingerprint() {
        assert!(
            valid_fingerprint("B3:5B:68:D5:CE:84:50:55:7C:6A:55:FD:64:B5:1F:EA:C1:10:CB:36:D6:A3:52:1C:59:48:DB:3A:38:0A:34:A9").is_ok(),
            "Should be valid fingerprint"
        );
    }

    #[test]
    fn check_invalid_fingerprint_lowercase() {
        let result = valid_fingerprint(
            "b3:5b:68:d5:ce:84:50:55:7c:6a:55:fd:64:b5:1f:ea:c1:10:cb:36:d6:a3:52:1c:59:48:db:3a:38:0a:34:a9",
        );
        assert!(result.is_err(), "Should be invalid fingerprint");
        assert!(matches!(result, Err(ValidationError::ParseFailed(..))))
    }

    #[test]
    fn check_invalid_fingerprint_length() {
        let result = valid_fingerprint("B3:5B:68:D5:CE:84:50:55:7C:6A:55");
        assert!(result.is_err(), "Should be invalid fingerprint");
        assert!(matches!(result, Err(ValidationError::InvalidLength)))
    }

    #[test]
    fn check_invalid_fingerprint_non_hex() {
        assert!(
            valid_fingerprint("B3:5B:68:X5:CE:84:50:55:7C:6A:55:FD:64:B5:1F:EA:C1:10:CB:36:D6:A3:52:1C:59:48:DB:3A:38:0A:34:A9").is_err(),
            "Should be valid fingerprint"
        );
    }

    #[test]
    fn asset_link_url_ok() {
        let url = Url::parse("https://www.facebook.com/.well-known/assetlinks.json").unwrap();
        assert!(valid_asset_link_url(&url));
    }

    #[test]
    fn asset_link_url_not_secure() {
        let url = Url::parse("http://www.facebook.com/.well-known/assetlinks.json").unwrap();
        assert!(!valid_asset_link_url(&url));
    }

    #[test]
    fn asset_link_url_unexpected_path() {
        let url = Url::parse("https://www.facebook.com/assetlinks.json").unwrap();
        assert!(!valid_asset_link_url(&url));
    }
}
