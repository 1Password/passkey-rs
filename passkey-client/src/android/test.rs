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
