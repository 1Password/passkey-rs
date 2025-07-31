use passkey_types::webauthn::WellKnown;
use public_suffix::DEFAULT_PROVIDER;
use url::Url;

use crate::{Fetcher, Origin, RelatedOriginResponse, RpIdVerifier, WebauthnError};

pub struct TestFetcher {
    pub origins: Vec<Url>,
    pub final_url: Option<Url>,
}

impl Default for TestFetcher {
    fn default() -> Self {
        TestFetcher {
            origins: [
                "https://1password.com",
                "https://1password.ca",
                "https://future.1password.com",
                "https://1password.eu",
                "https://kolide.com",
                "https://trelica.com",
                "https://1password-test.com",
                "https://1password-dev.com",
            ]
            .into_iter()
            .map(Url::parse)
            .map(Result::unwrap)
            .collect(),
            final_url: None,
        }
    }
}

impl Fetcher for TestFetcher {
    async fn fetch_related_origins(
        &self,
        url: Url,
    ) -> Result<RelatedOriginResponse, WebauthnError> {
        Ok(RelatedOriginResponse {
            payload: WellKnown {
                origins: self.origins.clone(),
            },
            final_url: self.final_url.clone().unwrap_or(url),
        })
    }
}

/// This test contains the upper limit of 5 different labels where one has multiple different tlds
/// and subdomains.
/// This does not tests whether any redirects occured when fetching the related origins.
#[tokio::test]
async fn test_happy_path_no_redirects() {
    let fetcher = TestFetcher::default();
    let verifier = RpIdVerifier::new(DEFAULT_PROVIDER, Some(fetcher));

    let op_rpid = verifier
        .validate_related_origins("1password.com", "1password.eu")
        .await
        .expect("Could not validate cross tld");
    assert_eq!(op_rpid, "1password.com");

    let op_ca_rpid = verifier
        .validate_related_origins("1password.ca", "future.1password.com")
        .await
        .expect("Could not validate cross tld");
    assert_eq!(op_ca_rpid, "1password.ca");

    let op_rpid = verifier
        .validate_related_origins("1password.com", "kolide.com")
        .await
        .expect("Could not validate across labels");
    assert_eq!(op_rpid, "1password.com");

    let should_error = verifier
        .validate_related_origins("1password.com", "future.kolide.com")
        .await
        .expect_err("kolide sub domain should not match");
    assert_eq!(should_error, WebauthnError::OriginRpMissmatch);
}

#[tokio::test]
async fn meta_sanity_check() {
    let fetcher = TestFetcher {
        origins: [
            "https://messenger.com",
            "https://www.messenger.com",
            "https://facebook.com",
            "https://www.facebook.com",
            "https://accounts.meta.com",
            "https://business.facebook.com",
            "https://accountscenter.meta.com",
            "https://accountscenter.facebook.com",
        ]
        .into_iter()
        .map(Url::parse)
        .map(Result::unwrap)
        .collect(),
        final_url: None,
    };

    let verifier = RpIdVerifier::new(DEFAULT_PROVIDER, Some(fetcher));

    let meta_rpid = verifier
        .validate_related_origins("accounts.meta.com", "messenger.com")
        .await
        .expect("Could not validate cross tld");
    assert_eq!(meta_rpid, "accounts.meta.com");

    let meta_rpid = verifier
        .validate_related_origins("accounts.meta.com", "www.facebook.com")
        .await
        .expect("Could not validate cross tld");
    assert_eq!(meta_rpid, "accounts.meta.com");

    let meta_rpid = verifier
        .validate_related_origins("accounts.meta.com", "accounts.meta.com")
        .await
        .expect("Could not validate cross tld");
    assert_eq!(meta_rpid, "accounts.meta.com");
}

#[tokio::test]
async fn microsoft_sanity_check() {
    let fetcher = TestFetcher {
        origins: [
            "https://login.live.com",
            "https://login.microsoftonline.com",
        ]
        .into_iter()
        .map(Url::parse)
        .map(Result::unwrap)
        .collect(),
        final_url: None,
    };

    let verifier = RpIdVerifier::new(DEFAULT_PROVIDER, Some(fetcher));

    let ms_rpid = verifier
        .validate_related_origins("login.microsoft.com", "login.microsoftonline.com")
        .await
        .expect("Could not validate cross tld");
    assert_eq!(ms_rpid, "login.microsoft.com");

    let ms_rpid = verifier
        .validate_related_origins("login.microsoft.com", "login.live.com")
        .await
        .expect("Could not validate cross tld");
    assert_eq!(ms_rpid, "login.microsoft.com");

    // The actual rpId is not in the list but is where the wellknown originates.
    // This will fail related origins check, but would pass a normal rpId check
    let should_error = verifier
        .validate_related_origins("login.microsoft.com", "login.microsoft.com")
        .await
        .expect_err("kolide sub domain should not match");
    assert_eq!(should_error, WebauthnError::OriginRpMissmatch);

    let ms_origin = Origin::Web(std::borrow::Cow::Owned(
        Url::parse("https://login.microsoft.com").unwrap(),
    ));
    let ms_rpid = verifier
        .assert_domain(&ms_origin, Some("login.microsoft.com"))
        .await
        .expect("this is the same rp and origin, should pass");
    assert_eq!(ms_rpid, "login.microsoft.com");
}

#[tokio::test]
async fn assert_invalid_rp_id_doesnt_panic() {
    let fetcher = TestFetcher::default();

    let verifier = RpIdVerifier::new(DEFAULT_PROVIDER, Some(fetcher));

    let should_error = verifier
        .validate_related_origins("com", "1password.ca")
        .await
        .expect_err("kolide sub domain should not match");
    assert_eq!(should_error, WebauthnError::InvalidRpId);

    let should_error = verifier
        .validate_related_origins("1password..com", "1password.ca")
        .await
        .expect_err("kolide sub domain should not match");
    assert_eq!(should_error, WebauthnError::InvalidRpId);

    let should_error = verifier
        .validate_related_origins("1password", "1password.ca")
        .await
        .expect_err("kolide sub domain should not match");
    assert_eq!(should_error, WebauthnError::InvalidRpId);
}
