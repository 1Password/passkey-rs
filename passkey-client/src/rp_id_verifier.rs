use std::{borrow::Cow, ops::ControlFlow};

use url::Url;

use crate::{Origin, WebauthnError};

#[cfg(doc)]
use crate::Client;

#[cfg(feature = "android-asset-validation")]
pub(crate) mod android;

#[cfg(feature = "android-asset-validation")]
use android::UnverifiedAssetLink;

/// Wrapper struct for verifying that a given RpId matches the request's origin.
///
/// While most cases should not use this type directly and instead use [`Client`], there are some
/// cases that warrant the need for checking an RpId in the same way that the client does, but without
/// the rest of pieces that the client needs.
pub struct RpIdVerifier<P> {
    tld_provider: Box<P>,
    allows_insecure_localhost: bool,
}

impl<P> RpIdVerifier<P>
where
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
{
    /// Create a new Verifier with a given TLD provider. Most cases should just use
    /// [`public_suffix::DEFAULT_PROVIDER`].
    pub fn new(tld_provider: P) -> Self {
        Self {
            tld_provider: Box::new(tld_provider),
            allows_insecure_localhost: false,
        }
    }

    /// Allows [`RpIdVerifier::assert_domain`] to pass through requests from `localhost`
    pub fn allows_insecure_localhost(mut self, is_allowed: bool) -> Self {
        self.allows_insecure_localhost = is_allowed;
        self
    }

    /// Parse the given Relying Party Id and verify it against the origin url of the request.
    ///
    /// This follows the steps defined in: <https://html.spec.whatwg.org/multipage/browsers.html#is-a-registrable-domain-suffix-of-or-is-equal-to>
    ///
    /// Returns the effective domain on success or some [`WebauthnError`]
    pub fn assert_domain<'a>(
        &self,
        origin: &'a Origin,
        rp_id: Option<&'a str>,
    ) -> Result<&'a str, WebauthnError> {
        match origin {
            Origin::Web(url) => self.assert_web_rp_id(url, rp_id),
            #[cfg(feature = "android-asset-validation")]
            Origin::Android(unverified) => self.assert_android_rp_id(unverified, rp_id),
        }
    }

    fn assert_web_rp_id<'a>(
        &self,
        origin: &'a Url,
        rp_id: Option<&'a str>,
    ) -> Result<&'a str, WebauthnError> {
        let mut effective_domain = origin.domain().ok_or(WebauthnError::OriginMissingDomain)?;

        if let Some(rp_id) = rp_id {
            if !effective_domain.ends_with(rp_id) {
                return Err(WebauthnError::OriginRpMissmatch);
            }

            effective_domain = rp_id;
        }

        // Guard against local host and assert rp_id is not part of the public suffix list
        if let ControlFlow::Break(res) = self.assert_valid_rp_id(effective_domain) {
            return res;
        }

        // Make sure origin uses https://
        if !(origin.scheme().eq_ignore_ascii_case("https")) {
            return Err(WebauthnError::UnprotectedOrigin);
        }

        Ok(effective_domain)
    }

    fn assert_valid_rp_id<'a>(
        &self,
        rp_id: &'a str,
    ) -> ControlFlow<Result<&'a str, WebauthnError>, ()> {
        // guard against localhost effective domain, return early
        if rp_id == "localhost" {
            return if self.allows_insecure_localhost {
                ControlFlow::Break(Ok(rp_id))
            } else {
                ControlFlow::Break(Err(WebauthnError::InsecureLocalhostNotAllowed))
            };
        }

        // assert rp_id is not part of the public suffix list and is a registerable domain.
        if decode_host(rp_id)
            .as_ref()
            .and_then(|s| self.tld_provider.effective_tld_plus_one(s).ok())
            .is_none()
        {
            return ControlFlow::Break(Err(WebauthnError::InvalidRpId));
        }

        ControlFlow::Continue(())
    }

    /// Parse a given Relying Party ID and assert that it is valid to act as such.
    ///
    /// This method is only to assert that an RP ID passes the required checks.
    /// In order to ensure that a request's origin is in accordance with it's claimed RP ID,
    /// [`Self::assert_domain`] should be used.
    ///
    /// There are several checks that an RP ID must pass:
    /// 1. An RP ID set to `localhost` is only allowed when explicitly enabled with [`Self::allows_insecure_localhost`].
    /// 1. An RP ID must not be part of the [public suffix list],
    ///    since that would allow it to act as a credential for unrelated services by other entities.
    pub fn is_valid_rp_id(&self, rp_id: &str) -> bool {
        match self.assert_valid_rp_id(rp_id) {
            ControlFlow::Continue(_) | ControlFlow::Break(Ok(_)) => true,
            ControlFlow::Break(Err(_)) => false,
        }
    }

    #[cfg(feature = "android-asset-validation")]
    fn assert_android_rp_id<'a>(
        &self,
        target_link: &'a UnverifiedAssetLink,
        rp_id: Option<&'a str>,
    ) -> Result<&'a str, WebauthnError> {
        let mut effective_rp_id = target_link.host();

        if let Some(rp_id) = rp_id {
            // subset from assert_web_rp_id
            if !effective_rp_id.ends_with(rp_id) {
                return Err(WebauthnError::OriginRpMissmatch);
            }
            effective_rp_id = rp_id;
        }

        if decode_host(effective_rp_id)
            .as_ref()
            .and_then(|s| self.tld_provider.effective_tld_plus_one(s).ok())
            .is_none()
        {
            return Err(WebauthnError::InvalidRpId);
        }

        // TODO: Find an ergonomic and caching friendly way to fetch the remote
        // assetlinks and validate them here.
        // https://github.com/1Password/passkey-rs/issues/13

        Ok(effective_rp_id)
    }
}

/// Returns a decoded [String] if the domain name is punycode otherwise
/// the original string reference [str] is returned.
fn decode_host(host: &str) -> Option<Cow<str>> {
    if host.split('.').any(|s| s.starts_with("xn--")) {
        let (decoded, result) = idna::domain_to_unicode(host);
        result.ok().map(|_| Cow::from(decoded))
    } else {
        Some(Cow::from(host))
    }
}
