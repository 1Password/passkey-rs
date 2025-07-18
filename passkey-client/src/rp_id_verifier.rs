use std::{borrow::Cow, collections::HashMap, ops::ControlFlow};

use itertools::Itertools;
use passkey_types::webauthn::WellKnown;
use url::Url;

use crate::{Origin, WebauthnError};

#[cfg(doc)]
use crate::Client;

#[cfg(test)]
pub(crate) mod tests;

#[cfg(feature = "android-asset-validation")]
pub(crate) mod android;

#[cfg(feature = "android-asset-validation")]
use android::UnverifiedAssetLink;

/// Wrapper struct for verifying that a given RpId matches the request's origin.
///
/// While most cases should not use this type directly and instead use [`Client`], there are some
/// cases that warrant the need for checking an RpId in the same way that the client does, but without
/// the rest of pieces that the client needs.
pub struct RpIdVerifier<P, F> {
    tld_provider: Box<P>,
    allows_insecure_localhost: bool,
    fetcher: Option<F>,
}

impl<P, F> RpIdVerifier<P, F>
where
    P: public_suffix::EffectiveTLDProvider + Sync + 'static,
    F: Fetcher + Sync,
{
    /// Create a new Verifier with a given TLD provider. Most cases should just use
    /// [`public_suffix::DEFAULT_PROVIDER`].
    pub fn new(tld_provider: P, fetcher: Option<F>) -> Self {
        Self {
            tld_provider: Box::new(tld_provider),
            allows_insecure_localhost: false,
            fetcher,
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
    pub async fn assert_domain<'a>(
        &self,
        origin: &'a Origin<'a>,
        rp_id: Option<&'a str>,
    ) -> Result<&'a str, WebauthnError> {
        match origin {
            Origin::Web(url) => self.assert_web_rp_id(url, rp_id).await,
            #[cfg(feature = "android-asset-validation")]
            Origin::Android(unverified) => self.assert_android_rp_id(unverified, rp_id),
        }
    }

    async fn assert_web_rp_id<'a>(
        &self,
        origin: &'a Url,
        rp_id: Option<&'a str>,
    ) -> Result<&'a str, WebauthnError> {
        let mut effective_domain = origin.domain().ok_or(WebauthnError::OriginMissingDomain)?;

        if let Some(rp_id) = rp_id {
            if !effective_domain.ends_with(rp_id) {
                effective_domain = self
                    .validate_related_origins(rp_id, effective_domain)
                    .await?;
            } else {
                effective_domain = rp_id;
            }
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

    const ORIGIN_LABEL_LIMIT: usize = 5;

    async fn validate_related_origins<'a>(
        &self,
        rp_id: &'a str,
        effective_domain: &'a str,
    ) -> Result<&'a str, WebauthnError> {
        let Some(ref fetcher) = self.fetcher else {
            return Err(WebauthnError::OriginRpMissmatch);
        };

        if let ControlFlow::Break(res) = self.assert_valid_rp_id(rp_id) {
            return res;
        }

        let well_known_url = Url::parse(&format!("https://{rp_id}/.well-known/webauthn"))
            .expect("Building well_known_url unexpectedly failed");

        let RelatedOriginResponse { payload, final_url } =
            fetcher.fetch_related_origins(well_known_url).await?;

        if final_url
            .domain()
            .filter(|domain| domain.ends_with(rp_id))
            .is_none()
        {
            return Err(WebauthnError::RedirectError);
        }

        let WellKnown { origins } = payload;

        let origin_domains: Vec<_> = origins
            .iter()
            .filter_map(|origin| decode_host(origin.domain()?))
            .collect();

        let labels_to_origins: HashMap<_, _> = origin_domains
            .iter()
            .filter_map(|origin| {
                let etld = self.tld_provider.effective_tld_plus_one(origin).ok()?;
                let (label, _) = etld.split_once('.')?;
                if label.is_empty() {
                    None
                } else {
                    Some((label, origin))
                }
            })
            .into_group_map();

        // upper limit of registerable domain labels
        if labels_to_origins.len() > Self::ORIGIN_LABEL_LIMIT {
            return Err(WebauthnError::ExceedsMaxLabelLimit);
        }

        let decoded_effective_domain =
            decode_host(effective_domain).ok_or(WebauthnError::InvalidRpId)?;
        let Some((requesting_label, _)) = self
            .tld_provider
            .effective_tld_plus_one(&decoded_effective_domain)
            .ok()
            .and_then(|etld| etld.split_once('.'))
        else {
            return Err(WebauthnError::InvalidRpId);
        };

        let Some(matching_origins) = labels_to_origins.get(requesting_label) else {
            return Err(WebauthnError::OriginRpMissmatch);
        };

        // If this passes, it means the requesting origin is in the related origins list.
        if !matching_origins.contains(&&decoded_effective_domain) {
            return Err(WebauthnError::OriginRpMissmatch);
        };

        Ok(rp_id)
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

/// A trait to implement fetching remote resources for RP ID validation.
///
/// The implementer should take the following into consideration:
/// * Ensure a proper user agent is set
/// * Ensure an appropriate timeout is set
/// * Only follow HTTPS links and redirects
/// * Limit the number of redirects
/// * Set the `Accept` header to `application/json`
#[expect(async_fn_in_trait)]
pub trait Fetcher {
    /// Fetch the related origins resources from a url.
    ///
    /// The URL provided here already points to the `/.well-known/webauthn` path of a domain,
    /// the fetcher should use the url parameter without modifications.
    async fn fetch_related_origins(&self, url: Url)
    -> Result<RelatedOriginResponse, WebauthnError>;
}

/// The response to fetching a related origins resource.
pub struct RelatedOriginResponse {
    /// The deserialized payload of the resource, the source for this data should be in json format.
    pub payload: WellKnown,
    /// The final url of the request should the fetcher follow redirects.
    pub final_url: Url,
}

impl Fetcher for () {
    async fn fetch_related_origins(
        &self,
        _url: Url,
    ) -> Result<RelatedOriginResponse, WebauthnError> {
        Err(WebauthnError::FetcherError)
    }
}
