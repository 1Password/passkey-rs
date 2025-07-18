use serde::{Deserialize, Serialize};
use url::Url;

/// The payload hosted by a relying party to augment their WebAuthn experience.
#[derive(Debug, Serialize, Deserialize)]
pub struct WellKnown {
    /// Should the relying party wish to re-use an rpId accross multiple origin domains
    /// that otherwise would not pass validation for a webauthn ceremony.
    ///
    /// To learn more please see refer to
    /// [WebAuthn level 3 - 5.11 Using Web Authentication across related origins][1]
    ///
    /// [1]: https://w3c.github.io/webauthn/#sctn-validating-relation-origin
    pub origins: Vec<Url>,
}
