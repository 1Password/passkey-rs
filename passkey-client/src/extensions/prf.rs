use std::collections::HashMap;

use passkey_types::{
    crypto::sha256,
    ctap2::{
        extensions::{AuthenticatorPrfInputs, AuthenticatorPrfValues},
        get_assertion, get_info, make_credential,
    },
    webauthn::{
        AuthenticationExtensionsClientInputs, AuthenticationExtensionsPrfInputs,
        AuthenticationExtensionsPrfValues, PublicKeyCredentialDescriptor,
        PublicKeyCredentialRequestOptions,
    },
    Bytes,
};

use crate::WebauthnError;

type Result<T> = ::std::result::Result<T, WebauthnError>;

pub(super) fn registration_prf_to_ctap2_input(
    request: Option<&AuthenticationExtensionsClientInputs>,
    supported_extensions: &[get_info::Extension],
) -> Result<Option<make_credential::ExtensionInputs>> {
    make_ctap_extension(request.and_then(|r| r.prf.as_ref()), supported_extensions)
}

fn validate_no_eval_by_cred(
    prf_input: Option<&AuthenticationExtensionsPrfInputs>,
) -> Result<Option<&AuthenticationExtensionsPrfInputs>> {
    Ok(match prf_input {
        Some(prf) if prf.eval_by_credential.is_some() => {
            return Err(WebauthnError::NotSupportedError);
        }
        Some(prf) => Some(prf),
        None => None,
    })
}

fn convert_eval_to_ctap(
    eval: &AuthenticationExtensionsPrfValues,
) -> Result<AuthenticatorPrfValues> {
    let (first, second) = {
        let salt1 = make_salt(&eval.first);
        let salt2 = eval.second.as_ref().map(make_salt);
        (salt1, salt2)
    };

    Ok(AuthenticatorPrfValues { first, second })
}

fn make_ctap_extension(
    prf: Option<&AuthenticationExtensionsPrfInputs>,
    supported_extensions: &[get_info::Extension],
) -> Result<Option<make_credential::ExtensionInputs>> {
    // Check if PRF extension input is provided and process it.
    //
    // Should return a "NotSupportedError" if `evalByCredential` is present
    // in this registration request.
    let prf = validate_no_eval_by_cred(prf)?;

    // Only request hmac-secret extension input if it's enabled on the authenticator and prf is requested.
    let hmac_secret = prf.and_then(|_| {
        supported_extensions
            .contains(&get_info::Extension::HmacSecret)
            .then_some(true)
    });

    let prf = prf
        .filter(|_| supported_extensions.contains(&get_info::Extension::Prf))
        .map(|prf| {
            // Only create prf extension input if it's enabled on the authenticator.
            prf.eval
                .as_ref()
                .map(convert_eval_to_ctap)
                .transpose()
                .map(|eval| AuthenticatorPrfInputs {
                    eval,
                    eval_by_credential: None,
                })
        })
        .transpose()?;

    // If any of the input fields are Some, only then should this pass
    // a Some(ExtensionInputs) to authenticator. Otherwise, it should
    // forward a None.
    Ok(make_credential::ExtensionInputs {
        hmac_secret,
        hmac_secret_mc: None,
        prf,
    }
    .zip_contents())
}

pub(super) fn auth_prf_to_ctap2_input(
    request: &PublicKeyCredentialRequestOptions,
    supported_extensions: &[get_info::Extension],
) -> Result<Option<get_assertion::ExtensionInputs>> {
    get_ctap_extension(
        request.allow_credentials.as_deref(),
        request.extensions.as_ref().and_then(|ext| ext.prf.as_ref()),
        supported_extensions,
    )
}

fn get_ctap_extension(
    allow_credentials: Option<&[PublicKeyCredentialDescriptor]>,
    prf_input: Option<&AuthenticationExtensionsPrfInputs>,
    supported_extensions: &[get_info::Extension],
) -> Result<Option<get_assertion::ExtensionInputs>> {
    // Check if the authenticator supports prf before continuing
    if !supported_extensions.contains(&get_info::Extension::Prf) {
        return Ok(None);
    }
    // Check if PRF extension input is provided and process it.
    let eval_by_credential = prf_input
        .as_ref()
        .and_then(|prf| prf.eval_by_credential.as_ref());

    // If evalByCredential is not empty but allowCredentials is empty,
    // return a DOMException whose name is “NotSupportedError”.
    if eval_by_credential.is_some_and(|record| !record.is_empty())
        && (allow_credentials.is_none()
            || allow_credentials
                .as_ref()
                .is_some_and(|allow| allow.is_empty()))
    {
        return Err(WebauthnError::NotSupportedError);
    }

    // Pre-compute the parsed values of the base64url-encoded key s.t. we
    // can speed up our logic later on instead of having the re-compute
    // these values there again.
    // TODO: consolidate with authenticator logic
    let precomputed_eval_cred = eval_by_credential
        .map(|record| {
            record
                .iter()
                .map(|(key, val)| {
                    Bytes::try_from(key.as_str())
                        .map(|k| (k, val))
                        .map_err(|_| WebauthnError::SyntaxError)
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;

    // If any key in evalByCredential is the empty string, or is not a valid
    // base64url encoding, or does not equal the id of some element of
    // allowCredentials after performing base64url decoding, then return a
    // DOMException whose name is “SyntaxError”.
    if let Some(record) = precomputed_eval_cred.as_ref() {
        if record.iter().any(|(k_bytes, _)| {
            k_bytes.is_empty()
                || allow_credentials
                    .as_ref()
                    .is_some_and(|allow| !allow.iter().any(|cred| cred.id == *k_bytes))
        }) {
            return Err(WebauthnError::SyntaxError);
        }
    }

    let new_eval_by_cred = precomputed_eval_cred
        .map(|map| {
            map.into_iter()
                .map(|(k, values)| convert_eval_to_ctap(values).map(|v| (k, v)))
                .collect::<Result<HashMap<_, _>>>()
        })
        .transpose()?;

    let eval = prf_input
        .and_then(|prf| prf.eval.as_ref().map(convert_eval_to_ctap))
        .transpose()?;

    let prf = prf_input.map(|_| AuthenticatorPrfInputs {
        eval,
        eval_by_credential: new_eval_by_cred,
    });

    let extension_inputs = get_assertion::ExtensionInputs {
        hmac_secret: None,
        prf,
    }
    .zip_contents();

    Ok(extension_inputs)
}

// Build the value that's used as salt by the CTAP2 hmac-secret extension.
fn make_salt(prf_value: &Bytes) -> [u8; 32] {
    sha256(
        &b"WebAuthn PRF"
            .iter()
            .chain(std::iter::once(&0x0))
            .chain(prf_value)
            .cloned()
            .collect::<Vec<_>>(),
    )
}
