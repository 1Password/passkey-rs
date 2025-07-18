use passkey_types::{Passkey, ctap2::Aaguid};

use crate::{Authenticator, MockUserValidationMethod};

use super::*;

pub(crate) fn prf_eval_request(eval: Option<Vec<u8>>) -> AuthenticatorPrfInputs {
    let eval = eval
        .and_then(|data| HmacSecretSaltOrOutput::try_from(data.as_slice()).ok())
        .map(|salts| AuthenticatorPrfValues {
            first: salts.first().try_into().unwrap(),
            second: salts.second().map(|b| b.try_into().unwrap()),
        });
    AuthenticatorPrfInputs {
        eval,
        eval_by_credential: None,
    }
}

#[test]
fn hmac_secret_cycle_works() {
    let auth = Authenticator::new(Aaguid::new_empty(), None, MockUserValidationMethod::new())
        .hmac_secret(HmacSecretConfig::new_without_uv());

    let ext = auth
        .make_hmac_secret(Some(true))
        .expect("There should be passkey extensions");
    assert!(ext.cred_without_uv.is_some());

    let passkey = Passkey::mock("sneakernetsend.com".into())
        .hmac_secret(ext)
        .build();

    let request = prf_eval_request(Some(random_vec(64)));

    let res = auth
        .get_prf(
            &passkey.credential_id,
            passkey.extensions.hmac_secret.as_ref(),
            request.clone(),
            true,
        )
        .expect("did not succeed in creating hashes")
        .expect("hmac-secret was not supported when creation was requested")
        .results;
    assert!(res.second.is_some());
    assert_ne!(&res.first, res.second.as_ref().unwrap());

    // Make sure that the same input gives the same output
    let res2 = auth
        .get_prf(
            &passkey.credential_id,
            passkey.extensions.hmac_secret.as_ref(),
            request.clone(),
            true,
        )
        .expect("did not succeed in calling it twice with the same input")
        .expect("hmac-secret was not supported when creation was requested")
        .results;

    assert_eq!(res.first, res2.first);
    assert_eq!(res.second, res2.second);

    // Ensure that a different input changes the output
    let res3 = auth
        .get_prf(
            &passkey.credential_id,
            passkey.extensions.hmac_secret.as_ref(),
            prf_eval_request(Some(random_vec(64))),
            true,
        )
        .expect("Changing input should still succeed")
        .expect("hmac-secret was not supported when creation was requested")
        .results;

    assert_ne!(res.first, res3.first);
    assert_ne!(res.second, res3.second);
    assert!(res3.second.is_some());
    assert_ne!(res3.first, res3.second.unwrap());

    // make sure that if the same input is given but without UV the output is different
    let res4 = auth
        .get_prf(
            &passkey.credential_id,
            passkey.extensions.hmac_secret.as_ref(),
            request,
            false,
        )
        .expect("did not succeed in calling it twice with the same input")
        .expect("hmac-secret was not supported when creation was requested")
        .results;

    assert_ne!(res.first, res4.first);
    assert_ne!(res.second, res4.second);
    assert!(res4.second.is_some());
    assert_ne!(res4.first, res4.second.unwrap());
}

#[test]
fn hmac_secret_cycle_works_with_one_cred() {
    let auth = Authenticator::new(Aaguid::new_empty(), None, MockUserValidationMethod::new())
        .hmac_secret(HmacSecretConfig::new_with_uv_only());

    let ext = auth
        .make_hmac_secret(Some(true))
        .expect("There should be passkey extensions");
    assert!(ext.cred_without_uv.is_none());

    let passkey = Passkey::mock("sneakernetsend.com".into())
        .hmac_secret(ext)
        .build();

    let request = prf_eval_request(Some(random_vec(64)));

    let res = auth
        .get_prf(
            &passkey.credential_id,
            passkey.extensions.hmac_secret.as_ref(),
            request.clone(),
            true,
        )
        .expect("did not succeed in creating hashes")
        .expect("hmac-secret was not supported when creation was requested")
        .results;
    assert!(res.second.is_none());

    let res2 = auth
        .get_prf(
            &passkey.credential_id,
            passkey.extensions.hmac_secret.as_ref(),
            request,
            true,
        )
        .expect("did not succeed in calling it twice with the same input")
        .expect("hmac-secret was not supported when creation was requested")
        .results;

    assert_eq!(res.first, res2.first);
    assert!(res2.second.is_none());

    let res3 = auth
        .get_prf(
            &passkey.credential_id,
            passkey.extensions.hmac_secret.as_ref(),
            prf_eval_request(Some(random_vec(64))),
            true,
        )
        .expect("Changing input should still succeed")
        .expect("hmac-secret was not supported when creation was requested")
        .results;

    assert_ne!(res.first, res3.first);
    assert!(res3.second.is_none());
}
