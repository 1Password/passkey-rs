use serde::{Deserialize, Serialize};

use super::CredentialCreationOptions;
use crate::webauthn::{ClientDataType, CollectedClientData, PublicKeyCredentialCreationOptions};

// Normal client data from Chrome assertion
const CLIENT_DATA_JSON_STRING: &str = r#"{
        "type":"webauthn.get",
        "challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg",
        "origin":"http://localhost:4000",
        "crossOrigin":false
    }"#;

const EXTENDED_ANDROID_CLIENT_DATA_JSON_STRING: &str = r#"{
        "type": "webauthn.get",
        "challenge": "ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg",
        "origin": "http://localhost:4000",
        "crossOrigin": false,
        "androidPackageName": "com.android.chrome",
        "other_keys_can_be_added_here": "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
    }"#;

/// This is a Secure Payment Confirmation (SPC) response. SPC assertion responses
/// extend the `CollectedClientData` struct by adding a "payment" field that
/// normally does not exist on `CollectedClientData`
const EXTENDED_CLIENT_DATA_JSON_STRING: &str = r#"{
            "type": "payment.get",
            "challenge": "ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg",
            "origin": "http://localhost:4000",
            "crossOrigin": false,
            "payment": {
                "rpId": "localhost",
                "topOrigin": "http://localhost:4000",
                "payeeOrigin": "https://localhost:4000",
                "total": {
                    "value": "1.01",
                    "currency": "APT"
                },
                "instrument": {
                    "icon": "https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico",
                    "displayName": "Petra test"
                }
            }
        }"#;

#[test]
fn ebay_registration() {
    let request = r#"{
            "publicKey": {
                "challenge": [
                    77, 115, 118, 84, 75, 114, 76, 45, 88, 119, 100, 121, 116, 118, 110, 88, 87, 109,
                    65, 77, 98, 100, 120, 77, 67, 119, 70, 103, 112, 70, 98, 122, 83, 81, 110, 74,
                    97, 68, 120, 118, 117, 49, 115, 46, 77, 84, 89, 51, 79, 84, 107, 122, 77, 68, 81,
                    52, 77, 84, 69, 50, 77, 119, 46, 77, 110, 70, 108, 99, 71, 70, 107, 90, 122, 74,
                    48, 99, 109, 69, 46, 120, 117, 120, 86, 77, 108, 97, 90, 100, 78, 70, 112, 54,
                    78, 122, 73, 90, 84, 68, 87, 89, 71, 122, 112, 70, 48, 108, 68, 71, 114, 66, 106,
                    110, 57, 86, 89, 87, 88, 103, 78, 54, 120, 69
                ],
                "rp": {
                    "id": "ebay.ca",
                    "name": "ebay.ca"
                },
                "user": {
                    "id": [50, 113, 101, 112, 97, 100, 103, 50, 116, 114, 97],
                    "name": "R L",
                    "displayName": "R L"
                },
                "pubKeyCredParams": [
                    { "type": "public-key", "alg": -7 },
                    { "type": "public-key", "alg": -35 },
                    { "type": "public-key", "alg": -36 },
                    { "type": "public-key", "alg": -257 },
                    { "type": "public-key", "alg": -258 },
                    { "type": "public-key", "alg": -259 },
                    { "type": "public-key", "alg": -37 },
                    { "type": "public-key", "alg": -38 },
                    { "type": "public-key", "alg": -39 },
                    { "type": "public-key", "alg": -1 }
                ],
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "requireResidentKey": false,
                    "userVerification": "preferred"
                },
                "timeout": 60000,
                "attestation": "direct"
            }
        }"#;

    let deserialized =
        serde_json::from_str::<CredentialCreationOptions>(request).expect("Failed to deserialize");
    // there are 10 in the json but we should be ignoring the `alg: -1`
    assert_eq!(deserialized.public_key.pub_key_cred_params.len(), 9);
}

#[test]
fn webauthn_me_debugger() {
    let request = r#"{
            "publicKey": {
              "rp": {
                "name": "test"
              },
              "user": {
                "id": [
                  208, 3, 44, 155, 74, 109, 149, 31, 234, 107, 36, 243, 249, 29, 32, 48,
                  189, 69, 220, 216, 11, 222, 113, 155, 129, 208, 156, 217, 58, 99, 41,
                  166
                ],
                "name": "test",
                "displayName": "Test User"
              },
              "challenge": [
                21, 69, 217, 214, 15, 130, 240, 139, 91, 76, 136, 60, 96, 131, 25, 110,
                173, 121, 215, 220, 246, 162, 39, 30, 0, 144, 238, 65, 195, 219, 32, 233
              ],
              "pubKeyCredParams": [
                {
                  "type": "public-key",
                  "alg": "-257"
                },
                {
                  "type": "public-key",
                  "alg": "-7"
                }
              ],
              "timeout": "300000"
            }
          }"#;

    let deserialized =
        serde_json::from_str::<CredentialCreationOptions>(request).expect("Failed to deserialize");
    assert_eq!(deserialized.public_key.timeout, Some(300_000));
    assert_eq!(deserialized.public_key.pub_key_cred_params.len(), 2)
}

#[test]
fn test_client_data_type_to_string() {
    let payment_get = ClientDataType::PaymentGet;
    assert_eq!(payment_get.to_string(), "payment.get");

    let webauthn_get = ClientDataType::Get;
    assert_eq!(webauthn_get.to_string(), "webauthn.get");
}

#[test]
fn test_client_data_serialization() {
    // This is the raw client data json byte buffer returned by a webauthn assertion
    let expected_client_data_bytes = r#"{"type":"webauthn.get","challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg","origin":"http://localhost:4000","crossOrigin":false}"#.as_bytes();

    // Deserialize CollectedClientData from JSON string
    let actual_collected_client_data: CollectedClientData =
        serde_json::from_str(CLIENT_DATA_JSON_STRING).unwrap();

    // Check that serde_json byte serialization is also equivalent
    let actual_client_data_bytes = serde_json::to_vec(&actual_collected_client_data).unwrap();
    assert_eq!(
        actual_client_data_bytes.as_slice(),
        expected_client_data_bytes
    )
}

#[test]
fn test_client_data_deserialization_with_extra_and_unknown_data() {
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    #[serde(rename_all = "camelCase")]
    struct AndroidExtraData {
        android_package_name: String,
    }

    let expected_collected_client_data = CollectedClientData {
        ty: ClientDataType::Get,
        challenge: "ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg".to_string(),
        origin: "http://localhost:4000".to_owned(),
        cross_origin: Some(false),
        extra_data: AndroidExtraData {
            android_package_name: "com.android.chrome".to_string(),
        },
        unknown_keys: [(
            "other_keys_can_be_added_here".to_string(),
            serde_json::json!(
                "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
            ),
        )]
        .iter()
        .cloned()
        .collect(),
    };

    // Deserialize CollectedClientData from JSON string
    let actual_collected_client_data: CollectedClientData<AndroidExtraData> =
        serde_json::from_str(EXTENDED_ANDROID_CLIENT_DATA_JSON_STRING).unwrap();

    // Check that serde_json byte serialization is also equivalent
    assert_eq!(
        actual_collected_client_data.extra_data,
        expected_collected_client_data.extra_data,
    );
    assert_eq!(
        actual_collected_client_data.unknown_keys,
        expected_collected_client_data.unknown_keys,
    );
}

#[test]
fn test_client_data_serialization_with_extra_and_unknown_data() {
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AndroidExtraData {
        android_package_name: String,
    }

    // This is the raw client data json byte buffer returned by an Android webauthn assertion
    let expected_client_data_bytes = r#"{"type":"webauthn.get","challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg","origin":"http://localhost:4000","crossOrigin":false,"androidPackageName":"com.android.chrome","other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}"#.as_bytes();

    // Deserialize CollectedClientData from JSON string
    let actual_collected_client_data: CollectedClientData<AndroidExtraData> =
        serde_json::from_str(EXTENDED_ANDROID_CLIENT_DATA_JSON_STRING).unwrap();

    // Check that serde_json byte serialization is also equivalent
    let actual_client_data_bytes = serde_json::to_vec(&actual_collected_client_data).unwrap();
    assert_eq!(
        actual_client_data_bytes.as_slice(),
        expected_client_data_bytes
    )
}

#[test]
fn test_extended_client_data_serialization() {
    // This is the raw client data json byte buffer returned by an SPC webauthn assertion
    let expected_client_data_bytes = r#"{"type":"payment.get","challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg","origin":"http://localhost:4000","crossOrigin":false,"payment":{"rpId":"localhost","topOrigin":"http://localhost:4000","payeeOrigin":"https://localhost:4000","total":{"value":"1.01","currency":"APT"},"instrument":{"icon":"https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico","displayName":"Petra test"}}}"#.as_bytes();

    // Deserialize CollectedClientData from JSON string
    let actual_collected_client_data: CollectedClientData =
        serde_json::from_str(EXTENDED_CLIENT_DATA_JSON_STRING).unwrap();

    // Check that serde_json byte serialization is also equivalent
    let actual_client_data_bytes = serde_json::to_vec(&actual_collected_client_data).unwrap();
    assert_eq!(
        actual_client_data_bytes.as_slice(),
        expected_client_data_bytes
    );

    // This is another byte serialization of client data json, different from the ones above
    let expected_client_data_bytes= r#"{"type":"payment.get","challenge":"eUf1aXwdtHKnIYUXkTgHxmWtYQ_U0c3O8Ldmx3PTA_g","origin":"http://localhost:5173","crossOrigin":false,"payment":{"rpId":"localhost","topOrigin":"http://localhost:5173","payeeOrigin":"https://localhost:4000","total":{"value":"1.01","currency":"APT"},"instrument":{"icon":"https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico","displayName":"Petra test"}},"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"}"#.as_bytes();

    let collected_client_data_string = r#"
            {
              "type": "payment.get",
              "challenge": "eUf1aXwdtHKnIYUXkTgHxmWtYQ_U0c3O8Ldmx3PTA_g",
              "origin": "http://localhost:5173",
              "crossOrigin": false,
              "payment": {
                "rpId": "localhost",
                "topOrigin": "http://localhost:5173",
                "payeeOrigin": "https://localhost:4000",
                "total": {
                  "value": "1.01",
                  "currency": "APT"
                },
                "instrument": {
                  "icon": "https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico",
                  "displayName": "Petra test"
                }
              },
              "other_keys_can_be_added_here": "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
            }"#;

    // Deserialize CollectedClientData from JSON string
    let actual_collected_client_data: CollectedClientData =
        serde_json::from_str(collected_client_data_string).unwrap();

    // Check that serde_json byte serialization is also equivalent
    let actual_client_data_bytes = serde_json::to_vec(&actual_collected_client_data).unwrap();
    assert_eq!(
        actual_client_data_bytes.as_slice(),
        expected_client_data_bytes
    );
}

#[test]
fn test_extended_client_data_encoding_failure() {
    let expected_client_data: CollectedClientData =
        serde_json::from_str(EXTENDED_CLIENT_DATA_JSON_STRING).unwrap();
    let expected_client_data_bytes = serde_json::to_vec(&expected_client_data).unwrap();

    // This is a sample Secure Payment Confirmation (SPC) client_data response
    // based on the EXTENDED_CLIENT_DATA constant instantiated above
    // The ordering of "rpId" and "topOrigin" is switched
    let bad_client_data_json = r#"{
            "type": "payment.get",
            "challenge": "ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg",
            "origin": "http://localhost:4000",
            "crossOrigin": false,
            "payment": {
                "topOrigin": "http://localhost:4000",
                "rpId": "localhost",
                "payeeOrigin": "https://localhost:4000",
                "total": {
                    "value": "1.01",
                    "currency": "APT"
                },
                "instrument": {
                    "icon": "https://aptoslabs.com/assets/favicon-2c9e23abc3a3f4c45038e8c784b0a4ecb9051baa.ico",
                    "displayName": "Petra test"
                }
            }
        }"#;

    let bad_collected_client_data: CollectedClientData =
        serde_json::from_str(bad_client_data_json).unwrap();
    let bad_client_data_bytes = serde_json::to_vec(&bad_collected_client_data).unwrap();

    // Should not be equal
    assert_ne!(bad_client_data_bytes, expected_client_data_bytes);
}

#[test]
fn test_client_data_cross_origin_serialization() {
    let mut ccd: CollectedClientData = serde_json::from_str(CLIENT_DATA_JSON_STRING).unwrap();

    // Check that serialization of cross_origin with value Some(true) resolves to true
    const CROSS_ORIGIN_TRUE: &str = r#"{"type":"webauthn.get","challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg","origin":"http://localhost:4000","crossOrigin":true}"#;
    ccd.cross_origin = Some(true);
    let client_data_json = serde_json::to_string(&ccd).unwrap();
    assert_eq!(client_data_json, CROSS_ORIGIN_TRUE);

    // Check that serialization of cross_origin with value Some(false) resolves to false
    const CROSS_ORIGIN_FALSE: &str = r#"{"type":"webauthn.get","challenge":"ZEvMflZDcwQJmarInnYi88px-6HZcv2Uoxw7-_JOOTg","origin":"http://localhost:4000","crossOrigin":false}"#;
    ccd.cross_origin = Some(false);
    let client_data_json = serde_json::to_string(&ccd).unwrap();
    assert_eq!(client_data_json, CROSS_ORIGIN_FALSE);

    // Check that serialization of cross_origin with value None resolves to false
    ccd.cross_origin = None;
    let client_data_json = serde_json::to_string(&ccd).unwrap();
    assert_eq!(client_data_json, CROSS_ORIGIN_FALSE);
}

#[test]
fn float_as_timeout() {
    let json = r#"{
          "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -257 }
          ],
          "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "requireResidentKey": true,
            "residentKey": "required",
            "userVerification": "required"
          },
          "challenge": "MjAyNC0wNy0zMVQxNTozNDowNFpbQkAyMmI3ZDgwOQ\u003d\u003d",
          "attestation": "none",
          "rp": { "id": "www.paypal.com", "name": "PayPal" },
          "timeout": 1800000.0,
          "user": {
            "id": "ZDExMTQ2ZWNlY2U3YmE2MGYwMGRhMGE2MWJiZjRiMzk2ZDlkOTBjMDcxOWY0N2Y3Yjc2NGQ0ZGRmMGMxMGRlYQ\u003d\u003d",
            "name": "test",
            "displayName": "test"
          }
        }"#;

    let deserialized: PublicKeyCredentialCreationOptions = serde_json::from_str(json).unwrap();

    assert_eq!(deserialized.timeout, Some(1800000));
}

#[test]
fn wells_fargo() {
    let json = r#"{
          "publicKey": {
            "attestation": "direct",
            "authenticatorSelection": {
              "authenticatorAttachment": "platform",
              "userVerification": "required",
              "requireResidentKey": "true"
            },
            "rp": {
              "id": "connect.secure.wellsfargo.com",
              "name": "WellsFargo-Retail"
            },
            "user": {
              "id": [
                81, 202, 116, 36, 100, 106, 38, 134, 235, 221, 219, 16, 73, 74, 100,
                11, 211, 81, 121, 113, 35, 83, 116, 164, 95, 201, 103, 229, 147, 192,
                61, 148, 149, 46, 63, 4, 175, 201, 67, 205, 50, 106, 87, 145, 247, 108,
                172, 173, 174, 164, 247, 196, 28, 102, 205, 12, 234, 58, 155, 62, 128,
                2, 153, 38
              ],
              "name": "test",
              "displayName": "test"
            },
            "pubKeyCredParams": [
              { "alg": "-36", "type": "public-key" },
              { "alg": "-35", "type": "public-key" },
              { "alg": "-7", "type": "public-key" },
              { "alg": "-8", "type": "public-key" },
              { "alg": "-259", "type": "public-key" },
              { "alg": "-258", "type": "public-key" },
              { "alg": "-257", "type": "public-key" }
            ],
            "timeout": 60000,
            "challenge": [
              34, 49, 64, 211, 179, 150, 60, 142, 99, 176, 122, 215, 254, 182, 151, 208,
              24, 18, 157, 60
            ],
            "excludeCredentials": []
          }
        }"#;
    let options: CredentialCreationOptions =
        serde_json::from_str(json).expect("Failed to deserialize options from wells-fargo");

    assert!(options.public_key.authenticator_selection.is_some());
    let authenticator_selection = options.public_key.authenticator_selection.unwrap();

    // was correctly deserialized to a true boolean value
    assert!(authenticator_selection.require_resident_key);
}
