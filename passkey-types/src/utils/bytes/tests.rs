use super::*;
use std::collections::HashMap;
#[test]
fn deserialize_many_formats_into_base64url_vec() {
    let json = r#"{
            "array": [101,195,212,161,191,112,75,189,152,52,121,17,62,113,114,164],
            "base64url": "ZcPUob9wS72YNHkRPnFypA",
            "base64": "ZcPUob9wS72YNHkRPnFypA=="
        }"#;

    let deserialized: HashMap<&str, Bytes> =
        serde_json::from_str(json).expect("failed to deserialize");

    assert_eq!(deserialized["array"], deserialized["base64url"]);
    assert_eq!(deserialized["base64url"], deserialized["base64"]);
}

#[test]
fn deserialization_should_fail() {
    let json = r#"{
            "array": ["ZcPUob9wS72YNHkRPnFypA","ZcPUob9wS72YNHkRPnFypA=="],
        }"#;

    serde_json::from_str::<HashMap<&str, Bytes>>(json)
        .expect_err("did not give an error as expected.");
}
