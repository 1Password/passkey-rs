use ciborium::cbor;

use super::{Aaguid, AuthenticatorTransport, Extension, Options, Response, Version};
#[test]
fn serialization_round_trip() {
    let expected = Response {
        versions: vec![Version::FIDO_2_0],
        extensions: Some(vec![
            Extension::HmacSecret,
            Extension::Unknown("credProtect".into()),
        ]),
        aaguid: Aaguid::new_empty(),
        options: Some(Options {
            rk: true,
            uv: Some(true),
            ..Default::default()
        }),
        max_msg_size: None,
        pin_protocols: Some(vec![1]),
        transports: Some(vec![
            AuthenticatorTransport::Internal,
            AuthenticatorTransport::Hybrid,
        ]),
    };
    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&expected, &mut serialized).expect("Could not serialize to cbor");

    let deserialized: Response =
        ciborium::de::from_reader(serialized.as_slice()).expect("Could not deserialize");

    assert_eq!(deserialized, expected);
}

#[test]
fn serialization_expected_wire_fmt() {
    let aaguid = Aaguid::new_empty();
    let input = Response {
        versions: vec![Version::FIDO_2_0],
        extensions: Some(vec![
            Extension::HmacSecret,
            Extension::Unknown("credProtect".into()),
        ]),
        aaguid,
        options: Some(Options {
            rk: true,
            uv: Some(true),
            plat: false,
            ..Default::default()
        }),
        max_msg_size: None,
        pin_protocols: Some(vec![1]),
        transports: Some(vec![
            AuthenticatorTransport::Internal,
            AuthenticatorTransport::Hybrid,
        ]),
    };
    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&input, &mut serialized).expect("Could not serialize to cbor");

    let deserialized: ciborium::value::Value =
        ciborium::de::from_reader(serialized.as_slice()).expect("Could not deserialize");

    let expected = cbor!({
        0x01 => vec!["FIDO_2_0"],
        0x02 => vec!["hmac-secret", "credProtect"],
        0x03 => ciborium::value::Value::Bytes([0;16].into()),
        0x04 => {
            "plat" => false,
            "rk" => true,
            "up" => true,
            "uv" => true
            // clientPin should be skipped
        },
        // maxMsgSize should be skipped
        0x06 => vec![1],
        0x09 => vec!["internal", "hybrid"]
    })
    .unwrap();

    assert_eq!(deserialized, expected);
}

#[test]
fn unknown_transports_gets_ignored() {
    let input = cbor!({
        0x01 => vec!["FIDO_2_0", "FIDO_2_1"],
        0x02 => vec!["hmac-secret", "credProtect"],
        0x03 => ciborium::value::Value::Bytes([0;16].into()),
        0x04 => {
            "plat" => false,
            "rk" => true,
            "up" => true,
            "uv" => true
            // clientPin should be skipped
        },
        // maxMsgSize should be skipped
        0x06 => vec![1],
        0x09 => vec!["lora", "hybrid"]
    })
    .unwrap();

    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&input, &mut serialized).expect("Could not serialize to cbor");

    let deserialized: Response =
        ciborium::de::from_reader(serialized.as_slice()).expect("Could not deserialize");

    let expected = Response {
        versions: vec![Version::FIDO_2_0, Version::Unknown("FIDO_2_1".into())],
        extensions: Some(vec![
            Extension::HmacSecret,
            Extension::Unknown("credProtect".into()),
        ]),
        aaguid: Aaguid::new_empty(),
        options: Some(Options {
            rk: true,
            uv: Some(true),
            plat: false,
            ..Default::default()
        }),
        max_msg_size: None,
        pin_protocols: Some(vec![1]),
        transports: Some(vec![AuthenticatorTransport::Hybrid]),
    };

    assert_eq!(expected, deserialized);
}
