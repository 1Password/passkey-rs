use super::Aaguid;

#[test]
fn deserialize_byte_str_to_aaguid() {
    let cbor_bytes = [
        0x50, // bytes(16)
        0x02, 0x2b, 0xeb, 0xfd, 0x62, 0x3c, 0xac, 0x25, // data
        0xce, 0xe4, 0xd0, 0x90, 0xb9, 0xf8, 0xb5, 0xaf,
    ];

    let aaguid: Aaguid = ciborium::de::from_reader(cbor_bytes.as_slice())
        .expect("could not deserialize from byte string");
    assert_eq!(
        aaguid,
        Aaguid([
            0x02, 0x2b, 0xeb, 0xfd, 0x62, 0x3c, 0xac, 0x25, 0xce, 0xe4, 0xd0, 0x90, 0xb9, 0xf8,
            0xb5, 0xaf,
        ])
    );
}

#[test]
fn new_empty_truly_zero() {
    assert_eq!(Aaguid::new_empty().0, [0; 16]);
}

#[test]
fn aaguid_serialization_round_trip() {
    let expected = Aaguid::new_empty();
    let mut aaguid_bytes = Vec::with_capacity(17);
    ciborium::ser::into_writer(&expected, &mut aaguid_bytes).expect("could not serialize aaguid");

    let result =
        ciborium::de::from_reader(aaguid_bytes.as_slice()).expect("could not deserialized aaguid");

    assert_eq!(expected, result);
}
