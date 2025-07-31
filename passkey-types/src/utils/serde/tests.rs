use super::*;

#[test]
fn from_float_representations() {
    #[derive(Deserialize)]
    struct FromFloat {
        #[serde(deserialize_with = "maybe_stringified_num")]
        num: Option<u32>,
    }

    let float_with_0 = r#"{"num": 0.0}"#;
    let result: FromFloat = serde_json::from_str(float_with_0).expect("failed to parse from 0.0");
    assert_eq!(result.num, Some(0));

    let float_ends_with_0 = r#"{"num": 1800.0}"#;
    let result: FromFloat =
        serde_json::from_str(float_ends_with_0).expect("failed to parse from 1800.0");
    assert_eq!(result.num, Some(1800));

    let float_ends_with_num = r#"{"num": 1800.1234}"#;
    let result: FromFloat =
        serde_json::from_str(float_ends_with_num).expect("failed to parse from 1800.1234");
    assert_eq!(result.num, Some(1800));

    let sub_zero = r#"{"num": 0.1234}"#;
    let result: FromFloat = serde_json::from_str(sub_zero).expect("failed to parse from 0.1234");
    assert_eq!(result.num, Some(0));

    let scientific = r#"{"num": 1.0e-308}"#;
    let result: FromFloat =
        serde_json::from_str(scientific).expect("failed to parse from 1.0e-308");
    assert_eq!(result.num, Some(0));

    // Ignoring these cases because `serde_json` will fail to deserialize these values
    // https://github.com/serde-rs/json/issues/842

    // let nan = r#"{"num": NaN}"#;
    // let result: FromFloat = serde_json::from_str(nan).expect("failed to parse from NaN");
    // assert_eq!(result.num, Some(0));

    // let inf = r#"{"num": Infinity}"#;
    // let result: FromFloat = serde_json::from_str(inf).expect("failed to parse from Infinity");
    // assert_eq!(result.num, Some(0));

    // let neg_inf = r#"{"num": -Infinity}"#;
    // let result: FromFloat =
    //     serde_json::from_str(neg_inf).expect("failed to parse from -Infinity");
    // assert_eq!(result.num, Some(0));

    let float_with_0_str = r#"{"num": "0.0"}"#;
    let result: FromFloat =
        serde_json::from_str(float_with_0_str).expect("failed to parse from stringified 0.0");
    assert_eq!(result.num, Some(0));

    let float_ends_with_0_str = r#"{"num": "1800.0"}"#;
    let result: FromFloat = serde_json::from_str(float_ends_with_0_str)
        .expect("failed to parse from stringified 1800.0");
    assert_eq!(result.num, Some(1800));

    let float_ends_with_num_str = r#"{"num": "1800.1234"}"#;
    let result: FromFloat = serde_json::from_str(float_ends_with_num_str)
        .expect("failed to parse from stringified 1800.1234");
    assert_eq!(result.num, Some(1800));

    let sub_zero_str = r#"{"num": "0.1234"}"#;
    let result: FromFloat =
        serde_json::from_str(sub_zero_str).expect("failed to parse from stringified 0.1234");
    assert_eq!(result.num, Some(0));

    let scientific_str = r#"{"num": "1.0e-308"}"#;
    let result: FromFloat =
        serde_json::from_str(scientific_str).expect("failed to parse from stringified 1.0e-308");
    assert_eq!(result.num, Some(0));

    let nan_str = r#"{"num": "NaN"}"#;
    let result: FromFloat =
        serde_json::from_str(nan_str).expect("failed to parse from stringified NaN");
    assert_eq!(result.num, Some(0));

    let inf_str = r#"{"num": "Infinity"}"#;
    let result: FromFloat =
        serde_json::from_str(inf_str).expect("failed to parse from stringified Infinity");
    assert_eq!(result.num, Some(0));

    let neg_inf_str = r#"{"num": "-Infinity"}"#;
    let result: FromFloat =
        serde_json::from_str(neg_inf_str).expect("failed to parse from stringified -Infinity");
    assert_eq!(result.num, Some(0));
}
