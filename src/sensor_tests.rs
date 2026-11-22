use super::*;

fn encrypted(plain: &[u8], with_mac: bool, count: u8) -> Vec<u8, 128> {
    let key = [0x42; 16]; // Synthetic test key; never the user's key.
    let mut frame =
        Vec::from_slice(&[if with_mac { 0x58 } else { 0x48 }, 0x59, 0xdf, 0x6b, count]).unwrap();
    let mut mac_le = MAC;
    mac_le.reverse();
    if with_mac {
        frame.extend_from_slice(&mac_le).unwrap();
    }
    let mut nonce = [0u8; 12];
    nonce[..6].copy_from_slice(&mac_le);
    nonce[6..].copy_from_slice(&[0xdf, 0x6b, count, 0x48, 0, 0]);
    let mut data = Vec::<u8, 64>::from_slice(plain).unwrap();
    let tag = Cipher::new((&key).into())
        .encrypt_in_place_detached((&nonce).into(), &[0x11], data.as_mut_slice())
        .unwrap();
    frame.extend_from_slice(&data).unwrap();
    frame.extend_from_slice(&[0x48, 0, 0]).unwrap();
    frame.extend_from_slice(&tag).unwrap();
    frame
}

#[test]
fn decodes_multiple_objects_with_and_without_mac() {
    for with_mac in [true, false] {
        let frame = encrypted(
            &[
                1, 0x4c, 4, 0xcd, 0xcc, 0xa0, 0x41, 8, 0x4c, 4, 0, 0, 0x64, 0x42, 0x1d, 0x4c, 2,
                0xad, 4,
            ],
            with_mac,
            70,
        );
        let decoded = decrypt(&[0x42; 16], &MAC, &frame).unwrap();
        assert_eq!(decoded.counter, 0x4846);
        assert_eq!(
            decoded.measurements.as_slice(),
            &[
                Measurement::Temperature(20.1),
                Measurement::Humidity(57.0),
                Measurement::Co2(1197)
            ]
        );
    }
}
#[test]
fn rejects_wrong_key_tampering_and_truncation() {
    let mut f = encrypted(&[0x1d, 0x4c, 2, 0xad, 4], false, 1);
    assert_eq!(decrypt(&[0x43; 16], &MAC, &f), Err(Error::Authentication));
    for n in 0..f.len() {
        assert!(decrypt(&[0x42; 16], &MAC, &f[..n]).is_err());
    }
    f[5] ^= 1;
    assert_eq!(decrypt(&[0x42; 16], &MAC, &f), Err(Error::Authentication));
}
#[test]
fn rejects_nan_malformed_objects_and_bad_ad_lengths() {
    for p in [&[1, 0x4c, 4, 0, 0, 0xc0, 0x7f][..], &[0x1d, 0x4c, 3, 1][..]] {
        assert!(decrypt(&[0x42; 16], &MAC, &encrypted(p, false, 1)).is_err());
    }
    assert_eq!(service_data(&[9, 0x16, 0x95, 0xfe]), Err(Error::Truncated));
    assert_eq!(
        service_data(&[2, 1, 6, 5, 0x16, 0x95, 0xfe, 1, 2]).unwrap(),
        Some(&[1, 2][..])
    );
}
#[test]
fn duplicate_does_not_refresh_observation_and_fields_expire() {
    let frame = decrypt(
        &[0x42; 16],
        &MAC,
        &encrypted(&[0x1d, 0x4c, 2, 0xad, 4], true, 1),
    )
    .unwrap();
    let mut state = State::default();
    assert!(state.apply(&frame, 1000, -50));
    assert!(!state.apply(&frame, 5000, -40));
    let json = state.json(6000).unwrap();
    assert!(json.contains("\"co2_ppm\":1197,\"co2_ppm_age_ms\":5000"));
    assert!(json.contains("\"temperature_c\":null"));
    assert!(state.json(901001).unwrap().contains("\"co2_ppm\":null"));
}
