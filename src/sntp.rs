//! Bounded SNTP response validation. Network time is not authenticated.
pub const MIN_UNIX_TIME: u64 = 1_767_225_600; // 2026-01-01
const NTP_OFFSET: u64 = 2_208_988_800;

pub fn request(nonce: [u8; 8]) -> [u8; 48] {
    let mut packet = [0u8; 48];
    packet[0] = 0x23; // Version 4, client.
    packet[40..48].copy_from_slice(&nonce);
    packet
}
pub fn response(packet: &[u8], nonce: &[u8; 8]) -> Result<u64, ()> {
    if packet.len() < 48
        || packet[0] >> 6 == 3
        || packet[0] & 7 != 4
        || !matches!((packet[0] >> 3) & 7, 3 | 4)
        || !(1..=15).contains(&packet[1])
        || &packet[24..32] != nonce
        || packet[40..48] == [0; 8]
    {
        return Err(());
    }
    let raw = u32::from_be_bytes(packet[40..44].try_into().map_err(|_| ())?) as u64;
    // Resolve the 2036 NTP rollover within the supported 2026..2100 interval.
    let ntp = if raw < NTP_OFFSET {
        raw + (1u64 << 32)
    } else {
        raw
    };
    let unix = ntp - NTP_OFFSET;
    if !(MIN_UNIX_TIME..4_102_444_800).contains(&unix) {
        return Err(());
    }
    Ok(unix)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_reply_and_rollover() {
        let nonce = [42; 8];
        for unix in [MIN_UNIX_TIME, 2_208_988_900] {
            let mut p = [0u8; 48];
            p[0] = 0x24;
            p[1] = 2;
            p[24..32].copy_from_slice(&nonce);
            p[40..44].copy_from_slice(&((unix + NTP_OFFSET) as u32).to_be_bytes());
            assert_eq!(response(&p, &nonce), Ok(unix));
            assert!(response(&p, &[0; 8]).is_err());
            assert!(response(&p[..47], &nonce).is_err());
            p[0] |= 0xc0;
            assert!(response(&p, &nonce).is_err());
            p[0] = 0x24;
            p[1] = 0;
            assert!(response(&p, &nonce).is_err());
        }
    }
}
