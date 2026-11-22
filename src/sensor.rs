use aes::Aes128;
use ccm::{
    Ccm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
    consts::{U4, U12},
};
use core::fmt::Write;
use heapless::{String, Vec};

type Cipher = Ccm<Aes128, U4, U12>;
pub const PRODUCT_ID: u16 = 0x6bdf;
pub const MAC: [u8; 6] = [0xa4, 0xc1, 0x38, 0x4d, 0x08, 0xa4];

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    Truncated,
    Unsupported,
    WrongDevice,
    Authentication,
    InvalidValue,
    Capacity,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Measurement {
    Temperature(f32),
    Humidity(f32),
    Co2(u16),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub counter: u32,
    pub measurements: Vec<Measurement, 8>,
}

/// Address is in human-readable order. `data` excludes the FE95 service UUID.
pub fn decrypt(key: &[u8; 16], expected_mac: &[u8; 6], data: &[u8]) -> Result<Frame, Error> {
    if data.len() < 12 {
        return Err(Error::Truncated);
    }
    let fc = u16::from_le_bytes([data[0], data[1]]);
    if u16::from_le_bytes([data[2], data[3]]) != PRODUCT_ID {
        return Err(Error::WrongDevice);
    }
    if !matches!(fc >> 12, 4 | 5) || fc & 0x48 != 0x48 || fc & 0x80 != 0 {
        return Err(Error::Unsupported);
    }
    let mut mac_le = *expected_mac;
    mac_le.reverse();
    let mut offset = 5;
    if fc & 0x10 != 0 {
        if data.get(offset..offset + 6) != Some(mac_le.as_slice()) {
            return Err(Error::WrongDevice);
        }
        offset += 6;
    }
    if fc & 0x20 != 0 {
        let capability = *data.get(offset).ok_or(Error::Truncated)?;
        offset += 1 + usize::from(capability & 0x20 != 0);
    }
    if data.len() < offset + 7 {
        return Err(Error::Truncated);
    }
    let end = data.len() - 7;
    let mut nonce = [0u8; 12];
    nonce[..6].copy_from_slice(&mac_le);
    nonce[6..9].copy_from_slice(&data[2..5]);
    nonce[9..].copy_from_slice(&data[end..end + 3]);
    let mut plaintext =
        Vec::<u8, 64>::from_slice(&data[offset..end]).map_err(|_| Error::Capacity)?;
    Cipher::new(key.into())
        .decrypt_in_place_detached(
            (&nonce).into(),
            &[0x11],
            plaintext.as_mut_slice(),
            GenericArray::from_slice(&data[end + 3..]),
        )
        .map_err(|_| Error::Authentication)?;
    let counter = u32::from_le_bytes([data[4], data[end], data[end + 1], data[end + 2]]);
    let mut measurements = Vec::new();
    let mut pos = 0;
    while pos < plaintext.len() {
        let h = plaintext.get(pos..pos + 3).ok_or(Error::Truncated)?;
        let id = u16::from_le_bytes([h[0], h[1]]);
        let len = h[2] as usize;
        let value = plaintext
            .get(pos + 3..pos + 3 + len)
            .ok_or(Error::Truncated)?;
        let item = match id {
            0x4c01 | 0x4c08 => {
                let bytes: [u8; 4] = value.try_into().map_err(|_| Error::InvalidValue)?;
                let v = f32::from_le_bytes(bytes);
                if !v.is_finite() {
                    return Err(Error::InvalidValue);
                }
                if id == 0x4c01 && (-30.0..=100.0).contains(&v) {
                    Some(Measurement::Temperature(v))
                } else if id == 0x4c08 && (0.0..=100.0).contains(&v) {
                    Some(Measurement::Humidity(v))
                } else {
                    return Err(Error::InvalidValue);
                }
            }
            // MHO-H413 capture: 1d4c02ad04 -> 1197 ppm. Confirmed by decryption;
            // physical display comparison is still required for field semantics.
            0x4c1d => {
                let bytes: [u8; 2] = value.try_into().map_err(|_| Error::InvalidValue)?;
                let v = u16::from_le_bytes(bytes);
                if !(400..=5000).contains(&v) {
                    return Err(Error::InvalidValue);
                }
                Some(Measurement::Co2(v))
            }
            _ => None,
        };
        if let Some(v) = item {
            measurements.push(v).map_err(|_| Error::Capacity)?;
        }
        pos += 3 + len;
    }
    Ok(Frame {
        counter,
        measurements,
    })
}

/// Parse bounded BLE advertising structures, including multiple AD elements.
pub fn service_data(ad: &[u8]) -> Result<Option<&[u8]>, Error> {
    let mut pos = 0;
    while pos < ad.len() {
        let len = ad[pos] as usize;
        if len == 0 {
            break;
        }
        let field = ad.get(pos + 1..pos + 1 + len).ok_or(Error::Truncated)?;
        if field.len() >= 3 && field[..3] == [0x16, 0x95, 0xfe] {
            return Ok(Some(&field[3..]));
        }
        pos += len + 1;
    }
    Ok(None)
}

pub fn hex_key(text: &str) -> Result<[u8; 16], Error> {
    if text.len() != 32 {
        return Err(Error::InvalidValue);
    }
    let mut result = [0u8; 16];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(Error::InvalidValue),
        };
        result[i] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug)]
struct Timed<T> {
    value: T,
    at_ms: u64,
}

#[derive(Default)]
pub struct State {
    temperature: Option<Timed<f32>>,
    humidity: Option<Timed<f32>>,
    co2: Option<Timed<u16>>,
    recent: Vec<u32, 32>,
    pub last_counter: Option<u32>,
    pub last_rssi: i8,
}

impl State {
    /// Deduplicate only authenticated frames. Do not refresh ages on repeats.
    pub fn apply(&mut self, frame: &Frame, now_ms: u64, rssi: i8) -> bool {
        if self.recent.contains(&frame.counter) {
            return false;
        }
        if self.recent.is_full() {
            self.recent.remove(0);
        }
        let _ = self.recent.push(frame.counter);
        if frame.measurements.is_empty() {
            return false;
        }
        for m in &frame.measurements {
            match *m {
                Measurement::Temperature(v) => {
                    self.temperature = Some(Timed {
                        value: v,
                        at_ms: now_ms,
                    })
                }
                Measurement::Humidity(v) => {
                    self.humidity = Some(Timed {
                        value: v,
                        at_ms: now_ms,
                    })
                }
                Measurement::Co2(v) => {
                    self.co2 = Some(Timed {
                        value: v,
                        at_ms: now_ms,
                    })
                }
            }
        }
        self.last_counter = Some(frame.counter);
        self.last_rssi = rssi;
        true
    }

    /// A missing/stale field is null, never zero. Each field retains its own age.
    pub fn json(&self, now_ms: u64) -> Result<String<512>, Error> {
        let mut out = String::new();
        write!(
            out,
            "{{\"uptime_ms\":{now_ms},\"frame_counter\":{},\"rssi\":{}",
            self.last_counter.unwrap_or(0),
            self.last_rssi
        )
        .map_err(|_| Error::Capacity)?;
        macro_rules! field {
            ($name:literal, $field:expr) => {
                if let Some(t) = $field {
                    let age = now_ms.saturating_sub(t.at_ms);
                    if age <= 900_000 {
                        write!(
                            out,
                            concat!(",\"", $name, "\":{},\"", $name, "_age_ms\":{}"),
                            t.value, age
                        )
                    } else {
                        write!(
                            out,
                            concat!(",\"", $name, "\":null,\"", $name, "_age_ms\":{}"),
                            age
                        )
                    }
                } else {
                    write!(
                        out,
                        concat!(",\"", $name, "\":null,\"", $name, "_age_ms\":null")
                    )
                }
                .map_err(|_| Error::Capacity)?;
            };
        }
        field!("temperature_c", self.temperature);
        field!("humidity_percent", self.humidity);
        field!("co2_ppm", self.co2);
        out.push('}').map_err(|_| Error::Capacity)?;
        Ok(out)
    }
}

#[cfg(test)]
#[path = "sensor_tests.rs"]
mod tests;
