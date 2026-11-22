use heapless::{String, Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    Open = 0,
    Wpa2 = 1,
    Wpa3 = 2,
    Unsupported = 3,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    pub ssid: String<32>,
    pub rssi: i8,
    pub channel: u8,
    pub security: Security,
}
#[derive(Clone, PartialEq, Eq)] // Deliberately no Debug: contains the password.
pub struct Credentials {
    pub ssid: String<32>,
    pub password: String<64>,
    pub security: Security,
}

pub enum Action {
    Scan,
    Prompt(String<32>),
    Connect(Credentials, u8),
    Status,
    Cancelled,
    Help,
    Key([u8; 16]),
    Invalid,
}
#[derive(Default)]
pub struct Menu {
    networks: Vec<Network, 24>,
    selected: Option<Network>,
}
impl Menu {
    pub fn replace_networks(&mut self, mut networks: Vec<Network, 24>) {
        networks.sort_unstable_by(|a, b| b.rssi.cmp(&a.rssi).then(a.ssid.cmp(&b.ssid)));
        self.networks = networks;
        self.selected = None;
    }
    pub fn networks(&self) -> &[Network] {
        &self.networks
    }
    pub fn waiting_password(&self) -> bool {
        self.selected.is_some()
    }
    pub fn input(&mut self, line: &str) -> Action {
        if let Some(selected) = &self.selected {
            if line == "cancel" {
                self.selected = None;
                return Action::Cancelled;
            }
            // Password whitespace is significant; do not trim it.
            let valid = if selected.security == Security::Open {
                line.is_empty()
            } else {
                (8..=63).contains(&line.len())
                    || (line.len() == 64 && line.bytes().all(|b| b.is_ascii_hexdigit()))
            };
            if !valid {
                return Action::Invalid;
            }
            let selected = self.selected.take().unwrap();
            return Action::Connect(
                Credentials {
                    ssid: selected.ssid,
                    password: String::try_from(line).unwrap(),
                    security: selected.security,
                },
                selected.channel,
            );
        }
        let line = line.trim();
        match line {
            "scan" => {
                self.networks.clear();
                Action::Scan
            }
            "status" => Action::Status,
            "help" | "?" => Action::Help,
            _ if line.starts_with("key ") => match crate::sensor::hex_key(&line[4..]) {
                Ok(k) => Action::Key(k),
                Err(_) => Action::Invalid,
            },
            _ => {
                let Some(n) = line.parse::<usize>().ok().and_then(|n| n.checked_sub(1)) else {
                    return Action::Invalid;
                };
                let Some(net) = self.networks.get(n) else {
                    return Action::Invalid;
                };
                if net.security == Security::Unsupported {
                    return Action::Invalid;
                }
                self.selected = Some(net.clone());
                Action::Prompt(net.ssid.clone())
            }
        }
    }
}

/// Two-slot Flash record format. Integrity/version checks reject interrupted writes.
pub const RECORD_SIZE: usize = 160;
pub fn encode_record(
    seq: u32,
    credentials: Option<&Credentials>,
    key: Option<&[u8; 16]>,
) -> [u8; RECORD_SIZE] {
    let mut out = [0u8; RECORD_SIZE];
    out[..4].copy_from_slice(b"MMC1");
    out[4..8].copy_from_slice(&seq.to_le_bytes());
    if let Some(c) = credentials {
        out[8] = c.ssid.len() as u8;
        out[9] = c.password.len() as u8;
        out[10] = c.security as u8;
        out[12..12 + c.ssid.len()].copy_from_slice(c.ssid.as_bytes());
        out[44..44 + c.password.len()].copy_from_slice(c.password.as_bytes());
    }
    if let Some(k) = key {
        out[11] = 1;
        out[108..124].copy_from_slice(k);
    }
    let crc = crc32(&out[..156]);
    out[156..].copy_from_slice(&crc.to_le_bytes());
    out
}
pub fn decode_record(
    bytes: &[u8; RECORD_SIZE],
) -> Option<(u32, Option<Credentials>, Option<[u8; 16]>)> {
    if &bytes[..4] != b"MMC1"
        || crc32(&bytes[..156]) != u32::from_le_bytes(bytes[156..].try_into().ok()?)
    {
        return None;
    }
    let seq = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
    let len = bytes[8] as usize;
    let passlen = bytes[9] as usize;
    if len > 32 || passlen > 64 || bytes[11] > 1 {
        return None;
    }
    let security = match bytes[10] {
        0 => Security::Open,
        1 => Security::Wpa2,
        2 => Security::Wpa3,
        _ => return None,
    };
    let credentials = if len == 0 {
        None
    } else {
        Some(Credentials {
            ssid: String::try_from(core::str::from_utf8(&bytes[12..12 + len]).ok()?).ok()?,
            password: String::try_from(core::str::from_utf8(&bytes[44..44 + passlen]).ok()?)
                .ok()?,
            security,
        })
    };
    let key = if bytes[11] == 1 {
        Some(bytes[108..124].try_into().ok()?)
    } else {
        None
    };
    Some((seq, credentials, key))
}
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320u32 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sorted_selection_password_spaces_and_persistence() {
        let mut menu = Menu::default();
        let mut nets = Vec::new();
        for (ssid, rssi) in [("weak", -90), ("my wifi", -35), ("middle", -60)] {
            nets.push(Network {
                ssid: String::try_from(ssid).unwrap(),
                rssi,
                channel: 5,
                security: Security::Wpa2,
            })
            .unwrap();
        }
        menu.replace_networks(nets);
        assert_eq!(menu.networks()[0].ssid, "my wifi");
        assert!(matches!(menu.input("0"), Action::Invalid));
        assert!(matches!(menu.input("1"), Action::Prompt(_)));
        assert!(matches!(menu.input("short"), Action::Invalid));
        let Action::Connect(creds, 5) = menu.input(" password with spaces ") else {
            panic!()
        };
        assert_eq!(creds.password, " password with spaces ");
        let mut record = encode_record(7, Some(&creds), Some(&[42; 16]));
        let (seq, back, key) = decode_record(&record).unwrap();
        assert_eq!(seq, 7);
        assert!(back.unwrap() == creds);
        assert_eq!(key, Some([42; 16]));
        record[24] ^= 1;
        assert!(decode_record(&record).is_none());
        assert!(decode_record(&[255; RECORD_SIZE]).is_none());
    }
}

#[cfg(test)]
mod menu_edges {
    use super::*;
    fn network(name: &str, security: Security) -> Network {
        Network {
            ssid: String::try_from(name).unwrap(),
            rssi: -50,
            channel: 6,
            security,
        }
    }
    #[test]
    fn rescan_invalidates_numbers_and_cancel_leaves_list() {
        let mut m = Menu::default();
        m.replace_networks(Vec::from_slice(&[network("home", Security::Wpa2)]).unwrap());
        assert!(matches!(m.input("2"), Action::Invalid));
        assert!(matches!(m.input("1"), Action::Prompt(_)));
        assert!(matches!(m.input("cancel"), Action::Cancelled));
        assert!(matches!(m.input("1"), Action::Prompt(_)));
        assert!(matches!(m.input("cancel"), Action::Cancelled));
        assert!(matches!(m.input("scan"), Action::Scan));
        assert!(matches!(m.input("1"), Action::Invalid));
    }
    #[test]
    fn open_network_and_unsupported_security() {
        let mut m = Menu::default();
        m.replace_networks(
            Vec::from_slice(&[
                network("a-open", Security::Open),
                network("b-enterprise", Security::Unsupported),
            ])
            .unwrap(),
        );
        assert!(matches!(m.input("2"), Action::Invalid));
        assert!(matches!(m.input("1"), Action::Prompt(_)));
        assert!(matches!(m.input("password"), Action::Invalid));
        let Action::Connect(c, 6) = m.input("") else {
            panic!()
        };
        assert!(c.password.is_empty());
        assert_eq!(c.security, Security::Open);
    }
}
