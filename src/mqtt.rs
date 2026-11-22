//! MQTT 3.1.1 packet encoding and bounded server-response parsing.
use heapless::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Capacity,
    Invalid,
    Rejected(u8),
}
pub type Packet = Vec<u8, 768>;

fn bytes(out: &mut Packet, data: &[u8]) -> Result<(), Error> {
    out.extend_from_slice(data).map_err(|_| Error::Capacity)
}
fn text(out: &mut Packet, s: &str) -> Result<(), Error> {
    let len = u16::try_from(s.len()).map_err(|_| Error::Capacity)?;
    if s.contains('\0') {
        return Err(Error::Invalid);
    }
    bytes(out, &len.to_be_bytes())?;
    bytes(out, s.as_bytes())
}
fn wrap(header: u8, body: &[u8]) -> Result<Packet, Error> {
    let mut out = Packet::new();
    bytes(&mut out, &[header])?;
    let mut n = body.len();
    loop {
        let mut b = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            b |= 128;
        }
        bytes(&mut out, &[b])?;
        if n == 0 {
            break;
        }
    }
    bytes(&mut out, body)?;
    Ok(out)
}
pub fn connect(client_id: &str) -> Result<Packet, Error> {
    if client_id.is_empty() {
        return Err(Error::Invalid);
    }
    let mut body = Packet::new();
    // Protocol name, version 4, clean session, keepalive 60 seconds.
    bytes(&mut body, b"\x00\x04MQTT\x04\x02\x00\x3c")?;
    text(&mut body, client_id)?;
    wrap(0x10, &body)
}
pub fn publish(topic: &str, payload: &[u8]) -> Result<Packet, Error> {
    if topic.is_empty() || topic.contains(['+', '#']) {
        return Err(Error::Invalid);
    }
    let mut body = Packet::new();
    text(&mut body, topic)?;
    bytes(&mut body, payload)?;
    wrap(0x30, &body) // QoS 0, no retained data on the public broker.
}
pub const PINGREQ: &[u8] = &[0xc0, 0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Connected,
    PingResponse,
}

/// CONNACK and PINGRESP can be fragmented/coalesced across TLS/TCP reads.
#[derive(Default)]
pub struct Receiver {
    buf: Vec<u8, 32>,
}
impl Receiver {
    pub fn feed(&mut self, data: &[u8]) -> Result<Vec<Event, 8>, Error> {
        let mut events = Vec::new();
        for &b in data {
            self.buf.push(b).map_err(|_| Error::Capacity)?;
            if self.buf.len() < 2 {
                continue;
            }
            let needed = match self.buf[0] {
                0x20 if self.buf[1] == 2 => 4,
                0xd0 if self.buf[1] == 0 => 2,
                _ => return Err(Error::Invalid),
            };
            if self.buf.len() == needed {
                let event = if self.buf[0] == 0x20 {
                    if self.buf[2] != 0 {
                        return Err(Error::Invalid);
                    }
                    if self.buf[3] != 0 {
                        return Err(Error::Rejected(self.buf[3]));
                    }
                    Event::Connected
                } else {
                    Event::PingResponse
                };
                events.push(event).map_err(|_| Error::Capacity)?;
                self.buf.clear();
            }
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_packets_and_fragmentation() {
        assert_eq!(
            connect("c2").unwrap().as_slice(),
            b"\x10\x0e\x00\x04MQTT\x04\x02\x00\x3c\x00\x02c2"
        );
        assert_eq!(
            publish("t", b"{}{}").unwrap().as_slice(),
            b"\x30\x07\x00\x01t{}{}"
        );
        let mut r = Receiver::default();
        assert!(r.feed(&[0x20]).unwrap().is_empty());
        assert!(r.feed(&[2, 0]).unwrap().is_empty());
        assert_eq!(
            r.feed(&[0, 0xd0, 0]).unwrap().as_slice(),
            &[Event::Connected, Event::PingResponse]
        );
        assert_eq!(
            Receiver::default().feed(&[0x20, 2, 0, 5]),
            Err(Error::Rejected(5))
        );
    }
}
