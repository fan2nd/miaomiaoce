use esp_storage::FlashStorage;
use miaomiaoce_c5::provision::{Credentials, RECORD_SIZE, decode_record, encode_record};
#[repr(align(4))]
struct Record([u8; RECORD_SIZE]);
pub struct Store {
    flash: FlashStorage<'static>,
    slot: usize,
    seq: u32,
    pub credentials: Option<Credentials>,
    pub key: Option<[u8; 16]>,
}
impl Store {
    pub fn new(mut flash: FlashStorage<'static>) -> Self {
        let mut found = None;
        for slot in 0..2 {
            let mut buf = Record([0; RECORD_SIZE]);
            if flash
                .read_nor(0x1f0000 + slot as u32 * 4096, &mut buf.0)
                .is_ok()
            {
                if let Some((seq, c, k)) = decode_record(&buf.0) {
                    if found
                        .as_ref()
                        .is_none_or(|(_, prev, _, _)| seq.wrapping_sub(*prev) as i32 > 0)
                    {
                        found = Some((slot, seq, c, k));
                    }
                }
            }
        }
        let (slot, seq, credentials, key) = found.unwrap_or((1, 0, None, None));
        Self {
            flash,
            slot,
            seq,
            credentials,
            key,
        }
    }
    pub fn save(
        &mut self,
        credentials: Option<Credentials>,
        key: Option<[u8; 16]>,
    ) -> Result<(), ()> {
        let slot = 1 - self.slot;
        let offset = 0x1f0000 + slot as u32 * 4096;
        let seq = self.seq.wrapping_add(1);
        let buf = Record(encode_record(seq, credentials.as_ref(), key.as_ref()));
        self.flash.erase(offset, offset + 4096).map_err(|_| ())?;
        self.flash.write_nor(offset, &buf.0).map_err(|_| ())?;
        let mut back = Record([0; RECORD_SIZE]);
        self.flash.read_nor(offset, &mut back.0).map_err(|_| ())?;
        if back.0 != buf.0 {
            return Err(());
        }
        self.slot = slot;
        self.seq = seq;
        self.credentials = credentials;
        self.key = key;
        Ok(())
    }
}
