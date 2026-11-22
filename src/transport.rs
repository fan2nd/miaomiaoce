//! Firmware adapters for the unmodified upstream embedded-tls library.
use core::cell::RefCell;
use embassy_crypto_rustcrypto as _;
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_time::{Duration, Instant, with_timeout};
use embedded_tls::embassy_crypto;
use embedded_tls::{Aes128GcmSha256, Certificate, TlsClock, TlsConnection, webpki::CertVerifier};

pub const HOST: &str = "broker.emqx.io";
pub const PORT: u16 = 8883;
pub const TOPIC: &str = "miaomiaoce/a4c1384d08a4/state";

struct HardwareRandom;
impl embassy_crypto::driver::Rng for HardwareRandom {
    fn fill_bytes(output: &mut [u8]) {
        // Wi-Fi/BLE is active before TLS. Never substitute a deterministic RNG.
        esp_hal::rng::Rng::new().read(output);
    }
}
embassy_crypto::rng_impl!(HardwareRandom);

static CLOCK: Mutex<CriticalSectionRawMutex, RefCell<Option<(u64, Instant)>>> =
    Mutex::new(RefCell::new(None));
pub struct NetworkClock;
impl TlsClock for NetworkClock {
    fn now() -> Option<u64> {
        // None would disable date validation in upstream. Before synchronization,
        // give an invalid epoch instead, so contemporary certificates fail closed.
        Some(CLOCK.lock(|clock| {
            clock
                .borrow()
                .as_ref()
                .map_or(0, |(unix, at)| unix.saturating_add(at.elapsed().as_secs()))
        }))
    }
}
pub fn set_time(unix: u64) -> Result<(), ()> {
    if unix < miaomiaoce_c5::sntp::MIN_UNIX_TIME {
        return Err(());
    }
    CLOCK.lock(|clock| *clock.borrow_mut() = Some((unix, Instant::now())));
    Ok(())
}
pub fn verifier() -> CertVerifier<'static, Aes128GcmSha256, NetworkClock, 4096> {
    CertVerifier::new(Certificate::X509(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/broker-ca.der"
    ))))
}
pub async fn send<S: embedded_io_async::Read + embedded_io_async::Write>(
    tls: &mut TlsConnection<'_, S, Aes128GcmSha256>,
    packet: &[u8],
) -> Result<(), ()> {
    with_timeout(Duration::from_secs(5), async {
        let mut written = 0;
        while written < packet.len() {
            let n = tls.write(&packet[written..]).await.map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            written += n;
        }
        tls.flush().await.map_err(|_| ())
    })
    .await
    .map_err(|_| ())?
}
