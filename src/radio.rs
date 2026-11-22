use super::*;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, with_timeout};
use esp_radio::{
    ble::controller::BleConnector,
    wifi::{
        self, AuthenticationMethod as Auth, AuthenticationMethodConfig as AuthConfig,
        sta::StationConfig,
    },
};
use miaomiaoce_c5::provision::Security;

static PAUSE_BLE: AtomicBool = AtomicBool::new(false);
static BLE_PAUSED: Signal<CriticalSectionRawMutex, ()> = Signal::new();

#[embassy_executor::task]
pub async fn wifi(mut controller: wifi::WifiController<'static>, mut saved: Option<Credentials>) {
    let mut next_retry = Instant::now();
    loop {
        WIFI.store(controller.is_connected(), Ordering::Relaxed);
        let command = match select(COMMANDS.receive(), Timer::after_millis(500)).await {
            Either::First(c) => Some(c),
            Either::Second(_) => None,
        };
        match command {
            Some(Command::Scan) => {
                match with_timeout(
                    Duration::from_secs(15),
                    controller.scan_async(
                        &wifi::scan::ScanConfig::default()
                            .with_max(24)
                            .with_scan_type(wifi::scan::ScanTypeConfig::Active {
                                min: esp_hal::time::Duration::from_millis(110),
                                max: esp_hal::time::Duration::from_millis(160),
                            }),
                    ),
                )
                .await
                {
                    Ok(Ok(aps)) => {
                        let mut nets = Vec::new();
                        for ap in aps {
                            if ap.ssid.is_empty() {
                                continue;
                            }
                            let security = match ap.auth_method {
                                Some(Auth::None) => Security::Open,
                                Some(
                                    Auth::Wpa2Personal
                                    | Auth::WpaWpa2Personal
                                    | Auth::Wpa2Wpa3Personal,
                                ) => Security::Wpa2,
                                _ => Security::Unsupported,
                            };
                            if let Ok(ssid) = String::try_from(ap.ssid.as_str()) {
                                let _ = nets.push(Network {
                                    ssid,
                                    rssi: ap.signal_strength,
                                    channel: ap.channel,
                                    security,
                                });
                            }
                        }
                        REPLIES.send(Reply::Scanned(nets)).await;
                    }
                    _ => REPLIES.send(Reply::ScanFailed).await,
                }
            }
            Some(Command::Connect(c, channel)) => {
                if connect(&mut controller, &c, Some(channel)).await {
                    saved = Some(c.clone());
                    REPLIES.send(Reply::Connected(c)).await;
                } else {
                    REPLIES.send(Reply::Failed).await;
                }
                next_retry = Instant::now() + Duration::from_secs(10);
            }
            None if !controller.is_connected() && Instant::now() >= next_retry => {
                if let Some(c) = &saved {
                    let _ = connect(&mut controller, c, None).await;
                }
                next_retry = Instant::now() + Duration::from_secs(10);
            }
            _ => {}
        }
    }
}
async fn connect(
    controller: &mut wifi::WifiController<'static>,
    c: &Credentials,
    channel: Option<u8>,
) -> bool {
    WIFI.store(false, Ordering::Relaxed);
    if controller.is_connected() {
        let _ = with_timeout(Duration::from_secs(3), controller.disconnect_async()).await;
    }
    let auth = match c.security {
        Security::Open => AuthConfig::Open,
        Security::Wpa2 => match c.password.as_str().try_into() {
            Ok(p) => AuthConfig::Wpa2Personal(p),
            Err(_) => return false,
        },
        _ => return false,
    };
    let Ok(ssid) = c.ssid.as_str().try_into() else {
        return false;
    };
    let mut station = StationConfig::default()
        .with_ssid(ssid)
        .with_authentication(auth)
        .with_scan_method(wifi::sta::ScanMethod::AllChannels)
        .with_failure_retry_cnt(2);
    if let Some(channel) = channel {
        station = station
            .with_channel(channel)
            .with_scan_method(wifi::sta::ScanMethod::Fast);
    }
    if let Err(e) = controller.set_config(&wifi::Config::Station(station)) {
        serial_line!("Wi-Fi configuration error: {:?}", e);
        return false;
    }
    let mut result = with_timeout(Duration::from_secs(45), controller.connect_async()).await;
    if channel.is_some()
        && matches!(&result, Ok(Err(wifi::ConnectionError::Failed(info)))
        if matches!(info.reason, wifi::DisconnectReason::NoAccessPointFound | wifi::DisconnectReason::AuthenticationExpired))
    {
        if let Ok(Err(e)) = &result {
            serial_line!("Wi-Fi first attempt: {:?}", e);
        }
        BLE_PAUSED.reset();
        PAUSE_BLE.store(true, Ordering::Release);
        if with_timeout(Duration::from_secs(4), BLE_PAUSED.wait())
            .await
            .is_ok()
        {
            serial_line!("BLE scan paused; retrying the same Wi-Fi connection.");
            result = with_timeout(Duration::from_secs(45), controller.connect_async()).await;
        }
        PAUSE_BLE.store(false, Ordering::Release);
    }
    let connected = match result {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            serial_line!("Wi-Fi join error: {:?}", e);
            false
        }
        Err(_) => {
            serial_line!("Wi-Fi join timed out after 45 seconds.");
            let _ = with_timeout(Duration::from_secs(3), controller.disconnect_async()).await;
            false
        }
    };
    WIFI.store(connected, Ordering::Relaxed);
    connected
}

async fn command(
    ble: &mut BleConnector<'static>,
    opcode: u16,
    params: &[u8],
    packet: &mut [u8],
) -> Result<(), ()> {
    let mut cmd = Vec::<u8, 32>::new();
    cmd.extend_from_slice(&[1, opcode as u8, (opcode >> 8) as u8, params.len() as u8])
        .map_err(|_| ())?;
    cmd.extend_from_slice(params).map_err(|_| ())?;
    let n = with_timeout(Duration::from_secs(2), ble.write_async(&cmd))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    if n != cmd.len() {
        return Err(());
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let n = ble.next(packet).map_err(|_| ())?;
        if n >= 7 && packet[..2] == [4, 0x0e] && packet[4..6] == opcode.to_le_bytes() {
            return if packet[6] == 0 { Ok(()) } else { Err(()) };
        }
        Timer::after_millis(5).await;
    }
    Err(())
}
#[embassy_executor::task]
pub async fn ble(mut ble: BleConnector<'static>, state: &'static Shared) {
    let mut packet = [0u8; 1024];
    loop {
        let init = async {
            command(&mut ble, 0x0c03, &[], &mut packet).await?;
            command(
                &mut ble,
                0x0c01,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f],
                &mut packet,
            )
            .await?;
            command(&mut ble, 0x2001, &[2, 0, 0, 0, 0, 0, 0, 0], &mut packet).await?;
            command(&mut ble, 0x200b, &[0, 160, 0, 80, 0, 0, 0], &mut packet).await?;
            command(&mut ble, 0x200c, &[1, 0], &mut packet).await
        }
        .await;
        if init.is_err() {
            serial_line!("BLE scan initialization failed; retrying.");
            Timer::after_secs(3).await;
            continue;
        }
        serial_line!("BLE scanning A4:C1:38:4D:08:A4.");
        loop {
            if PAUSE_BLE.load(Ordering::Acquire) {
                if command(&mut ble, 0x200c, &[0, 0], &mut packet)
                    .await
                    .is_err()
                {
                    break;
                }
                BLE_PAUSED.signal(());
                while PAUSE_BLE.load(Ordering::Acquire) {
                    Timer::after_millis(20).await;
                }
                if command(&mut ble, 0x200c, &[1, 0], &mut packet)
                    .await
                    .is_err()
                {
                    break;
                }
                serial_line!("BLE scan resumed.");
            }
            match ble.next(&mut packet) {
                Ok(n) if n > 0 => advertisement(&packet[..n], state),
                Err(_) => break,
                _ => Timer::after_millis(5).await,
            }
        }
    }
}
fn advertisement(packet: &[u8], state: &Shared) {
    if packet.len() < 5 || packet[..2] != [4, 0x3e] || packet[3] != 2 {
        return;
    }
    let mut pos = 5;
    for _ in 0..packet[4] {
        let Some(header) = packet.get(pos..pos + 9) else {
            return;
        };
        let len = header[8] as usize;
        let Some(data) = packet.get(pos + 9..pos + 9 + len) else {
            return;
        };
        let Some(&rssi) = packet.get(pos + 9 + len) else {
            return;
        };
        if header[2..8] == [0xa4, 0x08, 0x4d, 0x38, 0xc1, 0xa4] {
            if let (Some(key), Ok(Some(service))) = (
                KEY.lock(|k| *k.borrow()),
                miaomiaoce_c5::sensor::service_data(data),
            ) {
                if let Ok(frame) =
                    miaomiaoce_c5::sensor::decrypt(&key, &miaomiaoce_c5::sensor::MAC, service)
                {
                    state.lock(|s| {
                        s.borrow_mut()
                            .apply(&frame, Instant::now().as_millis(), rssi as i8);
                    });
                }
            }
        }
        pos += 10 + len;
    }
}
