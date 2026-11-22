use super::*;
use crate::transport::{self, HOST, PORT};
use core::fmt::Write;
use embassy_net::{
    Stack,
    udp::{PacketMetadata, UdpSocket},
};
use embassy_time::{Duration, with_timeout};
use embedded_tls::{Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext};
use miaomiaoce_c5::mqtt::{self, Event, Receiver};
#[embassy_executor::task]
pub async fn runner(mut runner: embassy_net::Runner<'static, esp_radio::wifi::Interface>) {
    runner.run().await
}
#[embassy_executor::task]
pub async fn mqtt(stack: Stack<'static>, state: &'static Shared) {
    loop {
        stack.wait_config_up().await;
        match session(stack, state).await {
            Ok(()) => {}
            Err(()) => serial_line!("TLS/TCP MQTT disconnected; reconnecting in 5 s."),
        }
        MQTT.store(false, Ordering::Relaxed);
        Timer::after_secs(5).await;
    }
}
async fn session(stack: Stack<'static>, state: &Shared) -> Result<(), ()> {
    let unix_seconds = synchronize_time(stack).await?;
    transport::set_time(unix_seconds)?;
    let addresses = with_timeout(
        Duration::from_secs(10),
        stack.dns_query(HOST, embassy_net::dns::DnsQueryType::A),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let address = *addresses.first().ok_or(())?;
    let endpoint = embassy_net::IpEndpoint::new(address, PORT);
    let mut rx_data = [0u8; 4096];
    let mut tx_data = [0u8; 4096];
    let mut socket = embassy_net::tcp::TcpSocket::new(stack, &mut rx_data, &mut tx_data);
    socket.set_timeout(Some(Duration::from_secs(30)));
    with_timeout(Duration::from_secs(10), socket.connect(endpoint))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    let mut id = String::<48>::new();
    write!(
        id,
        "mmc-a4c1384d08a4-{:08x}",
        esp_hal::rng::Rng::new().random()
    )
    .map_err(|_| ())?;
    let mut tls_rx = alloc::vec![0u8;16640];
    let mut tls_tx = alloc::vec![0u8;2048];
    let config = TlsConfig::new().with_server_name(HOST);
    let mut tls = TlsConnection::<_, Aes128GcmSha256>::new(socket, &mut tls_rx, &mut tls_tx);
    with_timeout(
        Duration::from_secs(30),
        tls.open(TlsContext::new(&config, transport::verifier())),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let connect = mqtt::connect(&id).map_err(|_| ())?;
    transport::send(&mut tls, &connect).await?;
    let mut receiver = Receiver::default();
    let mut rx = [0u8; 32];
    let connack_deadline = Instant::now() + Duration::from_secs(10);
    let mut ready = false;
    let mut last_sent = Instant::now();
    let mut ping_at: Option<Instant> = None;
    let mut last_publish: Option<Instant> = None;
    let mut last_counter = None;
    loop {
        if !stack.is_config_up() {
            return Err(());
        }
        let now = Instant::now();
        if (!ready && now >= connack_deadline)
            || ping_at.is_some_and(|at| at.elapsed() > Duration::from_secs(15))
        {
            return Err(());
        }
        if ready {
            let snapshot = state.lock(|s| {
                let s = s.borrow();
                let due = last_publish.is_none_or(|at| {
                    at.elapsed() >= Duration::from_secs(60)
                        || (s.last_counter != last_counter
                            && at.elapsed() >= Duration::from_secs(2))
                });
                if s.last_counter.is_some() && due {
                    s.json(now.as_millis())
                        .ok()
                        .map(|json| (s.last_counter, json))
                } else {
                    None
                }
            });
            if let Some((counter, json)) = snapshot {
                let packet = mqtt::publish(transport::TOPIC, json.as_bytes()).map_err(|_| ())?;
                transport::send(&mut tls, &packet).await?;
                last_sent = Instant::now();
                last_publish = Some(last_sent);
                last_counter = counter;
            }
            if ping_at.is_none() && last_sent.elapsed() >= Duration::from_secs(20) {
                transport::send(&mut tls, mqtt::PINGREQ).await?;
                last_sent = Instant::now();
                ping_at = Some(last_sent);
            }
        }
        // The pinned upstream revision preserves partial TLS records on read cancellation.
        if let Ok(result) = with_timeout(Duration::from_millis(100), tls.read(&mut rx)).await {
            let n = result.map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            for event in receiver.feed(&rx[..n]).map_err(|_| ())? {
                match event {
                    Event::Connected if !ready => {
                        ready = true;
                        MQTT.store(true, Ordering::Relaxed);
                        serial_line!("MQTT ready: TLS/TCP broker.emqx.io:8883");
                    }
                    Event::PingResponse if ping_at.is_some() => ping_at = None,
                    _ => return Err(()),
                }
            }
        }
    }
}

// Require two agreeing time sources; source-address and request-nonce checks
// reject stray/stale replies. SNTP itself does not authenticate the time server.
async fn synchronize_time(stack: Stack<'static>) -> Result<u64, ()> {
    let mut previous: Option<(u64, Instant)> = None;
    for host in ["time.cloudflare.com", "ntp.aliyun.com", "pool.ntp.org"] {
        if let Ok(seconds) = time_from(stack, host).await {
            if let Some((last, at)) = previous {
                if seconds.abs_diff(last + at.elapsed().as_secs()) <= 5 {
                    return Ok(seconds);
                }
            }
            previous = Some((seconds, Instant::now()));
        }
    }
    serial_line!("Time synchronization failed; TLS connection deferred.");
    Err(())
}
async fn time_from(stack: Stack<'static>, host: &str) -> Result<u64, ()> {
    let ips = with_timeout(
        Duration::from_secs(5),
        stack.dns_query(host, embassy_net::dns::DnsQueryType::A),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let endpoint = embassy_net::IpEndpoint::new(*ips.first().ok_or(())?, 123);
    let mut rm = [PacketMetadata::EMPTY; 1];
    let mut tm = [PacketMetadata::EMPTY; 1];
    let mut rb = [0u8; 128];
    let mut tb = [0u8; 48];
    let mut socket = UdpSocket::new(stack, &mut rm, &mut rb, &mut tm, &mut tb);
    socket.bind(0).map_err(|_| ())?;
    let mut nonce = [0u8; 8];
    esp_hal::rng::Rng::new().read(&mut nonce);
    with_timeout(
        Duration::from_secs(3),
        socket.send_to(&miaomiaoce_c5::sntp::request(nonce), endpoint),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    let mut response = [0u8; 128];
    let (n, remote) = with_timeout(Duration::from_secs(3), socket.recv_from(&mut response))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
    if remote.endpoint != endpoint {
        return Err(());
    }
    miaomiaoce_c5::sntp::response(&response[..n], &nonce)
}
