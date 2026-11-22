#![no_std]
#![no_main]
extern crate alloc;

macro_rules! serial_line {
    ($($arg:tt)*) => {
        esp_println::print!("{}\r\n", format_args!($($arg)*))
    };
}

mod network;
mod radio;
mod store;
mod transport;

use core::cell::RefCell;
use embassy_futures::select::{Either, select};
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    channel::Channel,
};
use embassy_time::{Instant, Timer};
use embedded_io_async::Read;
use esp_backtrace as _;
use esp_hal::{
    Async,
    usb::usb_serial_jtag::{UsbSerialJtag, UsbSerialJtagRx},
};
use heapless::{String, Vec};
use miaomiaoce_c5::{
    provision::{Action, Credentials, Menu, Network},
    sensor::State,
};
use portable_atomic::{AtomicBool, Ordering};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();
type Shared = Mutex<CriticalSectionRawMutex, RefCell<State>>;
static KEY: Mutex<CriticalSectionRawMutex, RefCell<Option<[u8; 16]>>> =
    Mutex::new(RefCell::new(None));
static WIFI: AtomicBool = AtomicBool::new(false);
static MQTT: AtomicBool = AtomicBool::new(false);
enum Command {
    Scan,
    Connect(Credentials, u8),
}
enum Reply {
    Scanned(Vec<Network, 24>),
    Connected(Credentials),
    Failed,
    ScanFailed,
}
static COMMANDS: Channel<CriticalSectionRawMutex, Command, 2> = Channel::new();
static REPLIES: Channel<CriticalSectionRawMutex, Reply, 2> = Channel::new();

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let p =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    esp_alloc::heap_allocator!(size: 32 * 1024);
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 64 * 1024);
    let timers = esp_hal::timer::timg::TimerGroup::new(p.TIMG0);
    esp_rtos::start(timers.timer0, p.FROM_CPU_INTR0);
    let store = store::Store::new(esp_storage::FlashStorage::new(p.FLASH));
    KEY.lock(|k| *k.borrow_mut() = store.key);
    let (rx, _tx) = UsbSerialJtag::new(p.USB_DEVICE).into_async().split();
    static STATE: StaticCell<Shared> = StaticCell::new();
    let state = STATE.init(Mutex::new(RefCell::new(State::default())));
    let controller = esp_radio::wifi::WifiController::new(
        p.WIFI,
        esp_radio::wifi::ControllerConfig::default()
            .with_static_rx_buf_num(4)
            .with_dynamic_rx_buf_num(8)
            .with_dynamic_tx_buf_num(8)
            .with_rx_ba_win(4),
    )
    .unwrap();
    let ble = esp_radio::ble::controller::BleConnector::new(p.BT, Default::default()).unwrap();
    static RESOURCES: StaticCell<embassy_net::StackResources<4>> = StaticCell::new();
    let random = esp_hal::rng::Rng::new();
    let seed = ((random.random() as u64) << 32) | random.random() as u64;
    let (stack, runner) = embassy_net::new(
        esp_radio::wifi::Interface::station(),
        embassy_net::Config::dhcpv4(Default::default()),
        RESOURCES.init(embassy_net::StackResources::new()),
        seed,
    );
    spawner.spawn(radio::wifi(controller, store.credentials.clone()).unwrap());
    spawner.spawn(radio::ble(ble, state).unwrap());
    spawner.spawn(network::runner(runner).unwrap());
    spawner.spawn(network::mqtt(stack, state).unwrap());
    serial_line!(
        "\r\nMHO-H413 / ESP32-C5; crystal: {:?}; serial 115200",
        esp_hal::clock::xtal_clock()
    );
    serial_line!("Commands: scan, status, key <32 hex>, help. Input is not echoed.");
    serial(rx, store, state).await;
}
async fn serial(
    mut rx: UsbSerialJtagRx<'static, Async>,
    mut store: store::Store,
    state: &'static Shared,
) -> ! {
    let mut menu = Menu::default();
    let mut line = Vec::<u8, 128>::new();
    let mut overflow = false;
    let mut was_cr = false;
    let mut bytes = [0u8; 1];
    loop {
        match select(rx.read(&mut bytes), REPLIES.receive()).await {
            Either::Second(reply) => match reply {
                Reply::Scanned(nets) => {
                    menu.replace_networks(nets);
                    serial_line!(" #   RSSI  Security     SSID");
                    for (i, n) in menu.networks().iter().enumerate() {
                        serial_line!(
                            "{:2}  {:4}  {:?}  {:?}",
                            i + 1,
                            n.rssi,
                            n.security,
                            n.ssid.as_str()
                        );
                    }
                    if menu.networks().is_empty() {
                        serial_line!("No visible networks found. Enter scan to retry.");
                    } else {
                        serial_line!(
                            "Select a number (1-{}), or scan again:",
                            menu.networks().len()
                        );
                    }
                }
                Reply::Connected(c) => {
                    let key = KEY.lock(|k| *k.borrow());
                    if store.save(Some(c), key).is_ok() {
                        serial_line!("Wi-Fi connected; credentials saved. Waiting for DHCP/MQTT.");
                    } else {
                        serial_line!(
                            "Wi-Fi connected, but Flash save failed; previous settings retained."
                        );
                    }
                }
                Reply::Failed => serial_line!(
                    "Connection failed. Use scan to choose again; retrying saved network if available."
                ),
                Reply::ScanFailed => serial_line!("Scan failed. Try scan again."),
            },
            Either::First(Ok(n)) if n > 0 => {
                let b = bytes[0];
                if b == b'\n' && was_cr {
                    was_cr = false;
                    continue;
                }
                was_cr = b == b'\r';
                if b == b'\r' || b == b'\n' {
                    if overflow {
                        serial_line!("Input too long; discarded.");
                    } else if let Ok(s) = core::str::from_utf8(&line) {
                        match menu.input(s) {
                            Action::Scan => {
                                if COMMANDS.try_send(Command::Scan).is_ok() {
                                    serial_line!("Scanning Wi-Fi (strongest first)...");
                                } else {
                                    serial_line!("Busy; retry scan shortly.");
                                }
                            }
                            Action::Prompt(ssid) => serial_line!(
                                "Password for {:?} (hidden; empty for open network; cancel to return):",
                                ssid.as_str()
                            ),
                            Action::Connect(c, channel) => {
                                if COMMANDS.try_send(Command::Connect(c, channel)).is_ok() {
                                    serial_line!("Connecting, starting on channel {}...", channel);
                                } else {
                                    serial_line!("Busy; select the number again.");
                                }
                            }
                            Action::Key(k) => {
                                if store.save(store.credentials.clone(), Some(k)).is_ok() {
                                    KEY.lock(|key| *key.borrow_mut() = Some(k));
                                    state.lock(|s| *s.borrow_mut() = State::default());
                                    serial_line!("Bindkey saved.");
                                } else {
                                    serial_line!("Flash save failed.");
                                }
                            }
                            Action::Status => {
                                serial_line!(
                                    "Wi-Fi={} MQTT={} bindkey={}",
                                    WIFI.load(Ordering::Relaxed),
                                    MQTT.load(Ordering::Relaxed),
                                    KEY.lock(|k| k.borrow().is_some())
                                );
                                let json =
                                    state.lock(|s| s.borrow().json(Instant::now().as_millis()));
                                if let Ok(json) = json {
                                    serial_line!("{}", json);
                                }
                                serial_line!("Free heap: {}", esp_alloc::HEAP.free());
                            }
                            Action::Cancelled => {
                                serial_line!("Cancelled. Enter scan or a network number.")
                            }
                            Action::Help => serial_line!(
                                "scan -> network number -> password. status | key <32 hex> | help"
                            ),
                            Action::Invalid => serial_line!(
                                "Invalid input. {}",
                                if menu.waiting_password() {
                                    "Enter an 8-63 byte password, 64 hex digits, or cancel."
                                } else {
                                    "Enter scan or a listed network number."
                                }
                            ),
                        }
                    } else {
                        serial_line!("Input must be UTF-8.");
                    }
                    line.fill(0);
                    line.clear();
                    overflow = false;
                } else if b == 8 || b == 127 {
                    line.pop();
                } else if b >= 32 {
                    if line.push(b).is_err() {
                        overflow = true;
                    }
                }
            }
            _ => Timer::after_millis(10).await,
        }
    }
}
