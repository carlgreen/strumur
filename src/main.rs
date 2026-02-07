mod advertise;
mod collection;
mod flac;
mod media_server;

extern crate socket2;

use std::env;
use std::fs::File;
use std::fs::read_to_string;
use std::io::ErrorKind;
use std::io::Result;
use std::io::Write as _;
use std::net::TcpListener;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use log::{Level, info, trace, warn};
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use stderrlog::Timestamp;
use uuid::Uuid;

use crate::advertise::SSDP_IPV4_MULTICAST_ADDRESS;
use crate::advertise::advertise_discovery_messages;
use crate::advertise::handle_search_error;
use crate::advertise::handle_search_message;
use crate::collection::populate_collection;
use crate::media_server::handle_device_connection;

const NAME: &str = env!("CARGO_PKG_NAME");

const VERSION: &str = env!("CARGO_PKG_VERSION");

const DEVICEID_FILE: &str = ".deviceid";

trait SocketToMe {
    fn send_to(&mut self, buf: &[u8], addr: &socket2::SockAddr) -> std::io::Result<usize>;
}

struct ReallySocketToMe {
    socket: socket2::Socket,
}

impl ReallySocketToMe {
    const fn new(socket: socket2::Socket) -> Self {
        Self { socket }
    }
}

impl SocketToMe for ReallySocketToMe {
    fn send_to(&mut self, buf: &[u8], addr: &socket2::SockAddr) -> std::io::Result<usize> {
        self.socket.send_to(buf, addr)
    }
}

#[derive(Clone)]
struct SysInfo {
    device_uuid: Uuid,
    os_version: String,
    boot_id: u64,
}

impl SysInfo {
    fn new(device_uuid: Uuid, os_version: &str, boot_id: u64) -> Self {
        let os_version = os_version.into();
        Self {
            device_uuid,
            os_version,
            boot_id,
        }
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let location = args
        .get(1)
        .expect("required argument missing: collection location");

    stderrlog::new()
        .module(module_path!())
        .verbosity(Level::Debug)
        .timestamp(Timestamp::Second)
        .init()
        .unwrap();

    let mut rng = rand::rng();

    let device_uuid = match get_device_uuid() {
        Ok(device_uuid) => device_uuid,
        Err(err) => panic!("{err}"),
    };

    let collection = populate_collection(location);

    let listener = TcpListener::bind("0.0.0.0:7878").unwrap();
    thread::spawn(move || {
        info!(
            "listening on {}",
            listener.local_addr().expect("could not get local address")
        );
        for stream in listener.incoming() {
            let stream = stream.expect("could not get TCP stream");
            let addr = format!(
                "http://{}/Content",
                stream.local_addr().expect("could not get stream address")
            );
            let peer_addr = stream
                .peer_addr()
                .map_or_else(|_| "unknown".to_string(), |a| a.to_string());
            trace!("incoming request from {peer_addr}");
            let collection = collection.clone(); // TODO i don't want to clone this.

            thread::spawn(move || {
                handle_device_connection(device_uuid, &addr, &collection, &stream, &stream);
            });
        }
    });

    let addr: SocketAddr = SSDP_IPV4_MULTICAST_ADDRESS
        .parse()
        .unwrap_or_else(|_| panic!("multicast address {SSDP_IPV4_MULTICAST_ADDRESS} is invalid"));
    let domain = Domain::IPV4;
    let socket: Socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(false)?;

    let ip_addr = addr.ip();
    if let IpAddr::V4(ref ipv4_addr) = ip_addr {
        socket.join_multicast_v4(ipv4_addr, &Ipv4Addr::UNSPECIFIED)?;
    } else {
        panic!("not ipv4");
    }

    socket.bind(&SockAddr::from(addr))?;

    // TODO
    // When a device knows it is newly added to the network, it shall multicast a number of
    // discovery messages advertising itself, its embedded devices, and its services (initial
    // announce).

    // Devices should wait a random interval (e.g. between 0 and 100milliseconds) before sending
    // an initial set of advertisements
    thread::sleep(Duration::from_millis(rng.random_range(0..=100)));

    // TODO Due to the unreliable nature of UDP, devices should send the entire set of discovery
    // messages more than once with some delay between sets e.g. a few hundred milliseconds. To
    // avoid network congestion discovery messages should not be sent more than three times. In
    // addition, the device shall re-send its advertisements periodically prior to expiration of the
    // duration specified in the CACHE-CONTROL header field; it is Recommended that such
    // refreshing of advertisements be done at a randomly-distributed interval of less than one-half
    // of the advertisement expiration time, so as to provide the opportunity for recovery from lost
    // advertisements before the advertisement expires, and to distribute over time the
    // advertisement refreshment of multiple devices on the network in order to avoid spikes in
    // network traffic. Note that UDP packets are also bounded in length (perhaps as small as 512
    // Bytes in some implementations); each discovery message shall fit entirely in a single UDP
    // packet. There is no guarantee that the above 3+2d+k messages will arrive in a particular
    // order.

    let location = "http://192.168.1.34:7878/Device.xml"; // TODO get this IP address properly
    let max_age = Duration::from_secs(1800);

    let info = os_info::get();

    let os_version = format!("{}/{}", info.os_type(), info.version());

    // A convenient mechanism is to set this field value to the time that the device sends
    // its initial announcement, expressed as seconds elapsed since midnight January 1, 1970.
    let boot_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let sys_info = SysInfo::new(device_uuid, &os_version, boot_id);

    advertise_discovery_messages(&sys_info, location, max_age, addr, &socket);

    loop {
        let mut buffer = Vec::with_capacity(1024);
        match socket.recv_from(buffer.spare_capacity_mut()) {
            Ok((received, src)) => {
                unsafe {
                    buffer.set_len(received);
                }

                let sys_info = sys_info.clone();
                // let os_version = os_version.clone();
                let mut socket =
                    ReallySocketToMe::new(socket.try_clone().expect("could not clone socket"));
                thread::spawn(move || {
                    let mut rng = rand::rng();

                    if let Err(err) = handle_search_message(
                        &sys_info,
                        location,
                        max_age,
                        &mut rng,
                        &buffer,
                        &src,
                        &mut socket,
                    ) {
                        handle_search_error(&err);
                    }
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {} // keep waiting
            Err(err) => {
                warn!("error receiving from socket: {err}");
            }
        }
    }

    // TODO
    // When a device is removed from the network, it should, if possible, multicast a number of
    // discovery messages revoking its earlier announcements, effectively declaring that its root
    // devices, embedded devices and services will no longer be available.
}

#[derive(Debug)]
enum DeviceUuidError {
    InvalidDeviceId(String, uuid::Error),
    IoError(std::io::Error),
}

impl std::fmt::Display for DeviceUuidError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidDeviceId(contents, err) => {
                write!(f, "invalid device ID {contents}: {err}")
            }
            Self::IoError(err) => {
                panic!("could not read device id: {err}");
            }
        }
    }
}

impl std::error::Error for DeviceUuidError {}

// TODO this file should probably be somewhere appropriate
fn get_device_uuid() -> std::result::Result<Uuid, DeviceUuidError> {
    match read_to_string(DEVICEID_FILE) {
        Ok(contents) => match Uuid::parse_str(&contents) {
            Ok(device_uuid) => {
                info!("starting with device UUID {device_uuid}");
                Ok(device_uuid)
            }
            Err(e) => Err(DeviceUuidError::InvalidDeviceId(contents, e)),
        },
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                // let device_uuid = Uuid::now_v6();
                let device_uuid = Uuid::new_v4();
                let mut file = File::create(DEVICEID_FILE).map_err(DeviceUuidError::IoError)?;
                file.write_all(device_uuid.to_string().as_bytes())
                    .map_err(DeviceUuidError::IoError)?;
                info!("generated new device UUID {device_uuid}");
                Ok(device_uuid)
            } else {
                Err(DeviceUuidError::IoError(e))
            }
        }
    }
}
