mod flac;
mod media_server;

extern crate socket2;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::DirEntry;
use std::fs::File;
use std::fs::read_to_string;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::Result;
use std::io::Seek;
use std::io::Write as _;
use std::net::TcpListener;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::NaiveDate;
use chrono::NaiveTime;
use chrono::Utc;
use log::{Level, debug, error, info, trace, warn};
use rand::Rng;
use rand::rngs::ThreadRng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use stderrlog::Timestamp;
use uuid::Uuid;

use crate::flac::extract_flac_metadata;
use crate::flac::is_flac;
use crate::media_server::handle_device_connection;

const NAME: &str = env!("CARGO_PKG_NAME");

const VERSION: &str = env!("CARGO_PKG_VERSION");

const DEVICEID_FILE: &str = ".deviceid";

const UPNP_VERSION: &str = "UPnP/2.0";

const SSDP_IPV4_MULTICAST_ADDRESS: &str = "239.255.255.250:1900";

const HTTP_PROTOCOL_NAME: &str = "HTTP";

const HTTP_PROTOCOL_VERSION: &str = "1.1";

const HTTP_MATCH_ANY_RESOURCE: &str = "*";

const HTTP_RESPONSE_OK: &str = "200 OK";

const HTTP_HEADER_SEP: &str = ":";

const HTTP_METHOD_NOTIFY: &str = "NOTIFY";

const HTTP_METHOD_SEARCH: &str = "M-SEARCH";

const HTTP_HEADER_HOST: &str = "HOST";

const HTTP_HEADER_SERVER: &str = "SERVER";

const HTTP_HEADER_LOCATION: &str = "LOCATION";

const HTTP_HEADER_DATE: &str = "DATE";

const HTTP_HEADER_EXT: &str = "EXT";

const HTTP_HEADER_CACHE_CONTROL: &str = "CACHE-CONTROL";

const HTTP_HEADER_BOOTID: &str = "BOOTID.UPNP.ORG";

const HTTP_HEADER_CONFIGID: &str = "CONFIGID.UPNP.ORG";

const HTTP_HEADER_NT: &str = "NT";

const HTTP_HEADER_NTS: &str = "NTS";

const HTTP_HEADER_ST: &str = "ST";

const HTTP_HEADER_USN: &str = "USN";

const NTS_ALIVE: &str = "ssdp:alive";

const ALL_SEARCH_TARGET: &str = "ssdp:all";

const ROOT_DEVICE_TYPE: &str = "upnp:rootdevice";

const MEDIA_SERVER_DEVICE_TYPE: &str = "urn:schemas-upnp-org:device:MediaServer:1";

const CONTENT_DIRECTORY_SERVICE_TYPE: &str = "urn:schemas-upnp-org:service:ContentDirectory:1";

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

#[derive(Clone, Debug, PartialEq)]
struct Artist {
    name: String,
    albums: Vec<Album>,
}

impl Artist {
    fn get_albums(&self) -> impl ExactSizeIterator<Item = &Album> {
        self.albums.iter()
    }

    fn get_tracks(&self) -> impl Iterator<Item = &Track> {
        self.albums.iter().flat_map(Album::get_tracks)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Album {
    title: String,
    date: Option<NaiveDate>,
    tracks: Vec<Track>,
    cover: String,
}

impl Album {
    fn get_tracks(&self) -> impl ExactSizeIterator<Item = &Track> {
        self.tracks.iter()
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Track {
    disc: u8,
    number: u8,
    title: String,
    file: String,
    duration: NaiveTime,
    size: u64,
    bits_per_sample: u8,
    sample_frequency: u32,
    channels: u8,
}

#[derive(Clone, Debug)]
struct Collection {
    system_update_id: u16, // TODO maintain this value
    base: PathBuf,
    artists: Vec<Artist>,
}

impl Collection {
    const fn get_system_update_id(&self) -> u16 {
        self.system_update_id
    }

    fn get_artists(&self) -> impl ExactSizeIterator<Item = &Artist> {
        self.artists.iter()
    }

    fn get_albums(&self) -> impl Iterator<Item = &Album> {
        self.artists.iter().flat_map(Artist::get_albums)
    }

    fn get_tracks(&self) -> impl Iterator<Item = &Track> {
        self.artists
            .iter()
            .flat_map(|artist| artist.get_albums().flat_map(Album::get_tracks))
    }
}

fn populate_collection(location: &str) -> Collection {
    info!("populating collection from {location:?}");
    let mut collection = Collection {
        system_update_id: 0,
        base: Path::new(location).to_path_buf(),
        artists: vec![],
    };

    let start = Instant::now();

    read_dir(location, location, &mut collection);

    info!("Populated collection in {:.2?}", start.elapsed());

    collection.artists.sort_by_key(|artist| artist.name.clone());
    for artist in &mut collection.artists {
        artist.albums.sort_by(|a1, a2| {
            let date_ordering = a1.date.cmp(&a2.date);
            if date_ordering.is_eq() {
                a1.title.cmp(&a2.title)
            } else {
                date_ordering
            }
        });
        for album in &mut artist.albums {
            album.tracks.sort_by(|t1, t2| {
                let disc_ordering = t1.disc.cmp(&t2.disc);
                if disc_ordering.is_eq() {
                    t1.number.cmp(&t2.number)
                } else {
                    disc_ordering
                }
            });
        }
    }

    info!("Collection sorted");

    collection
}

fn read_dir(location: &str, path: &str, collection: &mut Collection) {
    let entries = fs::read_dir(path).expect("no Music folder location in home directory");
    for entry in entries.flatten() {
        if let Ok(file_type) = entry.file_type() {
            if file_type.is_dir() {
                read_dir(location, entry.path().to_str().unwrap(), collection);
            }
            if file_type.is_file() {
                let display_file_name = entry.path().display().to_string();

                if let Ok(file) = File::open(entry.path()) {
                    let file_metadata = file.metadata().expect("could not read metadata");
                    let mut br = BufReader::new(file);
                    if is_flac(&mut br) {
                        br.rewind()
                            .expect("could not return to start of FLAC reader");
                        let metadata = extract_flac_metadata(&mut br);

                        let duration = metadata.duration();
                        let size = file_metadata.len();
                        let bits_per_sample = metadata.bits;
                        let sample_frequency = metadata.sample_rate;
                        let channels = metadata.channels;

                        let field_names = {
                            let mut names = metadata.get_field_names().collect::<Vec<&str>>();
                            names.sort_unstable();
                            names
                        };
                        // info!("field_names: {field_names:#?}");

                        let Some(artist_name) = metadata.get_field("ARTIST") else {
                            warn!("no artist name found in {display_file_name}");
                            debug!("fields in {display_file_name}: {field_names:?}");
                            continue;
                        };
                        let Some(album_title) = metadata.get_field("ALBUM") else {
                            warn!("no album title found in {display_file_name}");
                            debug!("fields in {display_file_name}: {field_names:?}");
                            continue;
                        };
                        let disc_number = metadata.get_field("DISCNUMBER").map_or_else(
                            || {
                                // no disc number is probably the norm
                                0
                            },
                            |number| number.parse::<u8>().expect("number"),
                        );
                        let track_number = metadata.get_field("TRACKNUMBER").map_or_else(
                            || {
                                warn!("no track number found in {display_file_name}");
                                debug!("fields in {display_file_name}: {field_names:?}",);
                                0
                            },
                            |number| number.parse::<u8>().expect("number"),
                        );
                        let Some(track_title) = metadata.get_field("TITLE") else {
                            warn!("no track title found in {display_file_name}");
                            debug!("fields in {display_file_name}: {field_names:?}");
                            continue;
                        };
                        let release_date = metadata.get_field("DATE").map_or_else(
                            || {
                                warn!("no release date found in {display_file_name}");
                                debug!("fields in {display_file_name}: {field_names:?}");
                                None
                            },
                            |mut datestr| {
                                fill_in_missing_date_parts(&mut datestr);
                                Some(datestr.parse::<NaiveDate>().unwrap_or_else(|err| {
                                    panic!("{err}. expected valid date not {datestr}")
                                }))
                            },
                        );

                        let track = Track {
                            disc: disc_number,
                            number: track_number,
                            title: track_title,
                            file: entry
                                .path()
                                .as_os_str()
                                .to_str()
                                .expect("can only handle utf8 for now") // maybe just store as Path?
                                .to_owned(),
                            duration,
                            size,
                            bits_per_sample,
                            sample_frequency,
                            channels,
                        };

                        add_track_to_collection(
                            collection,
                            location,
                            &entry,
                            artist_name,
                            album_title,
                            release_date,
                            track,
                        );
                    } else {
                        trace!("{display_file_name} is not supported");
                    }
                }
            }
        }
    }
}

fn add_track_to_collection(
    collection: &mut Collection,
    location: &str,
    entry: &DirEntry,
    artist_name: String,
    album_title: String,
    release_date: Option<NaiveDate>,
    track: Track,
) {
    let artist: Option<&mut Artist> = collection
        .artists
        .iter_mut()
        .find(|a| a.name == artist_name);
    if let Some(artist) = artist {
        let album = artist.albums.iter_mut().find(|a| a.title == album_title);
        if let Some(album) = album {
            album.tracks.push(track);
        } else {
            let cover_url = find_album_artwork(location, entry, &album_title);

            let album = Album {
                title: album_title,
                date: release_date,
                tracks: vec![track],
                cover: cover_url.unwrap_or_default(),
            };
            artist.albums.push(album);
        }
    } else {
        let cover_url = find_album_artwork(location, entry, &album_title);

        let album = Album {
            title: album_title,
            date: release_date,
            tracks: vec![track],
            cover: cover_url.unwrap_or_default(),
        };
        let artist = Artist {
            name: artist_name,
            albums: vec![album],
        };
        collection.artists.push(artist);
    }
}

/// want like yyyy-mm-dd, but might be just yyyy-mm or even yyyy.
/// so make missing parts 01, for now
fn fill_in_missing_date_parts(datestr: &mut String) {
    if datestr.len() == 4 {
        *datestr += "-01";
    }
    if datestr.len() == 7 {
        *datestr += "-01";
    }
}

fn find_album_artwork(location: &str, entry: &DirEntry, album_title: &str) -> Option<String> {
    // assume some kind of folder structure like artists/albums/tracks
    let p = entry.path();
    let probable_album_directory = p
        .parent()
        .expect("every file should have a parent directory");

    let mut images = Vec::new();

    let album_files = fs::read_dir(probable_album_directory).unwrap();
    for path in album_files.flatten() {
        if !path.file_type().unwrap().is_file() {
            debug!("non-file found, ignoring: {}", path.path().display());
            continue;
        }

        let file_name = path.file_name().into_string().unwrap();
        let p = path.path();
        let ext = match p.extension() {
            Some(ext) => ext.to_str().unwrap(),
            None if p.starts_with(".") => p
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .strip_prefix('.')
                .unwrap(),
            None => {
                debug!("skipping no extesion {file_name}");
                continue;
            }
        };

        match ext.to_lowercase().as_str() {
            "gif" | "jpg" | "jpeg" | "png" => {
                images.push(path.path());
            }
            _ => {}
        }
    }

    if images.len() == 1 {
        // one image found, that will do
        return Some(encode_path_for_url(
            images.first().expect("just checked the length"),
            location,
        ));
    }
    if !images.is_empty() {
        let candidates = vec!["cover.jpg", "folder.jpg"];
        for candidate in candidates {
            if let Some(cover) = find_something(&images, candidate) {
                // TODO maybe this should store the local path, and encode it etc. on request?
                return Some(encode_path_for_url(&cover, location));
            }
        }
        debug!("no suitable artwork found for {album_title} in {images:#?}");
    }

    None
}

fn find_something(images: &[PathBuf], name: &str) -> Option<PathBuf> {
    for image in images {
        if image
            .file_name()
            .unwrap()
            .to_ascii_lowercase()
            .to_str()
            .unwrap()
            == name.to_ascii_lowercase()
        {
            return Some(image.clone());
        }
    }
    None
}

fn encode_path_for_url(path: &Path, location: &str) -> String {
    path.strip_prefix(location)
        .unwrap()
        .components()
        .map(|c| urlencoding::encode(c.as_os_str().to_str().unwrap()).to_string())
        .collect::<Vec<String>>()
        .join("/")
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

fn handle_search_error(err: &HandleSearchMessageError) {
    match err {
        HandleSearchMessageError::InvalidSSDPMessage(_)
        | HandleSearchMessageError::UnhandledRequestLine(_)
        | HandleSearchMessageError::NoIPv4(_)
        | HandleSearchMessageError::MissingHostHeader
        | HandleSearchMessageError::MissingUserAgentHeader
        | HandleSearchMessageError::MissingMulticastMxHeader
        | HandleSearchMessageError::MissingStHeader
        | HandleSearchMessageError::SearchTargetUuidMismatch(_)
        | HandleSearchMessageError::MethodUnknown(_) => {
            error!("error handling search message: {err}");
        }
        HandleSearchMessageError::SearchTargetUnknown(_) => {
            // do you care about whatever other kind of UPNP thing could be out there?
            trace!("{err}");
        }
        HandleSearchMessageError::MethodNotSupported(_) => {
            // this will be a NOTIFY. i believe in myself, i don't need to know about the competition.
            trace!("{err}");
        }
    }
}

fn advertise_discovery_messages(
    sys_info: &SysInfo,
    location: &str,
    max_age: Duration,
    addr: SocketAddr,
    socket: &Socket,
) {
    let device_uuid = sys_info.device_uuid;
    let boot_id = sys_info.boot_id;
    let os_version = sys_info.os_version.clone();

    let uuid_urn = &format!("uuid:{device_uuid}");

    // To advertise its capabilities, a device multicasts a number of discovery messages. Specifically,
    // a root device shall multicast:

    // Three discovery messages for the root device.

    let nt = ROOT_DEVICE_TYPE;
    let usn = format!("{uuid_urn}::{ROOT_DEVICE_TYPE}");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\n{HTTP_HEADER_HOST}: {SSDP_IPV4_MULTICAST_ADDRESS}\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_NT}: {nt}\r\n{HTTP_HEADER_NTS}: {NTS_ALIVE}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    if let Err(err) = socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr)) {
        error!("error sending advertisement: {err}");
    }

    let nt = uuid_urn;
    let usn = uuid_urn;
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\n{HTTP_HEADER_HOST}: {SSDP_IPV4_MULTICAST_ADDRESS}\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_NT}: {nt}\r\n{HTTP_HEADER_NTS}: {NTS_ALIVE}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    if let Err(err) = socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr)) {
        error!("error sending advertisement: {err}");
    }

    let device_type = "MediaServer";
    let ver = 1;
    let nt = format!("urn:schemas-upnp-org:device:{device_type}:{ver}");
    let usn = format!("{uuid_urn}::urn:schemas-upnp-org:device:{device_type}:{ver}");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\n{HTTP_HEADER_HOST}: {SSDP_IPV4_MULTICAST_ADDRESS}\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_NT}: {nt}\r\n{HTTP_HEADER_NTS}: {NTS_ALIVE}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    if let Err(err) = socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr)) {
        error!("error sending advertisement: {err}");
    }

    // - Two discovery messages for each embedded device - I don't have any embedded devices

    // - Once for each service type in each device.

    let service_type = "ContentDirectory";
    let ver = 1;
    let nt = format!("urn:schemas-upnp-org:service:{service_type}:{ver}");
    let usn = format!("{uuid_urn}::urn:schemas-upnp-org:service:{service_type}:{ver}");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\n{HTTP_HEADER_HOST}: {SSDP_IPV4_MULTICAST_ADDRESS}\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_NT}: {nt}\r\n{HTTP_HEADER_NTS}: {NTS_ALIVE}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    if let Err(err) = socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr)) {
        error!("error sending advertisement: {err}");
    }

    // TODO ConnectionManager service
    // let service_type = "ConnectionManager";
    // let ver = 1;
    // let nt = format!("urn:schemas-upnp-org:service:{service_type}:{ver}");
    // let usn = format!("{uuid_urn}::urn:schemas-upnp-org:service:{service_type}:{ver}");
    // let advertisement = format!(
    //     "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\n{HTTP_HEADER_HOST}: {SSDP_IPV4_MULTICAST_ADDRESS}\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_NT}: {nt}\r\n{HTTP_HEADER_NTS}: {NTS_ALIVE}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
    //     max_age.as_secs()
    // );
    // if let Err(err) = socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr)) {
    //     error!("error sending advertisement: {err}");
    // }

    // TODO above messages should be resent periodically
}

fn extract_display_name(
    ssdp_message: &SSDPMessage,
) -> std::result::Result<String, HandleSearchMessageError> {
    trace!(
        "extracting display name from SSDP message: {:#?}",
        ssdp_message.headers
    );

    // if a friendly name is provided why not use that?
    if let Some(friendly_name_key) = ssdp_message
        .headers
        .keys()
        .find(|k| k.eq_ignore_ascii_case("CPFN.UPNP.ORG"))
        && let Some(friendly_name) = ssdp_message.headers.get(friendly_name_key)
    {
        return Ok(friendly_name.clone());
    }

    // is USER-AGENT mandatory? if not, then what?
    let user_agent_key = ssdp_message
        .headers
        .keys()
        .find(|k| k.eq_ignore_ascii_case("USER-AGENT"))
        .ok_or(HandleSearchMessageError::MissingUserAgentHeader)?;
    ssdp_message
        .headers
        .get(user_agent_key)
        .ok_or(HandleSearchMessageError::MissingUserAgentHeader)
        .cloned()
}

fn extract_host(
    ssdp_message: &SSDPMessage,
) -> std::result::Result<String, HandleSearchMessageError> {
    let host_key = ssdp_message
        .headers
        .keys()
        .find(|k| k.eq_ignore_ascii_case("HOST"))
        .ok_or(HandleSearchMessageError::MissingHostHeader)?;
    ssdp_message
        .headers
        .get(host_key)
        .ok_or(HandleSearchMessageError::MissingHostHeader)
        .cloned()
}

fn is_multicast(host: &str) -> bool {
    if host == SSDP_IPV4_MULTICAST_ADDRESS {
        true
    } else {
        trace!("unicast search");
        let unicast = host
            .parse::<SocketAddr>()
            .unwrap_or_else(|_| panic!("could not parse {host} as a SocketAddr"));
        trace!("  - {}:{}", unicast.ip(), unicast.port());
        false
    }
}

fn extract_mx(ssdp_message: &SSDPMessage) -> std::result::Result<u64, HandleSearchMessageError> {
    let mx_key = ssdp_message
        .headers
        .keys()
        .find(|k| k.eq_ignore_ascii_case("MX"));
    mx_key.map_or(
        Err(HandleSearchMessageError::MissingMulticastMxHeader),
        |mx_key| {
            let mx = ssdp_message
                .headers
                .get(mx_key)
                .ok_or(HandleSearchMessageError::MissingMulticastMxHeader)?;
            let mx = mx.parse::<u64>().unwrap();
            Ok(if mx > 5 { 5 } else { mx })
        },
    )
}

fn extract_st(ssdp_message: &SSDPMessage) -> std::result::Result<String, HandleSearchMessageError> {
    let st_key = ssdp_message
        .headers
        .keys()
        .find(|k| k.eq_ignore_ascii_case("ST"));
    let st_key = st_key.ok_or(HandleSearchMessageError::MissingStHeader)?;
    let st = ssdp_message
        .headers
        .get(st_key)
        .ok_or(HandleSearchMessageError::MissingStHeader)?;
    Ok(st.clone())
}

fn generate_advertisement(
    response_date: &str,
    sys_info: &SysInfo,
    st: &str,
    usn: &str,
    location: &str,
    max_age: Duration,
) -> String {
    let boot_id = sys_info.boot_id;
    let os_version = &sys_info.os_version;
    format!(
        "{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {HTTP_RESPONSE_OK}\r\n{HTTP_HEADER_DATE}: {response_date}\r\n{HTTP_HEADER_EXT}:\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_ST}: {st}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
        max_age.as_secs()
    )
}

fn send_advertisement(usn: &str, advertisement: &str, socket: &mut dyn SocketToMe, src: &SockAddr) {
    debug!("send {usn}");
    if let Err(err) = socket.send_to(advertisement.as_bytes(), src) {
        error!("error sending advertisement: {err}");
    }
}

#[derive(Debug)]
enum HandleSearchMessageError {
    InvalidSSDPMessage(String),
    UnhandledRequestLine(String),
    NoIPv4(Box<SockAddr>),
    MissingHostHeader,
    MissingUserAgentHeader,
    MissingMulticastMxHeader,
    MissingStHeader,
    SearchTargetUuidMismatch(String),
    SearchTargetUnknown(String),
    MethodNotSupported(String),
    MethodUnknown(String),
}

impl std::fmt::Display for HandleSearchMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidSSDPMessage(err) => {
                write!(f, "failed to parse ssdp message: {err}")
            }
            Self::UnhandledRequestLine(ssdp_message) => {
                write!(f, "what do i do with {ssdp_message:#?}")
            }
            Self::NoIPv4(src) => {
                write!(f, "{src:?} is not an IPv4 source")
            }
            Self::MissingHostHeader => {
                write!(f, "missing HOST header, ignoring")
            }
            Self::MissingUserAgentHeader => {
                write!(f, "missing USER-AGENT header, ignoring")
            }
            Self::MissingMulticastMxHeader => {
                write!(f, "multicast search missing MX header, ignoring")
            }
            Self::MissingStHeader => {
                write!(f, "missing ST header")
            }
            Self::SearchTargetUuidMismatch(st) => {
                write!(f, "unintended search target reciptient: {st}")
            }
            Self::SearchTargetUnknown(st) => {
                write!(f, "unknown search target {st}")
            }
            Self::MethodNotSupported(method) => {
                write!(f, "method {method} not supported")
            }
            Self::MethodUnknown(request_line) => {
                write!(f, "something else: {request_line}")
            }
        }
    }
}

impl std::error::Error for HandleSearchMessageError {}

fn handle_search_message(
    sys_info: &SysInfo,
    location: &str,
    max_age: Duration,
    rng: &mut ThreadRng,
    data: &[u8],
    src: &SockAddr,
    socket: &mut dyn SocketToMe,
) -> std::result::Result<(), HandleSearchMessageError> {
    let device_uuid = sys_info.device_uuid;

    // When a new control point is added to the network, it is allowed to multicast a discovery
    // message searching for interesting devices, services, or both.
    // All devices shall listen to the standard multicast address for these messages and shall
    // respond if any of their root devices, embedded devices or services matches the search criteria
    // in the discovery message.
    // All devices shall listen to incoming unicast search messages on port 1900 or, if provided, the
    // port number specified in the SEARCHPORT.UPNP.ORG header field and shall respond if any
    // of their root devices, embedded devices or services matches the search criteria in the
    // discovery message.

    let ssdp_message =
        parse_ssdp_message(data).map_err(HandleSearchMessageError::InvalidSSDPMessage)?;

    if ssdp_message.request_line
        == format!("{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {HTTP_RESPONSE_OK}")
    {
        return Err(HandleSearchMessageError::UnhandledRequestLine(
            ssdp_message.request_line,
        ));
    }
    let (method, _request_target, _protocol) =
        parse_request_line(&ssdp_message.request_line).unwrap();
    match method.as_str() {
        HTTP_METHOD_NOTIFY => Err(HandleSearchMessageError::MethodNotSupported(
            HTTP_METHOD_NOTIFY.to_string(),
        )),
        HTTP_METHOD_SEARCH => {
            // expect like:
            // M-SEARCH * HTTP/1.1
            // HOST: 239.255.255.250:1900
            // MAN: "ssdp:discover"
            // MX: seconds to delay response
            // ST: search target
            // USER-AGENT: OS/version UPnP/2.0 product/version
            // CPFN.UPNP.ORG: friendly name of the control point
            // CPUUID.UPNP.ORG: uuid of the control point

            let uuid_urn = format!("uuid:{device_uuid}");

            let st = extract_st(&ssdp_message)?;

            let cp_ip = src
                .as_socket_ipv4()
                .ok_or_else(|| HandleSearchMessageError::NoIPv4(Box::new(src.clone())))?
                .ip()
                .to_string();
            let display_name = match extract_display_name(&ssdp_message) {
                Ok(display_name) => {
                    format!("{display_name} ({cp_ip})")
                }
                Err(HandleSearchMessageError::MissingUserAgentHeader) => cp_ip,
                Err(err) => return Err(err),
            };
            info!("search from {display_name}: {st}");

            // either 239.255.255.250:1900 for multicast or unicast to this ip address and port
            let host = extract_host(&ssdp_message)?;
            let multicast = is_multicast(&host);

            // if multicast and contains TCPPORT.UPNP.ORG header then TODO
            if multicast && ssdp_message.headers.contains_key("TCPPORT.UPNP.ORG") {
                unimplemented!("TCPPORT.UPNP.ORG handling not implemented");
            }

            // For multicast M-SEARCH requests, if the search request does not contain an MX header field,
            // the device shall silently discard and ignore the search request. If the MX header field specifies
            // a field value greater than 5, the device should assume that it contained the value 5 or less.
            let mx = if multicast {
                Some(extract_mx(&ssdp_message)?)
            } else {
                None
            };

            // If a device implements “urn:schemas-upnp-org:service:xyz:2”, it shall
            // respond to search requests for both that type and “urn:schemas-upnp-org:service:xyz:1”. The
            // response shall specify the same version as was contained in the search request.

            // Devices respond if the ST
            // header field of the M-SEARCH request is “ssdp:all”, “upnp:rootdevice”, “uuid:” followed by a
            // UUID that exactly matches the one advertised by the device, or if the M-SEARCH request
            // matches a device type or service type supported by the device.
            //
            // TODO ConnectionManager service
            if st == ALL_SEARCH_TARGET
                || st == ROOT_DEVICE_TYPE
                || st == uuid_urn
                || st == MEDIA_SERVER_DEVICE_TYPE
                || st == CONTENT_DIRECTORY_SERVICE_TYPE
            // || st == "urn:schemas-upnp-org:service:ConnectionManager:1"
            {
                info!("ok search target: {st}");
            } else if st.starts_with(&uuid_urn) {
                warn!("unexpected search target format: {st}");
            } else if st.starts_with("uuid:") {
                return Err(HandleSearchMessageError::SearchTargetUuidMismatch(st));
            } else {
                return Err(HandleSearchMessageError::SearchTargetUnknown(st));
            }

            // if mulitcast, wait a random duration between 0 and MX seconds
            // if unicast, response within 1 second (i.e. don't wait)
            if let Some(mx) = mx {
                let d = Duration::from_secs(rng.random_range(0..=mx));
                thread::sleep(d);
            }

            let response_date = format_rfc1123(Utc::now());

            if st == ALL_SEARCH_TARGET || st == ROOT_DEVICE_TYPE {
                let st = ROOT_DEVICE_TYPE;
                let usn = format!("{uuid_urn}::{ROOT_DEVICE_TYPE}");
                let advertisement =
                    generate_advertisement(&response_date, sys_info, st, &usn, location, max_age);
                send_advertisement(&usn, &advertisement, socket, src);
            }

            if st == ALL_SEARCH_TARGET || st == uuid_urn {
                let st = &uuid_urn;
                let usn = &uuid_urn;
                let advertisement =
                    generate_advertisement(&response_date, sys_info, st, usn, location, max_age);
                send_advertisement(usn, &advertisement, socket, src);
            }

            if st == ALL_SEARCH_TARGET || st == MEDIA_SERVER_DEVICE_TYPE {
                let st = MEDIA_SERVER_DEVICE_TYPE;
                let usn = format!("{uuid_urn}::{st}");
                let advertisement =
                    generate_advertisement(&response_date, sys_info, st, &usn, location, max_age);
                send_advertisement(&usn, &advertisement, socket, src);
            }

            if st == ALL_SEARCH_TARGET || st == CONTENT_DIRECTORY_SERVICE_TYPE {
                let st = CONTENT_DIRECTORY_SERVICE_TYPE;
                let usn = format!("{uuid_urn}::{st}");
                let advertisement =
                    generate_advertisement(&response_date, sys_info, st, &usn, location, max_age);
                send_advertisement(&usn, &advertisement, socket, src);
            }

            // TODO ConnectionManager service
            // if st == ALL_SEARCH_TARGET
            //     || st == "urn:schemas-upnp-org:service:ConnectionManager:1"
            // {
            //     let st = "urn:schemas-upnp-org:service:ConnectionManager:1";
            //     let usn = format!("{uuid_urn}::{st}");
            //     let advertisement = format!(
            //         "{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {HTTP_RESPONSE_OK}\r\n{HTTP_HEADER_DATE}: {response_date}\r\n{HTTP_HEADER_EXT}:\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_ST}: {st}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
            //         max_age.as_secs()
            //     );
            //     trace!("send {usn}");
            //     if let Err(err) = socket.send_to(advertisement.as_bytes(), &src)
            //     {
            //         error!("error sending advertisement: {err}");
            //     }
            // }

            Ok(())
        }
        _ => Err(HandleSearchMessageError::MethodUnknown(
            ssdp_message.request_line,
        )),
    }
}

#[derive(Debug, PartialEq)]
struct SSDPMessage {
    request_line: String,
    headers: HashMap<String, String>,
}

fn parse_ssdp_message(data: &[u8]) -> std::result::Result<SSDPMessage, String> {
    let data = String::from_utf8(data.to_vec()).unwrap();
    let mut iter = data.lines();
    let request_line = iter.next().ok_or("failed to get request line")?;

    let mut headers = HashMap::new();
    for line in iter {
        if line.is_empty() {
            break;
        }
        let mut parts = line.splitn(2, HTTP_HEADER_SEP);
        let key = parts.next().ok_or("failed to get key")?.trim().to_string();
        let value = parts
            .next()
            .ok_or_else(|| format!("failed to get value for key {key}"))?
            .trim()
            .to_string();
        headers.insert(key, value);
    }

    Ok(SSDPMessage {
        request_line: request_line.to_string(),
        headers,
    })
}

// TODO maybe could be "HTTP/1.1 200 OK" too?
fn parse_request_line(request_line: &str) -> std::result::Result<(String, String, String), String> {
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or("failed to get method")?
        .trim()
        .to_string();
    if method != HTTP_METHOD_NOTIFY && method != HTTP_METHOD_SEARCH {
        return Err(format!("invalid method: {method}"));
    }

    let request_target = parts
        .next()
        .ok_or("failed to get request target")?
        .trim()
        .to_string();
    if request_target != HTTP_MATCH_ANY_RESOURCE {
        return Err(format!("invalid request target: {request_target}"));
    }

    let protocol = parts
        .next()
        .ok_or("failed to get protocol")?
        .trim()
        .to_string();
    if protocol != format!("{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}") {
        return Err(format!("invalid protocol: {protocol}"));
    }

    Ok((method, request_target, protocol))
}

/// some sources say an RFC 1123 date must be GMT and GMT only.
fn format_rfc1123(dt: chrono::DateTime<Utc>) -> String {
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use socket2::SockAddrStorage;

    use super::*;

    #[test]
    fn test_parse_request_line() {
        let request_line = r#"M-SEARCH * HTTP/1.1"#;
        let (method, request_target, protocol) = parse_request_line(request_line).unwrap();
        assert_eq!(method, "M-SEARCH");
        assert_eq!(request_target, "*");
        assert_eq!(protocol, "HTTP/1.1");
    }

    #[test]
    fn test_parse_request_line_with_invalid_method() {
        let request_line = r#"HELLO * HTTP/1.1"#;
        assert!(parse_request_line(request_line).is_err())
    }

    #[test]
    fn test_parse_request_line_with_invalid_target() {
        let request_line = r#"M-SEARCH 1 HTTP/1.1"#;
        assert!(parse_request_line(request_line).is_err())
    }

    #[test]
    fn test_parse_request_line_with_invalid_protocol() {
        let request_line = r#"M-SEARCH * HTTP/a.b"#;
        assert!(parse_request_line(request_line).is_err())
    }

    #[test]
    fn test_parse_search() {
        let data = r#"M-SEARCH * HTTP/1.1
St: urn:schemas-upnp-org:service:ContentDirectory:1
Host: 239.255.255.250:1900
Mx: 3
Man: "ssdp:discover"
"#;
        let want = SSDPMessage {
            request_line: "M-SEARCH * HTTP/1.1".to_string(),
            headers: HashMap::from([
                (
                    "St".to_string(),
                    "urn:schemas-upnp-org:service:ContentDirectory:1".to_string(),
                ),
                ("Host".to_string(), "239.255.255.250:1900".to_string()),
                ("Mx".to_string(), "3".to_string()),
                ("Man".to_string(), "\"ssdp:discover\"".to_string()),
            ]),
        };
        assert_eq!(parse_ssdp_message(data.as_bytes()).unwrap(), want);
    }

    #[test]
    fn test_format_rfc1123() {
        use chrono::TimeZone;

        let dt = Utc.with_ymd_and_hms(2025, 11, 24, 21, 28, 32).unwrap();
        let formatted = format_rfc1123(dt);
        assert_eq!(formatted, "Mon, 24 Nov 2025 21:28:32 GMT");
    }

    struct DontReallySocketToMe {
        buf: Vec<u8>,
    }

    impl DontReallySocketToMe {
        const fn new() -> Self {
            Self { buf: Vec::new() }
        }

        fn get_sent(&self) -> Vec<u8> {
            self.buf.clone()
        }
    }

    impl SocketToMe for DontReallySocketToMe {
        fn send_to(&mut self, buf: &[u8], _addr: &socket2::SockAddr) -> std::io::Result<usize> {
            self.buf.extend_from_slice(buf);
            Ok(buf.len())
        }
    }

    /// i've clearly done something wrong...
    fn setup_test_address() -> SockAddr {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        let mut addr_storage = SockAddrStorage::zeroed();
        let mut len = addr_storage.size_of();
        let res =
            unsafe { libc::getsockname(socket.as_raw_fd(), addr_storage.view_as(), &mut len) };
        if res == -1 {
            panic!("{}", std::io::Error::last_os_error());
        }
        unsafe { SockAddr::new(addr_storage, len) }
    }

    /// fun stuff to ignore the DATE header...
    fn extract_before_and_after_date_header(buf: &[u8]) -> (String, String) {
        let sent = String::from_utf8(buf.to_vec()).unwrap();
        let mut bits = sent.splitn(2, "DATE: ");
        let pre_date = bits.next().unwrap();
        let mut more_bits = bits.next().unwrap().splitn(2, "\r\n");
        more_bits.next().unwrap(); // skip the date
        let post_date = more_bits.next().unwrap();

        (pre_date.into(), post_date.into())
    }

    fn new_test_sysinfo() -> SysInfo {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let os_version = "a/1";
        let boot_id = 1;
        SysInfo::new(test_device_uuid, os_version, boot_id)
    }

    #[test]
    fn test_handle_rootdevice_search_message() {
        let sys_info = new_test_sysinfo();
        let location = "somewhere?";
        let max_age = Duration::from_secs(10);

        let buffer = "M-SEARCH * HTTP/1.1\r
HOST: 239.255.255.250:1900\r
MAN: \"ssdp:discover\"\r
MX: 0\r
ST: upnp:rootdevice\r
USER-AGENT: OS/version UPnP/2.0 product/version\r
CPFN.UPNP.ORG: test control point\r
CPUUID.UPNP.ORG: 7ef73657-27fc-4580-8e7a-c08a4528da9e\r\n\r\n"
            .as_bytes();

        let src = setup_test_address();
        let mut test_socket = DontReallySocketToMe::new();

        let mut rng = rand::rng();

        handle_search_message(
            &sys_info,
            location,
            max_age,
            &mut rng,
            buffer,
            &src,
            &mut test_socket,
        )
        .unwrap();

        let (pre_date, post_date) = extract_before_and_after_date_header(&test_socket.get_sent());

        assert_eq!(pre_date, "HTTP/1.1 200 OK\r\n");
        assert_eq!(
            post_date,
            "EXT:\r
BOOTID.UPNP.ORG: 1\r
CONFIGID.UPNP.ORG: 1\r
SERVER: a/1 UPnP/2.0 strumur/0.1.0\r
ST: upnp:rootdevice\r
USN: uuid:5c863963-f2a2-491e-8b60-079cdadad147::upnp:rootdevice\r
LOCATION: somewhere?\r
CACHE-CONTROL: max-age=10\r
\r
"
        );
    }

    #[test]
    fn test_handle_uuid_search_message() {
        let sys_info = new_test_sysinfo();
        let location = "somewhere?";
        let max_age = Duration::from_secs(10);

        let buffer = "M-SEARCH * HTTP/1.1\r
HOST: 239.255.255.250:1900\r
MAN: \"ssdp:discover\"\r
MX: 0\r
ST: uuid:5c863963-f2a2-491e-8b60-079cdadad147\r
USER-AGENT: OS/version UPnP/2.0 product/version\r
CPFN.UPNP.ORG: test control point\r
CPUUID.UPNP.ORG: 7ef73657-27fc-4580-8e7a-c08a4528da9e\r\n\r\n"
            .as_bytes();

        let src = setup_test_address();
        let mut test_socket = DontReallySocketToMe::new();

        let mut rng = rand::rng();

        handle_search_message(
            &sys_info,
            location,
            max_age,
            &mut rng,
            buffer,
            &src,
            &mut test_socket,
        )
        .unwrap();

        let (pre_date, post_date) = extract_before_and_after_date_header(&test_socket.get_sent());

        assert_eq!(pre_date, "HTTP/1.1 200 OK\r\n");
        assert_eq!(
            post_date,
            "EXT:\r
BOOTID.UPNP.ORG: 1\r
CONFIGID.UPNP.ORG: 1\r
SERVER: a/1 UPnP/2.0 strumur/0.1.0\r
ST: uuid:5c863963-f2a2-491e-8b60-079cdadad147\r
USN: uuid:5c863963-f2a2-491e-8b60-079cdadad147\r
LOCATION: somewhere?\r
CACHE-CONTROL: max-age=10\r
\r
"
        );
    }

    #[test]
    fn test_handle_media_server_search_message() {
        let sys_info = new_test_sysinfo();
        let location = "somewhere?";
        let max_age = Duration::from_secs(10);

        let buffer = "M-SEARCH * HTTP/1.1\r
HOST: 239.255.255.250:1900\r
MAN: \"ssdp:discover\"\r
MX: 0\r
ST: urn:schemas-upnp-org:device:MediaServer:1\r
USER-AGENT: OS/version UPnP/2.0 product/version\r
CPFN.UPNP.ORG: test control point\r
CPUUID.UPNP.ORG: 7ef73657-27fc-4580-8e7a-c08a4528da9e\r\n\r\n"
            .as_bytes();

        let src = setup_test_address();
        let mut test_socket = DontReallySocketToMe::new();

        let mut rng = rand::rng();

        handle_search_message(
            &sys_info,
            location,
            max_age,
            &mut rng,
            buffer,
            &src,
            &mut test_socket,
        )
        .unwrap();

        let (pre_date, post_date) = extract_before_and_after_date_header(&test_socket.get_sent());

        assert_eq!(pre_date, "HTTP/1.1 200 OK\r\n");
        assert_eq!(
            post_date,
            "EXT:\r
BOOTID.UPNP.ORG: 1\r
CONFIGID.UPNP.ORG: 1\r
SERVER: a/1 UPnP/2.0 strumur/0.1.0\r
ST: urn:schemas-upnp-org:device:MediaServer:1\r
USN: uuid:5c863963-f2a2-491e-8b60-079cdadad147::urn:schemas-upnp-org:device:MediaServer:1\r
LOCATION: somewhere?\r
CACHE-CONTROL: max-age=10\r
\r
"
        );
    }

    #[test]
    fn test_handle_content_directory_search_message() {
        let sys_info = new_test_sysinfo();
        let location = "somewhere?";
        let max_age = Duration::from_secs(10);

        let buffer = "M-SEARCH * HTTP/1.1\r
HOST: 239.255.255.250:1900\r
MAN: \"ssdp:discover\"\r
MX: 0\r
ST: urn:schemas-upnp-org:service:ContentDirectory:1\r
USER-AGENT: OS/version UPnP/2.0 product/version\r
CPFN.UPNP.ORG: test control point\r
CPUUID.UPNP.ORG: 7ef73657-27fc-4580-8e7a-c08a4528da9e\r\n\r\n"
            .as_bytes();

        let src = setup_test_address();
        let mut test_socket = DontReallySocketToMe::new();

        let mut rng = rand::rng();

        handle_search_message(
            &sys_info,
            location,
            max_age,
            &mut rng,
            buffer,
            &src,
            &mut test_socket,
        )
        .unwrap();

        let (pre_date, post_date) = extract_before_and_after_date_header(&test_socket.get_sent());

        assert_eq!(pre_date, "HTTP/1.1 200 OK\r\n");
        assert_eq!(
            post_date,
            "EXT:\r
BOOTID.UPNP.ORG: 1\r
CONFIGID.UPNP.ORG: 1\r
SERVER: a/1 UPnP/2.0 strumur/0.1.0\r
ST: urn:schemas-upnp-org:service:ContentDirectory:1\r
USN: uuid:5c863963-f2a2-491e-8b60-079cdadad147::urn:schemas-upnp-org:service:ContentDirectory:1\r
LOCATION: somewhere?\r
CACHE-CONTROL: max-age=10\r
\r
"
        );
    }

    #[test]
    fn test_fill_in_missing_date_parts() {
        let mut datestr = "2001".to_string();
        fill_in_missing_date_parts(&mut datestr);
        assert_eq!(datestr, "2001-01-01");

        let mut datestr = "2001-09".to_string();
        fill_in_missing_date_parts(&mut datestr);
        assert_eq!(datestr, "2001-09-01");

        let mut datestr = "2001-09-05".to_string();
        fill_in_missing_date_parts(&mut datestr);
        assert_eq!(datestr, "2001-09-05");
    }

    #[test]
    fn test_populate_collection() {
        let location = "./testdata/collection/";
        let collection = populate_collection(location);
        assert_eq!(
            collection.artists,
            vec![Artist {
                name: "carl".to_string(),
                albums: vec![Album {
                    title: "none".to_string(),
                    date: None,
                    tracks: vec![Track {
                        disc: 0,
                        number: 0,
                        title: "riff".to_string(),
                        file: "./testdata/collection/riff.flac".to_string(),
                        duration: NaiveTime::from_hms_milli_opt(0, 0, 5, 712).unwrap(),
                        size: 664150,
                        bits_per_sample: 16,
                        sample_frequency: 48000,
                        channels: 2,
                    }],
                    cover: String::new(),
                }]
            }]
        );
    }
}
