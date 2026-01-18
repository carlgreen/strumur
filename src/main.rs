extern crate socket2;

use std::collections::HashMap;
use std::env;
use std::fmt::Write;
use std::fs;
use std::fs::DirEntry;
use std::fs::File;
use std::fs::read_to_string;
use std::io::BufRead;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::Read;
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
use regex::Regex;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use stderrlog::Timestamp;
use uuid::Uuid;
use xmltree::Element;

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

const CDS_GET_SYSTEM_UPDATE_ID_ACTION: &str = "GetSystemUpdateID";

const CDS_GET_SEARCH_CAPABILITIES_ACTION: &str = "GetSearchCapabilities";

const CDS_GET_SORT_CAPABILITIES_ACTION: &str = "GetSortCapabilities";

const CDS_BROWSE_ACTION: &str = "Browse";

const CDS_SEARCH_ACTION: &str = "Search";

const CDS_CREATE_OBJECT_ACTION: &str = "CreateObject";

const CDS_DESTROY_OBJECT_ACTION: &str = "DestroyObject";

const CDS_UPDATE_OBJECT_ACTION: &str = "UpdateObject";

const CDS_IMPORT_RESOURCE_ACTION: &str = "ImportResource";

const CDS_EXPORT_RESOURCE_ACTION: &str = "ExportResource";

const CDS_STOP_TRANSFER_RESOURCE_ACTION: &str = "StopTransferResource";

const CDS_GET_TRANSFER_PROGRESS_ACTION: &str = "GetTransferProfress";

const CDS_DELETE_RESOURCE_ACTION: &str = "DeleteResource";

const CDS_CREATE_REFERENCE_ACTION: &str = "CreateReference";

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
                            let mut names = metadata
                                .fields
                                .iter()
                                .map(|f| f.name.clone())
                                .collect::<Vec<String>>();
                            names.sort();
                            names
                        };
                        // info!("field_names: {field_names:#?}");

                        let Some(artist_name) = get_field(&metadata, "ARTIST") else {
                            warn!("no artist name found in {display_file_name}");
                            debug!("fields in {display_file_name}: {field_names:?}");
                            continue;
                        };
                        let Some(album_title) = get_field(&metadata, "ALBUM") else {
                            warn!("no album title found in {display_file_name}");
                            debug!("fields in {display_file_name}: {field_names:?}");
                            continue;
                        };
                        let disc_number = get_field(&metadata, "DISCNUMBER").map_or_else(
                            || {
                                // no disc number is probably the norm
                                0
                            },
                            |number| number.parse::<u8>().expect("number"),
                        );
                        let track_number = get_field(&metadata, "TRACKNUMBER").map_or_else(
                            || {
                                warn!("no track number found in {display_file_name}");
                                debug!("fields in {display_file_name}: {field_names:?}",);
                                0
                            },
                            |number| number.parse::<u8>().expect("number"),
                        );
                        let Some(track_title) = get_field(&metadata, "TITLE") else {
                            warn!("no track title found in {display_file_name}");
                            debug!("fields in {display_file_name}: {field_names:?}");
                            continue;
                        };
                        let release_date = get_field(&metadata, "DATE").map_or_else(
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

fn get_field(metadata: &FlacMetadata, name: &str) -> Option<String> {
    metadata
        .fields
        .iter()
        .find(|f| f.name.to_uppercase() == name)
        .map(|f| f.content.clone())
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

#[derive(Debug)]
enum ParseRequestError {
    EmptyRequest,
    IoError(std::io::Error),
}

impl std::fmt::Display for ParseRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::EmptyRequest => {
                write!(f, "empty request")
            }
            Self::IoError(err) => {
                write!(f, "error reading request line: {err}")
            }
        }
    }
}

impl std::error::Error for ParseRequestError {}

fn parse_some_request_line(
    buf_reader: &mut BufReader<impl Read>,
) -> std::result::Result<String, ParseRequestError> {
    let mut line: String = String::with_capacity(100);
    match buf_reader.read_line(&mut line) {
        Ok(size) => {
            if size == 0 {
                return Err(ParseRequestError::EmptyRequest);
            }
            Ok(line.strip_suffix("\r\n").map_or_else(
                || {
                    warn!("warning: expected CRLF terminated request line: {line:#?}");
                    line.clone()
                },
                ToString::to_string,
            ))
        }
        Err(e) => Err(ParseRequestError::IoError(e)),
    }
}

// TODO probably should be case-insensitive for header names
fn parse_some_headers(buf_reader: &mut BufReader<impl Read>) -> HashMap<String, String> {
    let mut line: String = String::with_capacity(100);
    let mut http_request_headers = HashMap::new();
    loop {
        line.clear();
        match buf_reader.read_line(&mut line) {
            Ok(size) => {
                if size == 0 || line == "\r\n" {
                    break;
                }
                line = line.strip_suffix("\r\n").map_or_else(
                    || {
                        warn!("warning: expected CRLF terminated header: {line:#?}");
                        line.clone()
                    },
                    ToString::to_string,
                );
                let mut line = line.splitn(2, ':');
                let key = line.next().unwrap().trim().to_string();
                let value = line.next().unwrap().trim().to_string();
                http_request_headers.insert(key, value);
            }
            Err(e) => {
                error!("error reading header: {e}");
                break;
            }
        }
    }

    http_request_headers
}

fn get_content_length(request_line: &str, http_request_headers: &HashMap<String, String>) -> usize {
    http_request_headers
        .keys()
        .find(|k| k.eq_ignore_ascii_case("Content-Length"))
        .and_then(|content_length_key| http_request_headers.get(content_length_key))
        .map_or_else(
            || {
                if request_line.starts_with("GET ") {
                    // assume no body
                    0
                } else {
                    panic!("no content length");
                }
            },
            |content_length| content_length.parse().unwrap(),
        )
}

fn parse_body(content_length: usize, buf_reader: &mut BufReader<impl Read>) -> Option<String> {
    if content_length > 0 {
        let mut buf = vec![0; content_length];
        if let Err(e) = buf_reader.read_exact(&mut buf) {
            error!("could not ready body: {e}");
        }

        Some(String::from_utf8(buf).expect("body is not UTF8"))
    } else {
        None
    }
}

fn parse_soap_browse_request(body: &str) -> (Option<Vec<String>>, Option<u16>, Option<u16>) {
    let mut object_id = None;
    let mut starting_index: Option<u16> = None;
    let mut requested_count: Option<u16> = None;
    let envelope = Element::parse(body.as_bytes()).unwrap();
    let body = envelope.get_child("Body").unwrap();
    match body.get_child("Browse") {
        Some(browse) => {
            for child in &browse.children {
                match child.as_element().unwrap().name.as_str() {
                    "ObjectID" => {
                        object_id = Some(
                            child
                                .as_element()
                                .unwrap()
                                .get_text()
                                .unwrap()
                                .split('$')
                                .map(ToString::to_string)
                                .collect(),
                        );
                    }
                    "BrowseFlag" => {
                        let browse_flag = child.as_element().unwrap().get_text().unwrap();
                        if browse_flag == "BrowseDirectChildren" {
                            info!("direct children. simple.");
                        } else {
                            warn!("browse flag: {browse_flag}. what's up");
                        }
                    }
                    "Filter" => {
                        let filter = child.as_element().unwrap().get_text().unwrap();
                        if filter == "*" {
                            info!("no filter. simple.");
                        } else {
                            warn!("some filter: {filter}. what's up");
                        }
                    }
                    "StartingIndex" => {
                        starting_index = Some(
                            child
                                .as_element()
                                .unwrap()
                                .get_text()
                                .unwrap()
                                .parse()
                                .unwrap(),
                        );
                    }
                    "RequestedCount" => {
                        requested_count = Some(
                            child
                                .as_element()
                                .unwrap()
                                .get_text()
                                .unwrap()
                                .parse()
                                .unwrap(),
                        );
                    }
                    "SortCriteria" => {
                        let sort_criteria = child.as_element().unwrap().get_text();
                        if let Some(sort_criteria) = sort_criteria {
                            warn!("sort criteria: {sort_criteria}. what's up");
                        } else {
                            warn!("no sort criteria. do i just make this up?");
                        }
                    }
                    anything => warn!("what is {anything:?}"),
                }
            }
        }
        None => panic!("no Browse child"),
    }

    (object_id, starting_index, requested_count)
}

fn generate_browse_root_response(collection: &Collection) -> String {
    let album_count = collection.get_albums().count();
    let albums = format!(
        r#"<container id="0$albums" parentID="0" restricted="1" searchable="1"><dc:title>{album_count} albums</dc:title><upnp:class>object.container</upnp:class></container>"#
    );
    let items_count = collection.get_tracks().count();
    let items = format!(
        r#"<container id="0$items" parentID="0" restricted="1" searchable="1"><dc:title>{items_count} items</dc:title><upnp:class>object.container</upnp:class></container>"#
    );

    // how much of this do i even care about?
    let result = albums
        + &items
        + r#"<container id="0$playlists" parentID="0" restricted="1" searchable="1"><dc:title>0 playlists</dc:title><upnp:class>object.container</upnp:class></container>"#
        + r#"<container id="0$=Artist" parentID="0" restricted="1" searchable="1"><dc:title>Artist</dc:title><upnp:class>object.container</upnp:class></container>"#
        + r#"<container id="0$=Date" parentID="0" restricted="1" searchable="1"><dc:title>Date</dc:title><upnp:class>object.container</upnp:class></container>"#
        + r#"<container id="0$=Genre" parentID="0" restricted="1" searchable="1"><dc:title>Genre</dc:title><upnp:class>object.container</upnp:class></container>"#
        + r#"<container id="0$=All Artists" parentID="0" restricted="1" searchable="1"><dc:title>All Artists</dc:title><upnp:class>object.container</upnp:class></container>"#
        + r#"<container id="0$=Composer" parentID="0" restricted="1" searchable="1"><dc:title>Composer</dc:title><upnp:class>object.container</upnp:class></container>"#
        + r#"<container id="0$untagged" parentID="0" restricted="1" searchable="1"><dc:title>[untagged]</dc:title><upnp:class>object.container</upnp:class></container>"#
        + r#"<container id="0$folders" parentID="0" restricted="1" searchable="1"><dc:title>[folder view]</dc:title><upnp:class>object.container.storageFolder</upnp:class></container>"#;
    format_response(&result, 10, 10)
}

fn generate_browse_albums_response(
    collection: &Collection,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
    addr: &str,
) -> String {
    let total_matches = collection.get_albums().count();
    let starting_index = starting_index.unwrap().into();
    let requested_count: usize = requested_count.unwrap().into();
    let mut number_returned = 0;
    let mut result = String::new();
    let mut some_id = 0;
    let mut skipped = 0;
    'artists: for artist in collection.get_artists() {
        // move on quickly if we're not up to the starting index
        let albums = artist.get_albums();
        if skipped + albums.len() <= starting_index {
            skipped += albums.len();
            continue;
        }
        let artist_name = xml::escape::escape_str_attribute(&artist.name);
        for album in albums
            .skip(starting_index - skipped)
            .take(requested_count - number_returned)
        {
            number_returned += 1;
            let album_title = xml::escape::escape_str_attribute(&album.title);
            let date = create_date_element(album.date);
            let track_count = album.get_tracks().len();
            let cover = create_album_art_element(addr, &album.cover);
            // TODO album art details
            write!(
                result,
                r#"<container id="0$albums$*a{some_id}" parentID="0$albums" childCount="{track_count}" restricted="1" searchable="1"><dc:title>{album_title}</dc:title>{date}<upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist>{cover}<upnp:class>object.container.album.musicAlbum</upnp:class></container>"#,
            ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
            some_id += 1;
            if number_returned >= requested_count {
                break 'artists;
            }
        }
    }
    format_response(&result, number_returned, total_matches)
}

fn generate_browse_an_album_response(
    collection: &Collection,
    album_id: &str,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
    addr: &str,
) -> String {
    // dont' worry about this
    let mut some_id = 0;
    let mut found = None;
    'artists: for artist in collection.get_artists() {
        for album in artist.get_albums() {
            if format!("*a{some_id}") == album_id {
                found = Some((artist, album));
                break 'artists;
            }
            some_id += 1;
        }
    }
    let (artist, album) = found.unwrap_or_else(|| panic!("album {album_id} not found"));
    let tracks = album.get_tracks();
    let total_matches = tracks.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let artist_name = xml::escape::escape_str_attribute(&artist.name);
    let album_title = &album.title;
    let date = create_date_element(album.date);
    let cover = create_album_art_element(addr, &album.cover);
    let mut result = String::new();
    for (i, track) in tracks
        .skip(starting_index)
        .take(requested_count)
        .enumerate()
    {
        number_returned += 1;
        let id = starting_index + i + 1; // WTF
        let track_title = xml::escape::escape_str_attribute(&track.title);
        let track_number = track.number;
        let duration = format_time_nice(track.duration);
        let size = track.size;
        let bits_per_sample = track.bits_per_sample;
        let sample_frequency = track.sample_frequency;
        let channels = track.channels;
        let file = format!("{}/{}", addr, track.file);
        let file = xml::escape::escape_str_attribute(&file);
        write!(
            result,
            r#"<item id="0$albums${album_id}$*i{id}" parentID="0$albums${album_id}" restricted="1"><dc:title>{track_title}</dc:title>{date}<upnp:album>{album_title}</upnp:album><upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist><upnp:originalTrackNumber>{track_number}</upnp:originalTrackNumber>{cover}<res duration="{duration}" size="{size}" bitsPerSample="{bits_per_sample}" sampleFrequency="{sample_frequency}" nrAudioChannels="{channels}" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">{file}</res><upnp:class>object.item.audioItem.musicTrack</upnp:class></item>"#,
        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    format_response(&result, number_returned, total_matches)
}

fn generate_browse_artists_response(
    collection: &Collection,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
) -> String {
    let artists = collection.get_artists();
    let total_matches = artists.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let mut result = String::new();
    for (i, artist) in artists
        .skip(starting_index)
        .take(requested_count)
        .enumerate()
    {
        number_returned += 1;
        let id = starting_index + i + 1; // WTF
        let name = xml::escape::escape_str_attribute(&artist.name);
        write!(
            result,
            r#"<container id="0$=Artist${id}" parentID="0$=Artist" restricted="1" searchable="1"><dc:title>{name}</dc:title><upnp:class>object.container.person.musicArtist</upnp:class></container>"#
        )
        .unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    format_response(&result, number_returned, total_matches)
}

fn generate_browse_an_artist_response(
    collection: &Collection,
    artist_id: &str,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
) -> String {
    let things = ["albums", "items", "Date"];
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let total_matches = things.len();
    let artist = collection
        .get_artists()
        .skip(artist_id.parse::<usize>().unwrap() - 1)
        .take(1)
        .next()
        .unwrap();
    let mut number_returned = 0;
    let mut result = String::new();

    for thing in things.iter().skip(starting_index).take(requested_count) {
        number_returned += 1;
        let (sub_id, title) = match *thing {
            "albums" => {
                let sub_id = (*thing).to_string();
                let albums = artist.get_albums().len();
                let title = format!("{albums} albums");
                (sub_id, title)
            }
            "items" => {
                let sub_id = (*thing).to_string();
                let items = artist.get_tracks().count();
                let title = format!("{items} items");
                (sub_id, title)
            }
            _ => {
                let sub_id = format!("={thing}");
                let title = (*thing).to_string();
                (sub_id, title)
            }
        };
        write!(
            result,
            r#"<container id="0$=Artist${artist_id}${sub_id}" parentID="0$=Artist${artist_id}" restricted="1" searchable="1"><dc:title>{title}</dc:title><upnp:class>object.container</upnp:class></container>"#
        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    format_response(&result, number_returned, total_matches)
}

fn generate_browse_an_artist_albums_response(
    collection: &Collection,
    artist_id: &str,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
    addr: &str,
) -> String {
    let artist = collection
        .get_artists()
        .skip(artist_id.parse::<usize>().unwrap() - 1)
        .take(1)
        .next()
        .unwrap();
    let albums = artist.get_albums();
    let total_matches = albums.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let artist_name = xml::escape::escape_str_attribute(&artist.name);
    let mut result = String::new();
    for (i, album) in albums
        .skip(starting_index)
        .take(requested_count)
        .enumerate()
    {
        number_returned += 1;
        let id = starting_index + i + 1; // WTF
        let title = xml::escape::escape_str_attribute(&album.title);
        let date = create_date_element(album.date);
        let track_count = album.get_tracks().len();
        let cover = create_album_art_element(addr, &album.cover);
        write!(
            result,
            r#"<container id="0$=Artist${artist_id}$albums${id}" parentID="0$=Artist${artist_id}$albums" childCount="{track_count}" restricted="1" searchable="1"><dc:title>{title}</dc:title>{date}<upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist>{cover}<upnp:class>object.container.album.musicAlbum</upnp:class></container>"#,
        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    format_response(&result, number_returned, total_matches)
}

fn generate_browse_an_artist_album_response(
    collection: &Collection,
    artist_id: &str,
    album_id: &str,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
    addr: &str,
) -> String {
    let artist = collection
        .get_artists()
        .skip(artist_id.parse::<usize>().unwrap() - 1)
        .take(1)
        .next()
        .unwrap();
    let album = artist
        .get_albums()
        .skip(album_id.parse::<usize>().unwrap() - 1)
        .take(1)
        .next()
        .unwrap();
    let tracks = album.get_tracks();
    let total_matches = tracks.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let artist_name = xml::escape::escape_str_attribute(&artist.name);
    let album_title = xml::escape::escape_str_attribute(&album.title);
    let date = create_date_element(album.date);
    let cover = create_album_art_element(addr, &album.cover);
    let mut result = String::new();
    for (i, track) in tracks
        .skip(starting_index)
        .take(requested_count)
        .enumerate()
    {
        number_returned += 1;
        let id = starting_index + i + 1; // WTF
        let track_title = xml::escape::escape_str_attribute(&track.title);
        let track_number = track.number;
        let duration = format_time_nice(track.duration);
        let size = track.size;
        let bits_per_sample = track.bits_per_sample;
        let sample_frequency = track.sample_frequency;
        let channels = track.channels;
        let file = format!("{}/{}", addr, track.file);
        let file = xml::escape::escape_str_attribute(&file);
        write!(
            result,
            r#"<item id="0$=Artist${artist_id}$albums${album_id}${id}" parentID="0$=Artist${artist_id}$albums${album_id}" restricted="1"><dc:title>{track_title}</dc:title>{date}<upnp:album>{album_title}</upnp:album><upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist><upnp:originalTrackNumber>{track_number}</upnp:originalTrackNumber>{cover}<res duration="{duration}" size="{size}" bitsPerSample="{bits_per_sample}" sampleFrequency="{sample_frequency}" nrAudioChannels="{channels}" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">{file}</res><upnp:class>object.item.audioItem.musicTrack</upnp:class></item>"#,
        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    format_response(&result, number_returned, total_matches)
}

fn generate_browse_all_artists_response(
    collection: &Collection,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
) -> String {
    let artists = collection.get_artists();
    let total_matches = artists.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let mut result = String::new();
    for (i, artist) in artists
        .skip(starting_index)
        .take(requested_count)
        .enumerate()
    {
        number_returned += 1;
        let id = starting_index + i + 1; // WTF
        let name = xml::escape::escape_str_attribute(&artist.name);
        write!(
            result,
            r#"<container id="0$=All Artists${id}" parentID="0$=All Artists" restricted="1" searchable="1"><dc:title>{name}</dc:title><upnp:class>object.container.person.musicArtist</upnp:class></container>"#
        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    format_response(&result, number_returned, total_matches)
}

/// this is what i have to do to not have extra leading zeros on the hour field. probably very fallable.
fn format_time_nice(time: NaiveTime) -> String {
    time.format("%_H:%M:%S%.3f")
        .to_string()
        .trim_start()
        .to_string()
}

fn create_date_element(date: Option<NaiveDate>) -> String {
    date.map_or_else(String::new, |date| format!("<dc:date>{date}</dc:date>"))
}

fn create_album_art_element(addr: &str, cover: &str) -> String {
    let cover = format!("{addr}/{cover}");
    let cover = xml::escape::escape_str_attribute(&cover);
    format!("<upnp:albumArtURI dlna:profileID=\"JPEG_MED\">{cover}</upnp:albumArtURI>")
}

fn format_response(result: &str, number_returned: usize, total_matches: usize) -> String {
    let result = format!(
        r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
{result}</DIDL-Lite>"#
    );
    let result = xml::escape::escape_str_attribute(&result);
    format!(
        "
            <Result>{result}</Result>
            <NumberReturned>{number_returned}</NumberReturned>
            <TotalMatches>{total_matches}</TotalMatches>
            <UpdateID>25</UpdateID>"
    )
}

fn generate_get_system_update_id_response(collection: &Collection) -> (String, &'static str) {
    let system_update_id = collection.get_system_update_id();
    let body = format!(
        r#"
        <u:GetSystemUpdateIDResponse xmlns:u="{CONTENT_DIRECTORY_SERVICE_TYPE}">
            <Id>{system_update_id}</Id>
        </u:GetSystemUpdateIDResponse>"#
    );
    (wrap_with_envelope_body(&body), HTTP_RESPONSE_OK)
}

fn generate_get_search_capabilities_response() -> (String, &'static str) {
    // CSV, could be something like upnp:class,dc:title,dc:creator,upnp:artist,upnp:album,upnp:genre,dc:date,res,@refID,upnp:artist[@role="AlbumArtist"],upnp:artist[@role="Composer"]
    let search_caps = ""; // TODO nothing, for now.
    let body = format!(
        r#"
        <u:GetSearchCapabilitiesResponse xmlns:u="{CONTENT_DIRECTORY_SERVICE_TYPE}">
            <SearchCaps>{search_caps}</SearchCaps>
        </u:GetSearchCapabilitiesResponse>"#
    );
    (wrap_with_envelope_body(&body), HTTP_RESPONSE_OK)
}

fn generate_get_sort_capabilities_response() -> (String, &'static str) {
    // probably a CSV like search capabilities
    let sort_caps = ""; // TODO nothing, for now.
    let body = format!(
        r#"
        <u:GetSortCapabilitiesResponse xmlns:u="{CONTENT_DIRECTORY_SERVICE_TYPE}">
            <SortCaps>{sort_caps}</SortCaps>
        </u:GetSortCapabilitiesResponse>"#
    );
    (wrap_with_envelope_body(&body), HTTP_RESPONSE_OK)
}

fn wrap_with_envelope_body(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>{body}</s:Body>
</s:Envelope>"#
    )
}

fn generate_browse_response(
    collection: &Collection,
    object_id: &[String],
    starting_index: Option<u16>,
    requested_count: Option<u16>,
    addr: &str,
) -> (String, &'static str) {
    let browse_response =
        match object_id {
            [root] if root == "0" => Some(generate_browse_root_response(collection)),
            [root, next] if root == "0" && next == "albums" => Some(
                generate_browse_albums_response(collection, starting_index, requested_count, addr),
            ),
            [root, next, album_id] if root == "0" && next == "albums" => {
                Some(generate_browse_an_album_response(
                    collection,
                    album_id,
                    starting_index,
                    requested_count,
                    addr,
                ))
            }
            [root, next] if root == "0" && next == "=Artist" => Some(
                generate_browse_artists_response(collection, starting_index, requested_count),
            ),
            [root, next, artist_id] if root == "0" && next == "=Artist" => {
                Some(generate_browse_an_artist_response(
                    collection,
                    artist_id,
                    starting_index,
                    requested_count,
                ))
            }
            [root, next, artist_id, _artist_what] if root == "0" && next == "=Artist" => {
                Some(generate_browse_an_artist_albums_response(
                    collection,
                    artist_id,
                    starting_index,
                    requested_count,
                    addr,
                ))
            }
            [root, next, artist_id, artist_what, album_id]
                if root == "0" && next == "=Artist" && artist_what == "albums" =>
            {
                Some(generate_browse_an_artist_album_response(
                    collection,
                    artist_id,
                    album_id,
                    starting_index,
                    requested_count,
                    addr,
                ))
            }
            [root, next] if root == "0" && next == "=All Artists" => Some(
                generate_browse_all_artists_response(collection, starting_index, requested_count),
            ),
            _ => {
                error!("control: unexpected object ID: {object_id:?}");
                None
            }
        };
    browse_response.map_or_else(
        || (String::new(), "400 BAD REQUEST"),
        |browse_response| {
            let body = format!(
                r#"
        <u:BrowseResponse xmlns:u="{CONTENT_DIRECTORY_SERVICE_TYPE}">{browse_response}
        </u:BrowseResponse>"#
            );
            (wrap_with_envelope_body(&body), HTTP_RESPONSE_OK)
        },
    )
}

fn parse_soap_search_request(
    body: &str,
) -> (
    Option<Vec<String>>,
    Option<String>,
    Option<u16>,
    Option<u16>,
) {
    let mut container_id = None;
    let mut search_criteria = None;
    let mut starting_index: Option<u16> = None;
    let mut requested_count: Option<u16> = None;
    let envelope = Element::parse(body.as_bytes()).unwrap();
    let body = envelope.get_child("Body").unwrap();
    match body.get_child("Search") {
        Some(browse) => {
            for child in &browse.children {
                match child.as_element().unwrap().name.as_str() {
                    "ContainerID" => {
                        container_id = Some(
                            child
                                .as_element()
                                .unwrap()
                                .get_text()
                                .unwrap()
                                .split('$')
                                .map(ToString::to_string)
                                .collect(),
                        );
                    }
                    "SearchCriteria" => {
                        search_criteria = child.as_element().unwrap().get_text().map(Into::into);
                        if let Some(search_criteria) = &search_criteria {
                            warn!("search criteria: {search_criteria}. what's up");
                        } else {
                            warn!("no search criteria. why are we here?");
                        }
                    }
                    "Filter" => {
                        let filter = child.as_element().unwrap().get_text().unwrap();
                        if filter == "*" {
                            info!("no filter. simple.");
                        } else {
                            warn!("some filter: {filter}. what's up");
                        }
                    }
                    "StartingIndex" => {
                        starting_index = Some(
                            child
                                .as_element()
                                .unwrap()
                                .get_text()
                                .unwrap()
                                .parse()
                                .unwrap(),
                        );
                    }
                    "RequestedCount" => {
                        requested_count = Some(
                            child
                                .as_element()
                                .unwrap()
                                .get_text()
                                .unwrap()
                                .parse()
                                .unwrap(),
                        );
                    }
                    "SortCriteria" => {
                        let sort_criteria = child.as_element().unwrap().get_text();
                        if let Some(sort_criteria) = sort_criteria {
                            warn!("sort criteria: {sort_criteria}. what's up");
                        } else {
                            warn!("no sort criteria. do i just make this up?");
                        }
                    }
                    anything => warn!("what is {anything:?}"),
                }
            }
        }
        None => panic!("no Browse child"),
    }

    (
        container_id,
        search_criteria,
        starting_index,
        requested_count,
    )
}

fn parse_search_criteria(s: &str) -> &str {
    // TODO actually parse stuff
    let re = Regex::new(r#"dc:title contains "(?P<title>.*)" and @refID exists false"#).unwrap();
    re.captures(s)
        .and_then(|cap| cap.name("title").map(|title| title.as_str()))
        .unwrap_or_default()
}

fn generate_search_response(
    collection: &Collection,
    container_id: &[String],
    search_criteria: &str,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
    addr: &str,
) -> (String, &'static str) {
    // TODO handle starting_index, requested_count
    let search_response = match container_id {
        [root] if root == "0" => {
            // let total_matches = collection.get_albums().count();
            let mut total_matches = 0; // TODO how do i figure this out?
            // let starting_index = starting_index.unwrap().into();
            // let requested_count: usize = requested_count.unwrap().into();
            let mut number_returned = 0;
            let mut result = String::new();
            let mut album_id = 0;
            for (i, artist) in collection.get_artists().enumerate() {
                let artist_id = i + 1; // WTF
                let artist_name = xml::escape::escape_str_attribute(&artist.name);
                if artist.name.contains(search_criteria) {
                    write!(
                        result,
                        r#"<container id="0$=Artist${artist_id}" parentID="0$=Artist" restricted="1" searchable="1"><dc:title>{artist_name}</dc:title><upnp:class>object.container.person.musicArtist</upnp:class></container>"#
                    ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));

                    number_returned += 1;
                }

                for album in artist.get_albums() {
                    let album_title = xml::escape::escape_str_attribute(&album.title);
                    if album.title.contains(search_criteria) {
                        // let track_count = album.get_tracks().count();
                        // let date = create_date_element(album.date);
                        // let cover = create_album_art_element(addr, &album.cover);

                        write!(
                            result,
                            // childCount="{track_count}"
                            // {date}<upnp:artist>{artist_name}</upnp:artist><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist>{cover}
                            r#"<container id="0$albums$*a{album_id}" parentID="0$albums" restricted="1" searchable="1"><dc:title>{album_title}</dc:title><dc:creator>{artist_name}</dc:creator><upnp:class>object.container.album.musicAlbum</upnp:class></container>"#,
                        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));

                        number_returned += 1;
                    }

                    for (j, track) in album.get_tracks().enumerate() {
                        let track_id = j + 1; // WTF

                        if track.title.contains(search_criteria) {
                            // let date = create_date_element(album.date);
                            // let cover = create_album_art_element(addr, &album.cover);

                            let track_title = xml::escape::escape_str_attribute(&track.title);
                            let track_number = track.number;
                            let duration = format_time_nice(track.duration);
                            let size = track.size;
                            let bits_per_sample = track.bits_per_sample;
                            let sample_frequency = track.sample_frequency;
                            let channels = track.channels;
                            let file = format!("{}/{}", addr, track.file);
                            let file = xml::escape::escape_str_attribute(&file);
                            write!(
                                result,
                                // id="0$=Artist${artist_id}$albums${album_id}${track_id}" parentID="0$=Artist${artist_id}$albums${album_id}"
                                // {date}{cover}
                                r#"<item id="0$albums$*a{album_id}$*i{track_id}" parentID="0$albums$*a{album_id}" restricted="1"><dc:title>{track_title}</dc:title><upnp:album>{album_title}</upnp:album><upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist><upnp:originalTrackNumber>{track_number}</upnp:originalTrackNumber><res duration="{duration}" size="{size}" bitsPerSample="{bits_per_sample}" sampleFrequency="{sample_frequency}" nrAudioChannels="{channels}" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">{file}</res><upnp:class>object.item.audioItem.musicTrack</upnp:class></item>"#,
                            ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));

                            number_returned += 1;
                        }
                    }

                    album_id += 1;
                }
            }

            // TODO this isn't right
            total_matches = number_returned;

            Some(format_response(&result, number_returned, total_matches))
        }
        _ => {
            error!("control: unexpected container ID: {container_id:?}");
            None
        }
    };
    search_response.map_or_else(
        || (String::new(), "400 BAD REQUEST"),
        |search_response| {
            let body = format!(
                r#"
        <u:SearchResponse xmlns:u="{CONTENT_DIRECTORY_SERVICE_TYPE}">{search_response}
        </u:SearchResponse>"#
            );
            (wrap_with_envelope_body(&body), HTTP_RESPONSE_OK)
        },
    )
}

fn handle_device_connection(
    device_uuid: Uuid,
    addr: &str,
    collection: &Collection,
    input_stream: impl std::io::Read,
    mut output_stream: impl std::io::Write,
) {
    let mut buf_reader = BufReader::new(input_stream);

    let request_line = match parse_some_request_line(&mut buf_reader) {
        Ok(request_line) => request_line,
        Err(e) => {
            let (error_code, error_description) = match e {
                ParseRequestError::EmptyRequest => (401_u16, "Missing Request"),
                ParseRequestError::IoError(err) => {
                    warn!("could not parse request line: {err}");
                    (604_u16, "IO Error")
                }
            };
            let (content, result) = soap_upnp_error(error_code, error_description);
            write_response(
                result,
                Some("text/xml; charset=utf-8"),
                content.as_bytes(),
                &mut output_stream,
            );
            return;
        }
    };
    debug!("Request: {request_line}");

    let http_request_headers = parse_some_headers(&mut buf_reader);
    debug!("Headers: {http_request_headers:?}");

    let content_length = get_content_length(&request_line, &http_request_headers);
    debug!("content length: {content_length}");

    let body = parse_body(content_length, &mut buf_reader);

    let body = body.map(|body| {
        debug!("body: {body}");
        body
    });

    let (content, result) = match &request_line[..] {
        "GET /Device.xml HTTP/1.1" => {
            let content = format!(include_str!("Device.xml"), device_uuid);

            (content, HTTP_RESPONSE_OK)
        }
        "GET /ConnectionManager.xml HTTP/1.1" => {
            unimplemented!("GET /ConnectionManager.xml not implemented");
        }
        "GET /ContentDirectory.xml HTTP/1.1" => {
            let content = include_str!("ContentDirectory.xml");

            (content.to_string(), HTTP_RESPONSE_OK)
        }
        "POST /ContentDirectory/Control HTTP/1.1" => {
            let soap_action_key = http_request_headers
                .keys()
                .find(|k| k.eq_ignore_ascii_case("Soapaction"))
                .expect("no soap action");
            http_request_headers.get(soap_action_key).map_or_else(
                || {
                    warn!("control: no soap action");
                    (String::new(), "400 BAD REQUEST")
                },
                |soap_action| {
                    let soap_action = if soap_action.starts_with('"') && soap_action.ends_with('"')
                    {
                        soap_action.trim_matches('"')
                    } else {
                        warn!("expected soap action to be enclosed in '\"': {soap_action}");
                        // not just an invalid action, something worse?
                        return soap_upnp_error(401, "Invalid Action");
                    };
                    let Some((service, action)) = soap_action.split_once('#') else {
                        warn!("received soap action without '#': {soap_action}");
                        // not just an invalid action, something worse?
                        return soap_upnp_error(401, "Invalid Action");
                    };

                    if service == CONTENT_DIRECTORY_SERVICE_TYPE {
                        handle_content_directory_actions(action, addr, collection, body)
                    } else {
                        // TODO here, handle ConnectionManager, etc.
                        info!("we got {service}, we got {action}");
                        soap_upnp_error(401, "Invalid Service")
                    }
                },
            )
        }
        something if something.starts_with("GET /Content/") => {
            content_handler(something, collection, output_stream);
            return;
        }
        _ => {
            warn!("unknown request line: {request_line}");

            (String::new(), "404 NOT FOUND")
        }
    };

    write_response(
        result,
        Some("text/xml; charset=utf-8"),
        content.as_bytes(),
        &mut output_stream,
    );
}

fn handle_content_directory_actions<'a>(
    action: &str,
    addr: &str,
    collection: &Collection,
    body: Option<String>,
) -> (String, &'a str) {
    match action {
        CDS_GET_SYSTEM_UPDATE_ID_ACTION => generate_get_system_update_id_response(collection),
        CDS_GET_SEARCH_CAPABILITIES_ACTION => generate_get_search_capabilities_response(),
        CDS_GET_SORT_CAPABILITIES_ACTION => generate_get_sort_capabilities_response(),
        CDS_BROWSE_ACTION => {
            let (object_id, starting_index, requested_count) = body.map_or_else(
                || {
                    panic!("no body");
                },
                |body| parse_soap_browse_request(&body),
            );

            object_id.map_or_else(
                || {
                    panic!("no object id");
                },
                |object_id| {
                    generate_browse_response(
                        collection,
                        &object_id,
                        starting_index,
                        requested_count,
                        addr,
                    )
                },
            )
        }
        CDS_SEARCH_ACTION => {
            let (container_id, search_criteria, starting_index, requested_count) = body
                .map_or_else(
                    || {
                        panic!("no body");
                    },
                    |body| parse_soap_search_request(&body),
                );

            println!(
                "search:\n\tcontainer_id: {container_id:?}\n\tsearch_criteria: {search_criteria:?}\n\tstarting_index: {starting_index:?}\n\trequested_count: {requested_count:?}"
            );

            let temp = search_criteria.unwrap_or_default();
            let search_criteria = parse_search_criteria(&temp);

            let container_id = container_id.unwrap_or_else(|| {
                warn!("no container id, assuming 0");
                vec!["0".to_string()]
            });

            generate_search_response(
                collection,
                &container_id,
                search_criteria,
                starting_index,
                requested_count,
                addr,
            )
        }
        CDS_CREATE_OBJECT_ACTION
        | CDS_DESTROY_OBJECT_ACTION
        | CDS_UPDATE_OBJECT_ACTION
        | CDS_IMPORT_RESOURCE_ACTION
        | CDS_EXPORT_RESOURCE_ACTION
        | CDS_STOP_TRANSFER_RESOURCE_ACTION
        | CDS_GET_TRANSFER_PROGRESS_ACTION
        | CDS_DELETE_RESOURCE_ACTION
        | CDS_CREATE_REFERENCE_ACTION => soap_upnp_error(602, "Action Not Implemented"),
        _ => {
            info!("we got {CONTENT_DIRECTORY_SERVICE_TYPE}, we got {action}");
            soap_upnp_error(401, "Invalid Action")
        }
    }
}

fn soap_upnp_error(error_code: u16, error_description: &str) -> (String, &str) {
    // it seems based on the example in the docs that its always 500?
    let http_error_string = "500 Internal Server Error";
    let content = format!(
        r#"
        <s:Fault>
            <faultcode>s:Client</faultcode>
            <faultstring>UPnPError</faultstring>
            <detail>
                <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
                    <errorCode>{error_code}</errorCode>
                    <errorDescription>{error_description}</errorDescription>
                </UPnPError>
            </detail>
        </s:Fault>"#
    );
    (wrap_with_envelope_body(&content), http_error_string)
}

fn write_response(
    result: &str,
    content_type: Option<&str>,
    content: &[u8],
    output_stream: &mut impl std::io::Write,
) {
    let length = content.len();
    let status_line = format!("{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {result}");
    let content_type_header = content_type.map_or_else(String::new, |content_type| {
        format!("\r\nContent-Type: {content_type}")
    });
    let response_headers =
        format!("{status_line}{content_type_header}\r\nContent-Length: {length}\r\n\r\n");
    let response = [response_headers.as_bytes(), content].concat();
    if let Err(err) = output_stream.write_all(&response[..]) {
        error!("error writing response: {err}");
    }
}

fn content_handler(
    request_line: &str,
    collection: &Collection,
    mut output_stream: impl std::io::Write,
) {
    let request_path = urlencoding::decode(
        request_line
            .strip_prefix("GET /Content/")
            .unwrap()
            .strip_suffix(" HTTP/1.1")
            .unwrap(),
    )
    .unwrap();
    let content_type = if request_path.ends_with(".jpg") {
        Some("image/jpeg")
    } else if request_path.ends_with(".flac") {
        Some("audio/flac")
    } else {
        None
    };

    if let Some(content_type) = content_type {
        let file = collection.base.join(request_path.as_ref());
        let content = match fs::read(&file) {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                write_response("404 NOT FOUND", None, &[], &mut output_stream);
                return;
            }
            Err(err) => {
                panic!("could not read {}: {err}", file.display());
            }
        };

        write_response(
            HTTP_RESPONSE_OK,
            Some(content_type),
            &content,
            &mut output_stream,
        );
    } else {
        let content = format!("unsupported /Content request for {request_path}");
        write_response(
            "501 NOT IMPLEMENTED",
            Some("text/plain; charset=utf-8"),
            content.as_bytes(),
            &mut output_stream,
        );
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

// FLAC stuff see https://www.rfc-editor.org/rfc/rfc9639

// TODO these should not require reading the entire file into memory

const FLAC_MARKER: [u8; 4] = [0x66_u8, 0x4C_u8, 0x61_u8, 0x43_u8];

fn is_flac(reader: &mut BufReader<impl Read>) -> bool {
    let mut buf = [0; 4];
    reader
        .read_exact(&mut buf)
        .expect("failed to attempt to read FLAC marker");
    buf == FLAC_MARKER
}

#[derive(Debug)]
enum FlacMetadataBlockType {
    /// 0 Streaminfo
    Streaminfo,
    /// 1 Padding
    Padding,
    /// 2 Application
    Application,
    /// 3 Seek table
    SeekTable,
    /// 4 Vorbis comment
    VorbisComment,
    /// 5 Cuesheet
    Cuesheet,
    /// 6 Picture
    Picture,
    /// 7 - 126 Reserved
    Reserved,
    /// 127 Forbidden (to avoid confusion with a frame sync code)
    Forbidden,
}

impl FlacMetadataBlockType {
    fn from_int(value: u8) -> Self {
        match value {
            0 => Self::Streaminfo,
            1 => Self::Padding,
            2 => Self::Application,
            3 => Self::SeekTable,
            4 => Self::VorbisComment,
            5 => Self::Cuesheet,
            6 => Self::Picture,
            7..=126 => Self::Reserved,
            127 => Self::Forbidden,
            _ => {
                unreachable!("value was Bitwise AND with 0b111_1111 so should be in range 0..=127")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum FlacMetadataPictureType {
    /// 0 Other
    Other,

    /// 1 PNG file icon of 32x32 pixels (see [RFC2083])
    PNGIcon,

    /// 2 General file icon
    GeneralIcon,

    /// 3 Front cover
    FrontCover,

    /// 4 Back cover
    BackCover,

    /// 5 Liner notes page
    LinerNotes,

    /// 6 Media label (e.g., CD, Vinyl or Cassette label)
    MediaLabel,

    /// 7 Lead artist, lead performer, or soloist
    LeadArtist,

    /// 8 Artist or performer
    Artist,

    /// 9 Conductor
    Conductor,

    /// 10 Band or orchestra
    Band,

    /// 11 Composer
    Composer,

    /// 12 Lyricist or text writer
    Lyricist,

    /// 13 Recording location
    RecordingLocation,

    /// 14 During recording
    DuringRecording,

    /// 15 During performance
    DuringPerformance,

    /// 16 Movie or video screen capture
    VideoCapture,

    /// 17 A bright colored fish
    BrightColoredFish,

    /// 18 Illustration
    Illustration,

    /// 19 Band or artist logotype
    Logo,

    /// 20 Publisher or studio logotype
    PublisherStudioLogo,
}

impl FlacMetadataPictureType {
    fn from_int(value: u32) -> std::result::Result<Self, String> {
        match value {
            0 => Ok(Self::Other),
            1 => Ok(Self::PNGIcon),
            2 => Ok(Self::GeneralIcon),
            3 => Ok(Self::FrontCover),
            4 => Ok(Self::BackCover),
            5 => Ok(Self::LinerNotes),
            6 => Ok(Self::MediaLabel),
            7 => Ok(Self::LeadArtist),
            8 => Ok(Self::Artist),
            9 => Ok(Self::Conductor),
            10 => Ok(Self::Band),
            11 => Ok(Self::Composer),
            12 => Ok(Self::Lyricist),
            13 => Ok(Self::RecordingLocation),
            14 => Ok(Self::DuringRecording),
            15 => Ok(Self::DuringPerformance),
            16 => Ok(Self::VideoCapture),
            17 => Ok(Self::BrightColoredFish),
            18 => Ok(Self::Illustration),
            19 => Ok(Self::Logo),
            20 => Ok(Self::PublisherStudioLogo),
            _ => Err(format!("invalid picture type: {value}")),
        }
    }
}

#[derive(Debug)]
struct FlacMetadata {
    /// The minimum block size (in samples) used in the stream, excluding the last block.
    minimum_block_size: u16,

    /// The maximum block size (in samples) used in the stream.
    maximum_block_size: u16,

    /// The minimum frame size (in bytes) used in the stream. A value of 0 signifies that the value is not known.
    minimum_frame_size: u32,

    /// The maximum frame size (in bytes) used in the stream. A value of 0 signifies that the value is not known.
    maximum_frame_size: u32,

    /// Sample rate in Hz.
    sample_rate: u32,

    /// (number of channels)-1. FLAC supports from 1 to 8 channels.
    channels: u8,

    /// (bits per sample)-1. FLAC supports from 4 to 32 bits per sample.
    bits: u8,

    /// Total number of interchannel samples in the stream. A value of 0 here means the number of total samples is unknown.
    total: u64,

    /// MD5 checksum of the unencoded audio data. A value of 0 signifies that the value is not known.
    // checksum: [u8; 16],
    checksum: u128,

    /// The name of the program that generated the file or stream.
    vendor: String,

    /// Metadata describing various aspects of the contained audio.
    fields: Vec<FlacMetadataCommentField>,

    /// Contains image data of pictures in some way belonging to the audio
    picture: Vec<FlacMetadataPicture>,

    /// Can be used to store seek points
    seek_table: Vec<FlacMetadataSeekPoint>,

    /// Store either the track and index point structure of a Compact Disc Digital Audio (CD-DA)
    /// along with its audio or to provide a mechanism to store locations of interest
    cue_sheet: Option<FlacMetadataCueSheet>,

    /// Used by third-party applications
    application: Vec<FlacMetadataApplication>,
}

impl FlacMetadata {
    const fn default() -> Self {
        Self {
            minimum_block_size: 0,
            maximum_block_size: 0,
            minimum_frame_size: 0,
            maximum_frame_size: 0,
            sample_rate: 0,
            channels: 0,
            bits: 0,
            total: 0,
            checksum: 0,
            vendor: String::new(),
            fields: vec![],
            picture: vec![],
            seek_table: vec![],
            cue_sheet: None,
            application: vec![],
        }
    }

    fn duration(&self) -> NaiveTime {
        let whole_seconds = self.total / u64::from(self.sample_rate);
        let remainder = self.total % u64::from(self.sample_rate);
        let milli = (f64::from(u32::try_from(remainder).expect("crazy if not"))
            / f64::from(self.sample_rate)
            * 1000.0)
            .trunc();

        // i think i'm ok here but i haven't really thought about it
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let nano = milli as u32 * 1_000_000;

        NaiveTime::from_num_seconds_from_midnight_opt(
            u32::try_from(whole_seconds).expect("too much seconds"),
            nano,
        )
        .expect("exceeded time")
    }
}

#[derive(Debug, PartialEq)]
struct FlacMetadataCommentField {
    name: String,
    content: String,
}

#[derive(PartialEq)]
struct FlacMetadataPicture {
    picture_type: FlacMetadataPictureType,
    media_type: String,
    description: String,
    width: u32,
    height: u32,
    depth: u32,
    colors: u32,
    picture: Vec<u8>,
}

impl std::fmt::Debug for FlacMetadataPicture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlacMetadataPicture")
            .field("picture_type", &self.picture_type)
            .field("media_type", &self.media_type)
            .field("description", &self.description)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("depth", &self.depth)
            .field("colors", &self.colors)
            .field("picture", &Picture(&self.picture))
            .finish()
    }
}

struct Picture<'a>(&'a [u8]);

impl std::fmt::Debug for Picture<'_> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Print at most 8 elements, abbreviate the rest
        let mut f = fmt.debug_set();
        let f = f.entries(self.0.iter().take(8));
        if self.0.len() > 8 {
            f.finish_non_exhaustive()
        } else {
            f.finish()
        }
    }
}

#[derive(Debug, PartialEq)]
struct FlacMetadataSeekPoint {
    sample_number: u64,
    offset: u64,
    samples: u16,
}

#[derive(Debug, PartialEq)]
struct FlacMetadataCueSheet {
    /// Media catalog number in ASCII printable characters 0x20-0x7E.
    catalog_number: String,

    /// Number of lead-in samples.
    lead_in_samples: u64,

    /// 1 if the cuesheet corresponds to a CD-DA; else 0.
    is_cdda: bool,

    /// Cuesheet tracks
    tracks: Vec<FlacMetadataCueSheetTrack>,
}

#[derive(Debug, PartialEq)]
struct FlacMetadataCueSheetTrack {
    /// Track offset of the first index point in samples, relative to the beginning of the FLAC audio stream.
    offset: u64,

    /// Track number.
    number: u8,

    /// Track ISRC.
    isrc: Option<String>,

    /// The track type. This corresponds to the CD-DA Q-channel control bit 3.
    is_audio: bool,

    /// The pre-emphasis flag. This corresponds to the CD-DA Q-channel control bit 5.
    preemphasis_flag: bool,

    /// Index points for all tracks except the lead-out track
    index_points: Vec<FlacMetadataCueSheetTrackIndexPoint>,
}

#[derive(Debug, PartialEq)]
struct FlacMetadataCueSheetTrackIndexPoint {
    /// Offset in samples, relative to the track offset, of the index point.
    offset: u64,

    /// The track index point number.
    number: u8,
}

#[derive(Debug, PartialEq)]
struct FlacMetadataApplication {
    /// Registered application ID
    id: u32,

    /// Application data
    data: Vec<u8>,
}

fn extract_flac_metadata(reader: &mut BufReader<impl Read>) -> FlacMetadata {
    let mut metadata = FlacMetadata::default();

    let mut buf = [0; 4];
    reader
        .read_exact(&mut buf)
        .expect("failed to read FLAC marker");
    debug_assert_eq!(buf, FLAC_MARKER);

    // Each metadata block starts with a 4-byte header. The first bit in this header flags
    // whether a metadata block is the last one. It is 0 when other metadata blocks follow;
    // otherwise, it is 1. The 7 remaining bits of the first header byte contain the type of
    // the metadata block as an unsigned number between 0 and 126, according to the following
    // table. A value of 127 (i.e., 0b1111111) is forbidden. The three bytes that follow code
    // for the size of the metadata block in bytes, excluding the 4 header bytes, as an
    // unsigned number coded big-endian.
    loop {
        let mut header = [0; 4];
        reader
            .read_exact(&mut header)
            .expect("failed to read FLAC metadata block header");
        let last_metadata_block = (header[0] & 0b1000_0000) >> 7;
        let metadata_block_type = FlacMetadataBlockType::from_int(header[0] & 0b111_1111);

        let block_size = usize::from(header[3])
            + usize::from(header[2]) * 0x100
            + usize::from(header[1]) * 0x10000;

        let mut data = vec![0; block_size];
        reader
            .read_exact(&mut data)
            .expect("failed to read FLAC metadata block");

        match metadata_block_type {
            FlacMetadataBlockType::Streaminfo => {
                // The streaminfo metadata block has information about the whole stream, such
                // as sample rate, number of channels, total number of samples, etc. It MUST be
                // present as the first metadata block in the stream. Other metadata blocks MAY
                // follow. There MUST be no more than one streaminfo metadata block per FLAC
                // stream.

                // If the streaminfo metadata block contains incorrect or incomplete
                // information, decoder behavior is left unspecified (i.e., it is up to the
                // decoder implementation). A decoder MAY choose to stop further decoding when
                // the information supplied by the streaminfo metadata block turns out to be
                // incorrect or contains forbidden values. A decoder accepting information from
                // the streaminfo metadata block (most significantly, the maximum frame size,
                // maximum block size, number of audio channels, number of bits per sample, and
                // total number of samples) without doing further checks during decoding of
                // audio frames could be vulnerable to buffer overflows. See also Section 11.

                // The following table describes the streaminfo metadata block in order,
                // excluding the metadata block header.

                //  0               1               2               3               4               5               6               7               8               9
                //  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                // |                               |                               |                                               |                                               |

                //  10              11              12              13              14              14              16              17              18              19
                //  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
                // |                                       |     |         |                                                                       | ...

                // u(16)	The minimum block size (in samples) used in the stream, excluding the last block.
                let minimum_block_size = u16::from_be_bytes((&data[0..2]).try_into().unwrap());
                metadata.minimum_block_size = minimum_block_size;

                // u(16)	The maximum block size (in samples) used in the stream.
                let maximum_block_size = u16::from_be_bytes((&data[2..4]).try_into().unwrap());
                metadata.maximum_block_size = maximum_block_size;

                // The minimum block size and the maximum block size MUST be in the 16-65535
                // range. The minimum block size MUST be equal to or less than the maximum block size.

                // u(24)	The minimum frame size (in bytes) used in the stream. A value of 0 signifies that the value is not known.
                let mut u32_data = [0_u8; 4];
                u32_data[1..].copy_from_slice(&data[4..7]);
                let minimum_frame_size = u32::from_be_bytes(u32_data);
                metadata.minimum_frame_size = minimum_frame_size;

                // u(24)	The maximum frame size (in bytes) used in the stream. A value of 0 signifies that the value is not known.
                let mut u32_data = [0_u8; 4];
                u32_data[1..].copy_from_slice(&data[7..10]);
                let maximum_frame_size = u32::from_be_bytes(u32_data);
                metadata.maximum_frame_size = maximum_frame_size;

                // u(20)	Sample rate in Hz.
                let mut u32_data = [0_u8; 4];
                u32_data[1..].copy_from_slice(&data[10..13]);
                let sample_rate = u32::from_be_bytes(u32_data) >> 4;
                metadata.sample_rate = sample_rate;

                // u(3)	(number of channels)-1. FLAC supports from 1 to 8 channels.
                let channels = ((data[12] & 15) >> 1) + 1;
                metadata.channels = channels;

                // u(5)	(bits per sample)-1. FLAC supports from 4 to 32 bits per sample.
                let bits = u8::try_from(
                    (u16::from_be_bytes((&data[12..14]).try_into().unwrap()) >> 4 & 31) + 1,
                )
                .expect("bit magic should make this fit in u8");
                metadata.bits = bits;

                // u(36)	Total number of interchannel samples in the stream. A value of 0 here means the number of total samples is unknown.
                let mut u64_data = [0_u8; 8];
                u64_data[3..].copy_from_slice(&data[13..18]);
                let total = u64::from_be_bytes(u64_data) & 0x000F_FFFF_FFFF;
                metadata.total = total;

                // u(128)	MD5 checksum of the unencoded audio data. This allows the decoder to determine if an error exists in the audio data even when, despite the error, the bitstream itself is valid. A value of 0 signifies that the value is not known.
                let checksum = u128::from_be_bytes((&data[18..]).try_into().unwrap());
                metadata.checksum = checksum;
            }
            FlacMetadataBlockType::Padding => {
                // nothing to do for padding
            }
            FlacMetadataBlockType::Application => {
                // The application metadata block is for use by third-party applications. The only
                // mandatory field is a 32-bit application identifier (application ID). Application
                // IDs are registered in the IANA "FLAC Application Metadata Block IDs" registry
                // (see Section 12.2).

                metadata
                    .application
                    .push(extract_flac_application_metadata(&data[..]));
            }
            FlacMetadataBlockType::SeekTable => {
                // The seek table metadata block can be used to store seek points. It is possible
                // to seek to any given sample in a FLAC stream without a seek table, but the
                // delay can be unpredictable since the bitrate may vary widely within a stream.
                // By adding seek points to a stream, this delay can be significantly reduced.
                // There MUST NOT be more than one seek table metadata block in a stream, but the
                // table can have any number of seek points.

                // Each seek point takes 18 bytes, so a seek table with 1% resolution within a
                // stream adds less than 2 kilobytes of data. The number of seek points is implied
                // by the size described in the metadata block header, i.e., equal to size / 18.
                // There is also a special "placeholder" seek point that will be ignored by
                // decoders but can be used to reserve space for future seek point insertion.

                metadata.seek_table = extract_flac_seek_table_metadata(&data[..]);
            }
            FlacMetadataBlockType::VorbisComment => {
                // A Vorbis comment metadata block contains human-readable information coded in
                // UTF-8. The name "Vorbis comment" points to the fact that the Vorbis codec
                // stores such metadata in almost the same way (see [Vorbis]). A Vorbis comment
                // metadata block consists of a vendor string optionally followed by a number
                // of fields, which are pairs of field names and field contents. The vendor
                // string contains the name of the program that generated the file or stream.
                // The fields contain metadata describing various aspects of the contained
                // audio. Many users refer to these fields as "FLAC tags" or simply as "tags".
                // A FLAC file MUST NOT contain more than one Vorbis comment metadata block.

                let (vendor, fields) = extract_flac_comment_metadata(&data[..]);
                metadata.vendor = vendor;
                metadata.fields = fields;
            }
            FlacMetadataBlockType::Cuesheet => {
                // A cuesheet metadata block can be used either to store the track and index point
                // structure of a Compact Disc Digital Audio (CD-DA) along with its audio or to
                // provide a mechanism to store locations of interest within a FLAC file. Certain
                // aspects of this metadata block come directly from the CD-DA specification
                // (called Red Book), which is standardized as [IEC.60908.1999]. The description
                // below is complete, and further reference to [IEC.60908.1999] is not needed to
                // implement this metadata block.

                metadata.cue_sheet = Some(extract_flac_cus_sheet_metadata(&data[..]));
            }
            FlacMetadataBlockType::Picture => {
                // The picture metadata block contains image data of a picture in some way
                // belonging to the audio contained in the FLAC file. Its format is derived
                // from the Attached Picture (APIC) frame in the ID3v2 specification; see [ID3v2].
                // However, contrary to the APIC frame in ID3v2, the media type and description
                // are prepended with a 4-byte length field instead of being 0x00 delimited
                // strings. A FLAC file MAY contain one or more picture metadata blocks.

                // Note that while the length fields for media type, description, and picture data
                // are 4 bytes in length and could code for a size up to 4 GiB in theory, the
                // total metadata block size cannot exceed what can be described by the metadata
                // block header, i.e., 16 MiB.

                // Instead of picture data, the picture metadata block can also contain a URI as
                // described in [RFC3986].

                match extract_flac_picture_metadata(&data[..]) {
                    Ok(picture) => metadata.picture.push(picture),
                    Err(err) => error!("{err}"),
                }
            }
            FlacMetadataBlockType::Reserved => {
                warn!("FLAC metadata contains reserved block {metadata_block_type:?}, ignoring");
            }
            FlacMetadataBlockType::Forbidden => {
                warn!("FLAC metadata contains forbidden block, ignoring");
            }
        }

        if last_metadata_block == 1 {
            break;
        }
    }

    metadata
}

fn extract_flac_application_metadata(data: &[u8]) -> FlacMetadataApplication {
    let mut pos = 0;

    // u(32)	Registered application ID.
    let application_id = u32::from_be_bytes((&data[pos..pos + 4]).try_into().unwrap());

    pos += 4;

    // u(n)	Application data (n MUST be a multiple of 8, i.e., a whole number of
    // bytes). n is 8 times the size described in the metadata block header minus the
    // 32 bits already used for the application ID.
    let application_data = &data[pos..];

    FlacMetadataApplication {
        id: application_id,
        data: application_data.into(),
    }
}

fn extract_flac_seek_table_metadata(data: &[u8]) -> Vec<FlacMetadataSeekPoint> {
    let mut seek_table = vec![];

    let mut pos = 0;

    while pos < data.len() {
        let seek_data = &data[pos..pos + 18];

        // u(64)	Sample number of the first sample in the target frame or 0xFFFFFFFFFFFFFFFF for a placeholder point.
        let sample_number = u64::from_be_bytes((&seek_data[0..8]).try_into().unwrap());

        // u(64)	Offset (in bytes) from the first byte of the first frame header to the first byte of the target frame's header.
        let offset = u64::from_be_bytes((&seek_data[8..16]).try_into().unwrap());

        // u(16)	Number of samples in the target frame.
        let samples = u16::from_be_bytes((&seek_data[16..18]).try_into().unwrap());

        pos += 18;

        seek_table.push(FlacMetadataSeekPoint {
            sample_number,
            offset,
            samples,
        });
    }

    seek_table
}

fn extract_flac_comment_metadata(data: &[u8]) -> (String, Vec<FlacMetadataCommentField>) {
    let mut pos = 0;

    // In a Vorbis comment metadata block, the metadata block header is directly
    // followed by 4 bytes containing the length in bytes of the vendor string as
    // an unsigned number coded little-endian. The vendor string follows, is
    // UTF-8 coded and is not terminated in any way.
    let vendor_length = u32::from_le_bytes((&data[pos..pos + 4]).try_into().unwrap()) as usize;

    pos += 4;

    let vendor = String::from_utf8((&data[pos..pos + vendor_length]).into())
        .expect("vendor string must be UTF-8");

    pos += vendor_length;

    // Following the vendor string are 4 bytes containing the number of fields that
    // are in the Vorbis comment block, stored as an unsigned number coded
    // little-endian. If this number is non-zero, it is followed by the fields
    // themselves, each of which is stored with a 4-byte length. For each field,
    // the field length in bytes is stored as a 4-byte unsigned number coded
    // little-endian. The field itself follows it. Like the vendor string, the
    // field is UTF-8 coded and not terminated in any way.
    let field_count = u32::from_le_bytes((&data[pos..pos + 4]).try_into().unwrap()) as usize;
    let mut fields = Vec::with_capacity(field_count);

    pos += 4;

    for _ in 0..field_count {
        let field_length = u32::from_le_bytes((&data[pos..pos + 4]).try_into().unwrap()) as usize;

        pos += 4;

        if pos + field_length > data.len() {
            warn!(
                "field data exceeds Vorbis comment length. remaining data {:02x?}",
                &data[pos..]
            );
            break;
        }
        let field = String::from_utf8((&data[pos..pos + field_length]).into())
            .expect("field string must be UTF-8");

        pos += field_length;

        // Each field consists of a field name and field contents, separated by an =
        // character. The field name MUST only consist of UTF-8 code points U+0020
        // through U+007E, excluding U+003D, which is the = character. In other words,
        // the field name can contain all printable ASCII characters except the equals
        // sign. The evaluation of the field names MUST be case insensitive, so U+0041
        // through 0+005A (A-Z) MUST be considered equivalent to U+0061 through U+007A
        // (a-z). The field contents can contain any UTF-8 character.
        let (name, content) = field
            .split_once('=')
            .expect("comment field must be seperated by '='");
        fields.push(FlacMetadataCommentField {
            name: name.to_string(),
            content: content.to_string(),
        });
    }

    (vendor, fields)
}

fn extract_flac_cus_sheet_metadata(data: &[u8]) -> FlacMetadataCueSheet {
    let mut pos = 0;

    // u(128*8)	Media catalog number in ASCII printable characters 0x20-0x7E.
    // If the media catalog number is less than 128 bytes long, it is right-padded with
    // 0x00 bytes. For CD-DA, this is a 13-digit number followed by 115 0x00 bytes.
    let catalog_number = String::from_utf8((&data[pos..pos + 128]).into())
        .expect("catalog number string must be UTF-8 and then some further restrictions")
        .trim_end_matches('\0')
        .into();
    // debug_assert!(catalog_number.is_ascii());

    pos += 128;

    // u(64)	Number of lead-in samples.
    // The number of lead-in samples has meaning only for CD-DA cuesheets; for other
    // uses, it should be 0. For CD-DA, the lead-in is the TRACK 00 area where the
    // table of contents is stored; more precisely, it is the number of samples from
    // the first sample of the media to the first sample of the first index point of
    // the first track. According to [IEC.60908.1999], the lead-in MUST be silent, and
    // CD grabbing software does not usually store it; additionally, the lead-in MUST
    // be at least two seconds but MAY be longer. For these reasons, the lead-in length
    // is stored here so that the absolute position of the first track can be computed.
    // Note that the lead-in stored here is the number of samples up to the first index
    // point of the first track, not necessarily to INDEX 01 of the first track; even
    // the first track MAY have INDEX 00 data.
    let lead_in_samples = u64::from_be_bytes((&data[pos..pos + 8]).try_into().unwrap());

    pos += 8;

    // u(1)	1 if the cuesheet corresponds to a CD-DA; else 0.
    let is_cdda = data[pos] >> 7 == 1;

    // u(7+258*8)	Reserved. All bits MUST be set to zero.
    let mut reserved = [00; 259];
    reserved.clone_from_slice(&data[pos..pos + 259]);
    reserved[0] &= 0b0111_1111; // ignore very first bit
    debug_assert!(reserved.iter().all(|val| *val == 0));

    pos += 259;

    // u(8)	Number of tracks in this cuesheet.
    // The number of tracks MUST be at least 1, as a cuesheet block MUST have a
    // lead-out track. For CD-DA, this number MUST be no more than 100 (99 regular
    // tracks and one lead-out track). The lead-out track is always the last track in
    // the cuesheet. For CD-DA, the lead-out track number MUST be 170 as specified by
    // [IEC.60908.1999]; otherwise, it MUST be 255.
    let track_count = data[pos];

    pos += 1;

    let mut tracks = vec![];

    // Cuesheet tracks	A number of structures as specified in Section 8.7.1 equal to the number of tracks specified previously.
    for _ in 0..track_count {
        // u(64)	Track offset of the first index point in samples, relative to the beginning of the FLAC audio stream.
        // Note that the track offset differs from the one in CD-DA, where the track's
        // offset in the table of contents (TOC) is that of the track's INDEX 01 even
        // if there is an INDEX 00. For CD-DA, the track offset MUST be evenly
        // divisible by 588 samples (588 samples = 44100 samples/s * 1/75 s).
        let offset = u64::from_be_bytes((&data[pos..pos + 8]).try_into().unwrap());

        pos += 8;

        // u(8)	Track number.
        // A track number of 0 is not allowed because the CD-DA specification reserves
        // this for the lead-in. For CD-DA, the number MUST be 1-99 or 170 for the
        // lead-out; for non-CD-DA, the track number MUST be 255 for the lead-out. It
        // is recommended to start with track 1 and increase sequentially. Track
        // numbers MUST be unique within a cuesheet.
        let number = data[pos];

        pos += 1;

        // u(12*8)	Track ISRC.
        // The track ISRC (International Standard Recording Code) is a 12-digit
        // alphanumeric code; see [ISRC-handbook]. A value of 12 ASCII 0x00 characters
        // MAY be used to denote the absence of an ISRC.
        let raw_isrc = &data[pos..pos + 12];

        let isrc = if raw_isrc == [0u8; 12] {
            None
        } else {
            // ISRC is alphanumeric, using digits (the ten Arabic numerals 0 - 9) and the 26 upper case letters
            // of the Roman alphabet.
            // Lower case letters are not strictly permitted by the specification though it is recommended that
            // systems map lower-case letters to their upper-case equivalents before validating or using
            // codes.
            debug!("raw isrc: {raw_isrc:02x?}");
            match String::from_utf8(raw_isrc.into()) {
                Ok(str) => {
                    // TODO validate that it is only alphanumeric
                    Some(str.to_ascii_uppercase())
                }
                Err(err) => {
                    error!("ISRC {raw_isrc:02x?} could not be converted to a string: {err}");
                    None
                }
            }
        };

        pos += 12;

        // u(1)	The track type: 0 for audio, 1 for non-audio. This corresponds to the CD-DA Q-channel control bit 3.
        let is_audio: bool = data[pos] >> 7 == 0;

        // u(1)	The pre-emphasis flag: 0 for no pre-emphasis, 1 for pre-emphasis. This corresponds to the CD-DA Q-channel control bit 5.
        let preemphasis_flag = data[pos] >> 6 & 1 == 1;

        // u(6+13*8)	Reserved. All bits MUST be set to zero.
        let mut reserved = [00; 14];
        reserved.clone_from_slice(&data[pos..pos + 14]);
        reserved[0] &= 0b0011_1111; // ignore first two bits
        debug_assert!(reserved.iter().all(|val| *val == 0));

        pos += 14;

        // u(8)	The number of track index points.
        // There MUST be at least one index point in every track in a cuesheet except
        // for the lead-out track, which MUST have zero. For CD-DA, the number of index
        // points MUST NOT be more than 100.
        let index_point_count = data[pos];

        pos += 1;

        let mut index_points = vec![];

        // Cuesheet track index points	For all tracks except the lead-out track, a number of structures as specified in Section 8.7.1.1 equal to the number of index points specified previously.
        for _ in 0..index_point_count {
            // u(64)	Offset in samples, relative to the track offset, of the index point.
            // For CD-DA, the track index point offset MUST be evenly divisible by 588
            // samples (588 samples = 44100 samples/s * 1/75 s). Note that the offset
            // is from the beginning of the track, not the beginning of the audio data.
            let offset = u64::from_be_bytes((&data[pos..pos + 8]).try_into().unwrap());

            pos += 8;

            // u(8)	The track index point number.
            // For CD-DA, a track index point number of 0 corresponds to the track
            // pre-gap. The first index point in a track MUST have a number of 0 or 1,
            // and subsequently, index point numbers MUST increase by 1. Index point
            // numbers MUST be unique within a track.
            let number = data[pos];

            pos += 1;

            // u(3*8)	Reserved. All bits MUST be set to zero.
            let reserved = &data[pos..pos + 3];
            debug_assert!(reserved.iter().all(|val| *val == 0));

            pos += 3;

            index_points.push(FlacMetadataCueSheetTrackIndexPoint { offset, number });
        }

        tracks.push(FlacMetadataCueSheetTrack {
            offset,
            number,
            isrc,
            is_audio,
            preemphasis_flag,
            index_points,
        });
    }

    FlacMetadataCueSheet {
        catalog_number,
        lead_in_samples,
        is_cdda,
        tracks,
    }
}

fn extract_flac_picture_metadata(data: &[u8]) -> std::result::Result<FlacMetadataPicture, String> {
    let mut pos = 0;

    // Table 12
    // Data	Description
    // u(32)	The picture type according to Table 13.
    let n = u32::from_be_bytes((&data[pos..pos + 4]).try_into().unwrap());
    let picture_type = FlacMetadataPictureType::from_int(n)?;

    pos += 4;

    // u(32)	The length of the media type string in bytes.
    let media_type_length = u32::from_be_bytes((&data[pos..pos + 4]).try_into().unwrap()) as usize;

    pos += 4;

    // u(n*8)	The media type string as specified by [RFC2046], or the text string --> to signify that the data part is a URI of the picture instead of the picture data itself. This field must be in printable ASCII characters 0x20-0x7E.
    let media_type = String::from_utf8((&data[pos..pos + media_type_length]).into())
        .expect("field string must be UTF-8 and then some further restrictions");
    if media_type == "-->" {
        warn!("picture is stored at URI");
    }
    // debug_assert!(media_type.is_ascii());

    pos += media_type_length;

    // u(32)	The length of the description string in bytes.
    let description_length = u32::from_be_bytes((&data[pos..pos + 4]).try_into().unwrap()) as usize;

    pos += 4;

    // u(n*8)	The description of the picture in UTF-8.
    let description = String::from_utf8((&data[pos..pos + description_length]).into())
        .expect("field string must be UTF-8");

    pos += description_length;

    // u(32)	The width of the picture in pixels.
    let width = u32::from_be_bytes((&data[pos..pos + 4]).try_into().unwrap());

    pos += 4;

    // u(32)	The height of the picture in pixels.
    let height = u32::from_be_bytes((&data[pos..pos + 4]).try_into().unwrap());

    pos += 4;

    // u(32)	The color depth of the picture in bits per pixel.
    let depth = u32::from_be_bytes((&data[pos..pos + 4]).try_into().unwrap());

    pos += 4;

    // u(32)	For indexed-color pictures (e.g., GIF), the number of colors used; 0 for non-indexed pictures.
    let colors = u32::from_be_bytes((&data[pos..pos + 4]).try_into().unwrap());

    pos += 4;

    // u(32)	The length of the picture data in bytes.
    let length = u32::from_be_bytes((&data[pos..pos + 4]).try_into().unwrap()) as usize;

    pos += 4;

    debug_assert_eq!(length, data.len() - pos);

    // u(n*8)	The binary picture data.
    let picture = &data[pos..pos + length];

    Ok(FlacMetadataPicture {
        picture_type,
        media_type,
        description,
        width,
        height,
        depth,
        colors,
        picture: picture.into(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::os::fd::AsRawFd;

    use socket2::SockAddrStorage;
    use x_diff_rs::diff::diff;
    use x_diff_rs::tree::XTree;

    use super::*;

    fn make_album(artist_name: &str, album_title: &str, release_date: &str) -> Album {
        let date = release_date.parse::<NaiveDate>().unwrap();
        Album {
            title: album_title.to_string(),
            // date: NaiveDate::from_ymd_opt(1996, 2, 12).expect("invalid or out-of-range date"),
            date: Some(date),
            tracks: vec![],
            cover: format!("Music/{artist_name}/{album_title}/cover.jpg"),
        }
    }

    fn make_track(
        artist_name: &str,
        album_title: &str,
        track_number: u8,
        track_title: &str,
    ) -> Track {
        Track {
            disc: 0,
            number: track_number,
            title: track_title.to_string(),
            file: format!("Music/{artist_name}/{album_title}/{track_number:02} {track_title}.flac")
                .replace(' ', "*20"),
            duration: NaiveTime::from_hms_milli_opt(0, 2, 18, 893).unwrap(),
            size: 18323574,
            bits_per_sample: 16,
            sample_frequency: 44100,
            channels: 2,
        }
    }

    fn generate_test_collection() -> Collection {
        let mut a1 = make_album("a<bc", "a1", "1996-02-12");
        a1.tracks = vec![
            make_track("a<bc", "a1", 1, "a11"),
            make_track("a<bc", "a1", 2, "a12"),
            make_track("a<bc", "a1", 3, "a13"),
            make_track("a<bc", "a1", 4, "a14"),
        ];
        let mut g1 = make_album("ghi", "g1", "1996-02-12");
        g1.tracks = vec![
            make_track("ghi", "g1", 1, "g<11"),
            make_track("ghi", "g1", 2, "g12"),
            make_track("ghi", "g1", 3, "g13"),
        ];
        let mut h2 = make_album("ghi", "h2", "2002-07-30");
        h2.tracks = vec![
            make_track("ghi", "h2", 1, "h21"),
            make_track("ghi", "h2", 2, "h22"),
            make_track("ghi", "h2", 3, "h23"),
            make_track("ghi", "h2", 4, "h24"),
        ];
        let mut i3 = make_album("ghi", "i3", "2011-11-11");
        i3.tracks = vec![
            make_track("ghi", "i3", 1, "i31"),
            make_track("ghi", "i3", 2, "i32"),
        ];
        let j1 = make_album("jk", "j1", "1980-01-01");
        let l1 = make_album("lm", "l1", "1982-02-02");
        let n1 = make_album("nop", "n1", "1984-04-01");
        let q1 = make_album("qrs", "q1", "1986-06-06");
        let t1 = make_album("tuv", "t1", "1988-08-08");
        let w1 = make_album("w", "w1", "1990-10-10");
        let x1 = make_album("xyz", "x1", "1992-12-12");

        Collection {
            system_update_id: 7, // fun number for testing
            base: PathBuf::from("./"),
            artists: vec![
                Artist {
                    name: "a<bc".to_string(),
                    albums: vec![a1],
                },
                Artist {
                    name: "def".to_string(),
                    albums: vec![make_album("def", "d<1", "2005-07-02")],
                },
                Artist {
                    name: "ghi".to_string(),
                    albums: vec![g1, h2, i3],
                },
                Artist {
                    name: "jk".to_string(),
                    albums: vec![j1],
                },
                Artist {
                    name: "lm".to_string(),
                    albums: vec![l1],
                },
                Artist {
                    name: "nop".to_string(),
                    albums: vec![n1],
                },
                Artist {
                    name: "qrs".to_string(),
                    albums: vec![q1],
                },
                Artist {
                    name: "tuv".to_string(),
                    albums: vec![t1],
                },
                Artist {
                    name: "w".to_string(),
                    albums: vec![w1],
                },
                Artist {
                    name: "xyz".to_string(),
                    albums: vec![x1],
                },
            ],
        }
    }

    #[test]
    fn test_handle_get_device() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = "GET /Device.xml HTTP/1.1\r\n";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.collect::<String>();

        // check a couple of bits of the body rather than hard coding the whole thing
        assert!(body.contains("<root xmlns=\"urn:schemas-upnp-org:device-1-0\" configId=\"1\">"));
        assert!(body.contains("<UDN>uuid:5c863963-f2a2-491e-8b60-079cdadad147</UDN>"));
    }

    #[test]
    fn test_handle_get_content_directory() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = "GET /ContentDirectory.xml HTTP/1.1\r\n";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.collect::<String>();

        // check a couple of bits of the body rather than hard coding the whole thing
        assert!(body.contains("<scpd xmlns=\"urn:schemas-upnp-org:service-1-0\">"));
        assert!(body.contains("<name>Browse</name>"));
    }

    fn generate_get_system_update_id_request() -> String {
        let soap_action_header =
            r#"Soapaction: "urn:schemas-upnp-org:service:ContentDirectory:1#GetSystemUpdateID""#;
        let body = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
        <u:GetSystemUpdateID xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1" />
    </s:Body>
</s:Envelope>"#;

        "POST /ContentDirectory/Control HTTP/1.1\r\n".to_string()
            + soap_action_header
            + "\r\n"
            + "Content-Type: text/xml; charset=utf-8\r\n"
            + "Content-Length: "
            + format!("{}", body.len()).as_str()
            + "\r\n"
            + "\r\n"
            + body
    }

    fn extract_get_system_update_id_response(body: &str) -> u16 {
        let envelope = Element::parse(body.as_bytes()).unwrap();
        let body = envelope.get_child("Body").unwrap();
        let get_system_update_id_response = body.get_child("GetSystemUpdateIDResponse").unwrap();

        let id: u16 = get_system_update_id_response
            .get_child("Id")
            .unwrap()
            .get_text()
            .unwrap()
            .parse()
            .unwrap();

        id
    }

    #[test]
    fn test_handle_get_system_update_id() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_get_system_update_id_request();
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let id = extract_get_system_update_id_response(&body);

        assert_eq!(id, 7);
    }

    fn generate_get_search_capabilities_request() -> String {
        let soap_action_header = r#"Soapaction: "urn:schemas-upnp-org:service:ContentDirectory:1#GetSearchCapabilities""#;
        let body = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
        <u:GetSearchCapabilities xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1" />
    </s:Body>
</s:Envelope>"#;

        "POST /ContentDirectory/Control HTTP/1.1\r\n".to_string()
            + soap_action_header
            + "\r\n"
            + "Content-Type: text/xml; charset=utf-8\r\n"
            + "Content-Length: "
            + format!("{}", body.len()).as_str()
            + "\r\n"
            + "\r\n"
            + body
    }

    fn extract_get_search_capabilities_response(body: &str) -> Option<String> {
        let envelope = Element::parse(body.as_bytes()).unwrap();
        let body = envelope.get_child("Body").unwrap();
        let get_search_capabilities_response =
            body.get_child("GetSearchCapabilitiesResponse").unwrap();

        let search_caps = get_search_capabilities_response
            .get_child("SearchCaps")
            .unwrap()
            .get_text();

        search_caps.map(|sort_caps| sort_caps.into())
    }

    #[test]
    fn test_handle_get_search_capabilities() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_get_search_capabilities_request();
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let id = extract_get_search_capabilities_response(&body);

        assert_eq!(id, None);
    }

    fn generate_get_sort_capabilities_request() -> String {
        let soap_action_header =
            r#"Soapaction: "urn:schemas-upnp-org:service:ContentDirectory:1#GetSortCapabilities""#;
        let body = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
        <u:GetSortCapabilities xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1" />
    </s:Body>
</s:Envelope>"#;

        "POST /ContentDirectory/Control HTTP/1.1\r\n".to_string()
            + soap_action_header
            + "\r\n"
            + "Content-Type: text/xml; charset=utf-8\r\n"
            + "Content-Length: "
            + format!("{}", body.len()).as_str()
            + "\r\n"
            + "\r\n"
            + body
    }

    fn extract_get_sort_capabilities_response(body: &str) -> Option<String> {
        let envelope = Element::parse(body.as_bytes()).unwrap();
        let body = envelope.get_child("Body").unwrap();
        let get_sort_capabilities_response = body.get_child("GetSortCapabilitiesResponse").unwrap();

        let sort_caps = get_sort_capabilities_response
            .get_child("SortCaps")
            .unwrap()
            .get_text();

        sort_caps.map(|sort_caps| sort_caps.into())
    }

    #[test]
    fn test_handle_get_sort_capabilities() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_get_sort_capabilities_request();
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let id = extract_get_sort_capabilities_response(&body);

        assert_eq!(id, None);
    }

    fn generate_browse_request(
        object_id: &str,
        starting_index: u16,
        requested_count: u16,
    ) -> String {
        let soap_action_header =
            r#"Soapaction: "urn:schemas-upnp-org:service:ContentDirectory:1#Browse""#;
        let body = format!(
            r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
        <u:Browse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
            <ObjectID>{object_id}</ObjectID>
            <BrowseFlag>BrowseDirectChildren</BrowseFlag>
            <Filter>*</Filter>
            <StartingIndex>{starting_index}</StartingIndex>
            <RequestedCount>{requested_count}</RequestedCount>
            <SortCriteria></SortCriteria>
        </u:Browse>
    </s:Body>
</s:Envelope>"#
        );

        "POST /ContentDirectory/Control HTTP/1.1\r\n".to_string()
            + soap_action_header
            + "\r\n"
            + "Content-Type: text/xml; charset=utf-8\r\n"
            + "Content-Length: "
            + format!("{}", body.len()).as_str()
            + "\r\n"
            + "\r\n"
            + &body
    }

    fn extract_browse_response(body: &str) -> (String, u16, u16, String) {
        debug!("about to parse {body}");
        let envelope = Element::parse(body.as_bytes()).unwrap();
        let body = envelope.get_child("Body").unwrap();
        let browse_response = body.get_child("BrowseResponse").unwrap();

        let result = browse_response
            .get_child("Result")
            .unwrap()
            .get_text()
            .unwrap();

        let number_returned: u16 = browse_response
            .get_child("NumberReturned")
            .unwrap()
            .get_text()
            .unwrap()
            .parse()
            .unwrap();

        let total_matches: u16 = browse_response
            .get_child("TotalMatches")
            .unwrap()
            .get_text()
            .unwrap()
            .parse()
            .unwrap();

        let update_id = browse_response
            .get_child("UpdateID")
            .unwrap()
            .get_text()
            .unwrap();

        (
            result.into(),
            number_returned,
            total_matches,
            update_id.into(),
        )
    }

    fn compare_xml(a: &str, b: &str) {
        let tree1 = XTree::parse(a).unwrap();
        let tree2 = XTree::parse(b).unwrap();
        let difference = diff(&tree1, &tree2);
        assert!(difference.is_empty(), "difference: {difference:#?}");
    }

    #[test]
    fn test_handle_browse_content_root() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0", 0, 500);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let (result, number_returned, total_matches, update_id) = extract_browse_response(&body);

        compare_xml(
            &result,
            r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
    <container id="0$albums" parentID="0" restricted="1" searchable="1">
        <dc:title>12 albums</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$items" parentID="0" restricted="1" searchable="1">
        <dc:title>13 items</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$playlists" parentID="0" restricted="1" searchable="1">
        <dc:title>0 playlists</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$=Artist" parentID="0" restricted="1" searchable="1">
        <dc:title>Artist</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$=Date" parentID="0" restricted="1" searchable="1">
        <dc:title>Date</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$=Genre" parentID="0" restricted="1" searchable="1">
        <dc:title>Genre</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$=All Artists" parentID="0" restricted="1" searchable="1">
        <dc:title>All Artists</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$=Composer" parentID="0" restricted="1" searchable="1">
        <dc:title>Composer</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$untagged" parentID="0" restricted="1" searchable="1">
        <dc:title>[untagged]</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$folders" parentID="0" restricted="1" searchable="1">
        <dc:title>[folder view]</dc:title>
        <upnp:class>object.container.storageFolder</upnp:class>
    </container>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 10);
        assert_eq!(total_matches, 10);
        assert_eq!(update_id, "25");
    }

    #[test]
    fn test_handle_browse_albums_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$albums", 0, 5);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let (result, number_returned, total_matches, update_id) = extract_browse_response(&body);

        // think about genre, composer, etc.
        compare_xml(
            &result,
            r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
    <container id="0$albums$*a0" parentID="0$albums" childCount="4" restricted="1" searchable="1">
        <dc:title>a1</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:artist>a&lt;bc</upnp:artist>
        <dc:creator>a&lt;bc</dc:creator>
        <upnp:artist role="AlbumArtist">a&lt;bc</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/a&lt;bc/a1/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$albums$*a1" parentID="0$albums" childCount="0" restricted="1" searchable="1">
        <dc:title>d&lt;1</dc:title>
        <dc:date>2005-07-02</dc:date>
        <upnp:artist>def</upnp:artist>
        <dc:creator>def</dc:creator>
        <upnp:artist role="AlbumArtist">def</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/def/d&lt;1/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$albums$*a2" parentID="0$albums" childCount="3" restricted="1" searchable="1">
        <dc:title>g1</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$albums$*a3" parentID="0$albums" childCount="4" restricted="1" searchable="1">
        <dc:title>h2</dc:title>
        <dc:date>2002-07-30</dc:date>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/h2/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$albums$*a4" parentID="0$albums" childCount="2" restricted="1" searchable="1">
        <dc:title>i3</dc:title>
        <dc:date>2011-11-11</dc:date>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/i3/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 5);
        assert_eq!(total_matches, 12);
        assert_eq!(update_id, "25");
    }

    #[test]
    fn test_handle_browse_an_album_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$albums$*a2", 0, 500);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let (result, number_returned, total_matches, update_id) = extract_browse_response(&body);

        // think about genre, composer, etc.
        compare_xml(
            &result,
            r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
    <item id="0$albums$*a2$*i1" parentID="0$albums$*a2" restricted="1">
        <dc:title>g&lt;11</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>1</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/01*20g&lt;11.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$albums$*a2$*i2" parentID="0$albums$*a2" restricted="1">
        <dc:title>g12</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>2</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/02*20g12.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$albums$*a2$*i3" parentID="0$albums$*a2" restricted="1">
        <dc:title>g13</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>3</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/03*20g13.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 3);
        assert_eq!(total_matches, 3);
        assert_eq!(update_id, "25");
    }

    #[test]
    fn test_handle_browse_artists_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist", 0, 5);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let (result, number_returned, total_matches, update_id) = extract_browse_response(&body);

        compare_xml(
            &result,
            r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
    <container id="0$=Artist$1" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>a&lt;bc</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=Artist$2" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>def</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=Artist$3" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>ghi</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=Artist$4" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>jk</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=Artist$5" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>lm</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 5);
        assert_eq!(total_matches, 10);
        assert_eq!(update_id, "25");
    }

    #[test]
    fn test_handle_browse_an_artist_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$3", 0, 500);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let (result, number_returned, total_matches, update_id) = extract_browse_response(&body);

        compare_xml(
            &result,
            r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
    <container id="0$=Artist$3$albums" parentID="0$=Artist$3" restricted="1" searchable="1">
        <dc:title>3 albums</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$=Artist$3$items" parentID="0$=Artist$3" restricted="1" searchable="1">
        <dc:title>9 items</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$=Artist$3$=Date" parentID="0$=Artist$3" restricted="1" searchable="1">
        <dc:title>Date</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 3);
        assert_eq!(total_matches, 3);
        assert_eq!(update_id, "25");
    }

    #[test]
    fn test_handle_browse_an_artist_albums_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$3$albums", 0, 500);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let (result, number_returned, total_matches, update_id) = extract_browse_response(&body);

        compare_xml(
            &result,
            r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
    <container id="0$=Artist$3$albums$1" parentID="0$=Artist$3$albums" childCount="3" restricted="1" searchable="1">
        <dc:title>g1</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$=Artist$3$albums$2" parentID="0$=Artist$3$albums" childCount="4" restricted="1" searchable="1">
        <dc:title>h2</dc:title>
        <dc:date>2002-07-30</dc:date>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/h2/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$=Artist$3$albums$3" parentID="0$=Artist$3$albums" childCount="2" restricted="1" searchable="1">
        <dc:title>i3</dc:title>
        <dc:date>2011-11-11</dc:date>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/i3/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 3);
        assert_eq!(total_matches, 3);
        assert_eq!(update_id, "25");
    }

    #[test]
    fn test_handle_browse_an_artist_album_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$3$albums$1", 0, 500);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let (result, number_returned, total_matches, update_id) = extract_browse_response(&body);

        compare_xml(
            &result,
            r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
    <item id="0$=Artist$3$albums$1$1" parentID="0$=Artist$3$albums$1" restricted="1">
        <dc:title>g&lt;11</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>1</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/01*20g&lt;11.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$=Artist$3$albums$1$2" parentID="0$=Artist$3$albums$1" restricted="1">
        <dc:title>g12</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>2</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/02*20g12.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$=Artist$3$albums$1$3" parentID="0$=Artist$3$albums$1" restricted="1">
        <dc:title>g13</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>3</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/03*20g13.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 3);
        assert_eq!(total_matches, 3);
        assert_eq!(update_id, "25");
    }

    #[test]
    fn test_handle_browse_all_artists_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=All Artists", 0, 5);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let (result, number_returned, total_matches, update_id) = extract_browse_response(&body);

        compare_xml(
            &result,
            r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
    <container id="0$=All Artists$1" parentID="0$=All Artists" restricted="1" searchable="1">
        <dc:title>a&lt;bc</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=All Artists$2" parentID="0$=All Artists" restricted="1" searchable="1">
        <dc:title>def</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=All Artists$3" parentID="0$=All Artists" restricted="1" searchable="1">
        <dc:title>ghi</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=All Artists$4" parentID="0$=All Artists" restricted="1" searchable="1">
        <dc:title>jk</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=All Artists$5" parentID="0$=All Artists" restricted="1" searchable="1">
        <dc:title>lm</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 5);
        assert_eq!(total_matches, 10);
        assert_eq!(update_id, "25");
    }

    #[test]
    fn test_request_cover() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = "GET /Content/src/cover.jpg HTTP/1.1\r\n\r\n";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let mut line = Vec::new();
        cursor.set_position(0);
        let mut prev = None;
        loop {
            let mut buf = [0u8; 1];
            cursor.read_exact(&mut buf).unwrap();
            if prev == Some(b'\r') && buf[0] == b'\n' {
                line.pop().unwrap(); // get rid of the \r
                break;
            }
            line.push(buf[0]);
            prev = Some(buf[0]);
        }

        assert_eq!(
            String::from_utf8(line).unwrap(),
            "HTTP/1.1 200 OK".to_string()
        );

        loop {
            let mut line = Vec::new();
            let mut prev = None;
            loop {
                let mut buf = [0u8; 1];
                cursor.read_exact(&mut buf).unwrap();
                if prev == Some(b'\r') && buf[0] == b'\n' {
                    line.pop().unwrap(); // get rid of the \r
                    break;
                }
                line.push(buf[0]);
                prev = Some(buf[0]);
            }
            if line.is_empty() {
                break;
            }
            // TODO check/use String::from_utf8(line).unwrap() ?
        }

        let mut body = Vec::new();
        cursor.read_to_end(&mut body).unwrap();

        // for now, can just check against the only image being returned

        // let mut decoder = Decoder::new(&body[..]);
        // let result = decoder.decode();
        // assert!(
        //     result.is_ok(),
        //     "failed to decode image: {}",
        //     result.err().unwrap()
        // );

        let want = include_bytes!("cover.jpg");
        assert_eq!(body.as_slice(), want);
    }

    #[test]
    fn test_request_song() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = "GET /Content/src/riff.flac HTTP/1.1\r\n\r\n";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let mut line = Vec::new();
        cursor.set_position(0);
        let mut prev = None;
        loop {
            let mut buf = [0u8; 1];
            cursor.read_exact(&mut buf).unwrap();
            if prev == Some(b'\r') && buf[0] == b'\n' {
                line.pop().unwrap(); // get rid of the \r
                break;
            }
            line.push(buf[0]);
            prev = Some(buf[0]);
        }

        assert_eq!(
            String::from_utf8(line).unwrap(),
            "HTTP/1.1 200 OK".to_string()
        );

        loop {
            let mut line = Vec::new();
            let mut prev = None;
            loop {
                let mut buf = [0u8; 1];
                cursor.read_exact(&mut buf).unwrap();
                if prev == Some(b'\r') && buf[0] == b'\n' {
                    line.pop().unwrap(); // get rid of the \r
                    break;
                }
                line.push(buf[0]);
                prev = Some(buf[0]);
            }
            if line.is_empty() {
                break;
            }
            // TODO check/use String::from_utf8(line).unwrap() ?
        }

        let mut body = Vec::new();
        cursor.read_to_end(&mut body).unwrap();

        // for now, can just check against the only song being returned
        let want = include_bytes!("riff.flac");
        assert_eq!(body.as_slice(), want);
    }

    #[test]
    fn test_handle_device_connection_with_bad_request_line() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = "";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(
            lines.next().unwrap(),
            "HTTP/1.1 500 Internal Server Error".to_string()
        );

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        compare_xml(
            &body,
            r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <s:Fault>
            <faultcode>s:Client</faultcode>
            <faultstring>UPnPError</faultstring>
            <detail>
                <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
                    <errorCode>401</errorCode>
                    <errorDescription>Missing Request</errorDescription>
                </UPnPError>
            </detail>
        </s:Fault>
    </s:Body>
</s:Envelope>"#,
        );
    }

    #[test]
    fn test_parse_search_criteria() {
        let input = "dc:title contains \"g\" and @refID exists false";
        let search_criteria = parse_search_criteria(input);
        assert_eq!(search_criteria, "g");
    }

    fn generate_search_request(
        search_str: &str,
        starting_index: u16,
        requested_count: u16,
    ) -> String {
        let soap_action_header =
            r#"Soapaction: "urn:schemas-upnp-org:service:ContentDirectory:1#Search""#;
        // TOOD assuming ContainerID is always 0?
        let body = format!(
            r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Body>
        <u:Search xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
            <ContainerID>0</ContainerID>
            <SearchCriteria>dc:title contains "{search_str}" and @refID exists false</SearchCriteria>
            <Filter>*</Filter>
            <StartingIndex>{starting_index}</StartingIndex>
            <RequestedCount>{requested_count}</RequestedCount>
            <SortCriteria></SortCriteria>
        </u:Search>
    </s:Body>
</s:Envelope>"#
        );

        "POST /ContentDirectory/Control HTTP/1.1\r\n".to_string()
            + soap_action_header
            + "\r\n"
            + "Content-Type: text/xml; charset=utf-8\r\n"
            + "Content-Length: "
            + format!("{}", body.len()).as_str()
            + "\r\n"
            + "\r\n"
            + &body
    }

    fn extract_search_response(body: &str) -> (String, u16, u16, String) {
        debug!("about to parse {body}");
        let envelope = Element::parse(body.as_bytes()).unwrap();
        let body = envelope.get_child("Body").unwrap();
        let search_response = body.get_child("SearchResponse").unwrap();

        let result = search_response
            .get_child("Result")
            .unwrap()
            .get_text()
            .unwrap();

        let number_returned: u16 = search_response
            .get_child("NumberReturned")
            .unwrap()
            .get_text()
            .unwrap()
            .parse()
            .unwrap();

        let total_matches: u16 = search_response
            .get_child("TotalMatches")
            .unwrap()
            .get_text()
            .unwrap()
            .parse()
            .unwrap();

        let update_id = search_response
            .get_child("UpdateID")
            .unwrap()
            .get_text()
            .unwrap();

        (
            result.into(),
            number_returned,
            total_matches,
            update_id.into(),
        )
    }

    #[test]
    fn test_handle_search() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_search_request("g", 0, 5);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            &collection,
            input.as_bytes(),
            &mut cursor,
        );

        let result = String::from_utf8(cursor.into_inner()).unwrap();
        let mut lines = result.lines();

        assert_eq!(lines.next().unwrap(), "HTTP/1.1 200 OK".to_string());

        // skip headers
        loop {
            let l = lines.next().unwrap();
            if l.is_empty() {
                break;
            }
        }

        let body = lines.map(|s| s.to_owned() + "\n").collect::<String>();

        let (result, number_returned, total_matches, update_id) = extract_search_response(&body);

        // what do i expect? maybe one artist (ghi), one album (g1), and three tracks (g<11, g12,
        // and g13)?
        compare_xml(
            &result,
            r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
    <container id="0$=Artist$3" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>ghi</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$albums$*a2" parentID="0$albums" restricted="1" searchable="1">
        <dc:title>g1</dc:title>
        <dc:creator>ghi</dc:creator>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <item id="0$albums$*a2$*i1" parentID="0$albums$*a2" restricted="1">
        <dc:title>g&lt;11</dc:title>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>1</upnp:originalTrackNumber>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/01*20g&lt;11.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$albums$*a2$*i2" parentID="0$albums$*a2" restricted="1">
        <dc:title>g12</dc:title>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>2</upnp:originalTrackNumber>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/02*20g12.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$albums$*a2$*i3" parentID="0$albums$*a2" restricted="1">
        <dc:title>g13</dc:title>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>3</upnp:originalTrackNumber>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/03*20g13.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 5);
        assert_eq!(total_matches, 5);
        assert_eq!(update_id, "25");
    }

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
    fn test_format_time_nice() {
        let time = NaiveTime::from_hms_milli_opt(0, 0, 5, 712).unwrap();
        assert_eq!(format_time_nice(time), "0:00:05.712");
    }

    #[test]
    fn test_is_flac() {
        let f = File::open("src/riff.flac").unwrap();
        let mut br = BufReader::new(f);
        assert!(is_flac(&mut br));

        let f = File::open("src/cover.jpg").unwrap();
        let mut br = BufReader::new(f);
        assert!(!is_flac(&mut br));
    }

    #[test]
    fn test_extract_flac_metadata() {
        let f = File::open("src/riff.flac").unwrap();
        let mut br = BufReader::new(f);
        let metadata = extract_flac_metadata(&mut br);

        assert_eq!(metadata.minimum_block_size, 4096);
        assert_eq!(metadata.maximum_block_size, 4096);
        assert_eq!(metadata.minimum_frame_size, 2465);
        assert_eq!(metadata.maximum_frame_size, 12367);
        assert_eq!(metadata.sample_rate, 48000);
        assert_eq!(metadata.channels, 2);
        assert_eq!(metadata.bits, 16);
        assert_eq!(metadata.total, 274176);
        assert_eq!(metadata.checksum, 0xebede16f6f0c2fc9259bc4724a78e101);
        assert_eq!(
            metadata.duration(),
            NaiveTime::from_hms_milli_opt(0, 0, 5, 712).unwrap()
        );

        assert_eq!(metadata.vendor, "reference libFLAC 1.5.0 20250211");
        assert_eq!(
            metadata.fields,
            vec![
                FlacMetadataCommentField {
                    name: "TITLE".to_string(),
                    content: "riff".to_string(),
                },
                FlacMetadataCommentField {
                    name: "ARTIST".to_string(),
                    content: "carl".to_string(),
                },
                FlacMetadataCommentField {
                    name: "ALBUMARTIST".to_string(),
                    content: "carl".to_string(),
                },
                FlacMetadataCommentField {
                    name: "ALBUM".to_string(),
                    content: "none".to_string(),
                },
                FlacMetadataCommentField {
                    name: "RELEASEDATE".to_string(),
                    content: "2025".to_string(),
                },
            ]
        );

        assert_eq!(
            metadata.seek_table,
            vec![
                FlacMetadataSeekPoint {
                    sample_number: 0,
                    offset: 0,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 20480,
                    offset: 34807,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 45056,
                    offset: 89597,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 69632,
                    offset: 145375,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 94208,
                    offset: 192402,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 118784,
                    offset: 239699,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 143360,
                    offset: 300422,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 167936,
                    offset: 361855,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 188416,
                    offset: 413037,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 212992,
                    offset: 462389,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 237568,
                    offset: 510317,
                    samples: 4096
                },
                FlacMetadataSeekPoint {
                    sample_number: 262144,
                    offset: 559113,
                    samples: 4096
                },
            ]
        );

        assert_eq!(
            metadata.picture,
            vec![FlacMetadataPicture {
                picture_type: FlacMetadataPictureType::FrontCover,
                media_type: "image/jpeg".to_string(),
                description: String::new(),
                width: 1024,
                height: 768,
                depth: 24,
                colors: 0,
                picture: include_bytes!("cover.jpg").into(),
            }]
        );

        assert_eq!(
            metadata.application,
            vec![FlacMetadataApplication {
                id: 0x41424344,
                data: "this is fake application stuff for testing.\0\0\0\0\0\0\0".into(),
            }]
        );

        assert_eq!(
            metadata.cue_sheet,
            Some(FlacMetadataCueSheet {
                catalog_number: "1234567890123".to_string(),
                lead_in_samples: 0,
                is_cdda: false,
                tracks: vec![
                    FlacMetadataCueSheetTrack {
                        offset: 0,
                        number: 1,
                        isrc: Some("AA6662500001".to_string()),
                        is_audio: true,
                        preemphasis_flag: false,
                        index_points: vec![FlacMetadataCueSheetTrackIndexPoint {
                            offset: 0,
                            number: 1,
                        },],
                    },
                    FlacMetadataCueSheetTrack {
                        offset: 274176,
                        number: 255,
                        isrc: None,
                        is_audio: true,
                        preemphasis_flag: false,
                        index_points: vec![],
                    }
                ],
            })
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
