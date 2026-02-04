mod advertise;
mod flac;
mod media_server;

extern crate socket2;

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
use log::{Level, debug, info, trace, warn};
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use stderrlog::Timestamp;
use uuid::Uuid;

use crate::advertise::SSDP_IPV4_MULTICAST_ADDRESS;
use crate::advertise::advertise_discovery_messages;
use crate::advertise::handle_search_error;
use crate::advertise::handle_search_message;
use crate::flac::extract_flac_metadata;
use crate::flac::is_flac;
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

#[cfg(test)]
mod tests {
    use super::*;

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
