extern crate socket2;

use std::collections::HashMap;
use std::fmt::Write;
use std::fs;
use std::fs::File;
use std::fs::read_to_string;
use std::io::BufRead;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::io::Write as _;
use std::net::TcpListener;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::NaiveDate;
use chrono::Utc;
use rand::Rng;
use rand::rngs::ThreadRng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
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

#[derive(Clone, Debug)]
struct Artist {
    name: String,
    albums: Vec<Album>,
}

#[derive(Clone, Debug)]
struct Album {
    title: String,
    date: NaiveDate,
    tracks: Vec<Track>,
    cover: String,
}

#[derive(Clone, Debug)]
struct Track {
    number: u8,
    title: String,
    file: String,
}

#[derive(Clone, Debug)]
struct Collection {
    artists: Vec<Artist>,
}

fn populate_collection(location: &str) -> Collection {
    let mut collection = Collection { artists: vec![] };

    // naively assume folder structure is great!
    let artist_dirs = fs::read_dir(location).expect("no Music folder location in home directory");
    for path in artist_dirs.flatten() {
        if !path.file_type().unwrap().is_dir() {
            println!("non-directory found, ignoring: {}", path.path().display());
            continue;
        }

        let artist_name = path.file_name().into_string().unwrap();
        let mut artist = Artist {
            name: artist_name.clone(),
            albums: vec![],
        };

        let album_dirs = fs::read_dir(path.path()).unwrap();
        for path in album_dirs.flatten() {
            if !path.file_type().unwrap().is_dir() {
                println!("non-directory found, ignoring: {}", path.path().display());
                continue;
            }

            let album_title = path.file_name().into_string().unwrap();
            let mut album = Album {
                title: album_title.clone(),
                date: Utc::now().naive_utc().date(), // placeholder
                tracks: vec![],
                cover: String::new(),
            };

            let album_files = fs::read_dir(path.path()).unwrap();
            for path in album_files.flatten() {
                if !path.file_type().unwrap().is_file() {
                    println!("non-file found, ignoring: {}", path.path().display());
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
                        println!("skipping no extesion {file_name}");
                        continue;
                    }
                };

                match ext.to_lowercase().as_str() {
                    "flac" | "m4a" | "m4p" | "mp3" | "ogg" | "wav" | "wma" => {
                        let track = Track {
                            number: 0,
                            title: file_name,
                            file: path.path().display().to_string(),
                        };
                        album.tracks.push(track);
                    }
                    "m4v" | "mpeg" => {
                        println!("skipping video file {file_name}");
                    }
                    "m3u" => {
                        println!("skipping playlist {file_name}");
                    }
                    "gif" | "jpg" | "jpeg" | "png" => {
                        // TODO find cover
                    }
                    _ => {
                        println!("skipping unknown extension {file_name}");
                    }
                }
            }

            artist.albums.push(album);
        }

        collection.artists.push(artist);
    }

    collection
}
fn main() -> Result<()> {
    let mut rng = rand::rng();

    // TODO this file should probably be somewhere appropriate
    let device_uuid = match read_to_string(DEVICEID_FILE) {
        Ok(contents) => match Uuid::parse_str(&contents) {
            Ok(device_uuid) => device_uuid,
            Err(e) => {
                panic!("invalid device ID {contents}: {e}");
            }
        },
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                // let device_uuid = Uuid::now_v6();
                let device_uuid = Uuid::new_v4();
                let mut file = File::create(DEVICEID_FILE)?;
                file.write_all(device_uuid.to_string().as_bytes())?;
                device_uuid
            } else {
                panic!("could not read device id: {e}");
            }
        }
    };

    let collection = populate_collection("../../Music/");

    let listener = TcpListener::bind("0.0.0.0:7878").unwrap();
    thread::spawn(move || {
        println!("listening on {}", listener.local_addr().unwrap());
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            let addr = format!("http://{}/Content", stream.local_addr().unwrap());
            let peer_addr = stream
                .peer_addr()
                .map_or_else(|_| "unknown".to_string(), |a| a.to_string());
            let collection = collection.clone(); // TODO i don't want to clone this.

            thread::spawn(move || {
                handle_device_connection(
                    device_uuid,
                    &addr,
                    &peer_addr,
                    &collection,
                    &stream,
                    &stream,
                );
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
                let mut socket = ReallySocketToMe::new(socket.try_clone().unwrap());
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
                        println!("error handling search message: {err}");
                    }
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {} // keep waiting
            Err(err) => return Err(err),
        }
    }

    // TODO
    // When a device is removed from the network, it should, if possible, multicast a number of
    // discovery messages revoking its earlier announcements, effectively declaring that its root
    // devices, embedded devices and services will no longer be available.
}

fn parse_some_request_line(buf_reader: &mut BufReader<impl Read>, peer_addr: &str) -> String {
    let mut line: String = String::with_capacity(100);
    match buf_reader.read_line(&mut line) {
        Ok(size) => {
            if size == 0 {
                println!("empty request from {peer_addr}");
                return String::new(); // TODO error
            }
            line.strip_suffix("\r\n").map_or_else(
                || {
                    println!("warning: expected CRLF terminated request line: {line:#?}");
                    line.clone()
                },
                ToString::to_string,
            )
        }
        Err(e) => {
            println!("error reading request line: {e}");
            String::new() // TODO error
        }
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
                        println!("warning: expected CRLF terminated header: {line:#?}");
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
                println!("error reading header: {e}");
                break;
            }
        }
    }

    http_request_headers
}

fn get_content_length(request_line: &str, http_request_headers: &HashMap<String, String>) -> usize {
    http_request_headers.get("Content-Length").map_or_else(
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
            println!("could not ready body: {e}");
        }

        Some(String::from_utf8(buf).expect("body is not UTF8"))
    } else {
        None
    }
}

fn parse_soap_request(body: &str) -> (Option<Vec<String>>, Option<u16>, Option<u16>) {
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
                            println!("direct children. simple.");
                        } else {
                            println!("browse flag: {browse_flag}. what's up");
                        }
                    }
                    "Filter" => {
                        let filter = child.as_element().unwrap().get_text().unwrap();
                        if filter == "*" {
                            println!("no filter. simple.");
                        } else {
                            println!("some filter: {filter}. what's up");
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
                            println!("sort criteria: {sort_criteria}. what's up");
                        } else {
                            println!("no sort criteria. do i just make this up?");
                        }
                    }
                    anything => println!("what is {anything:?}"),
                }
            }
        }
        None => panic!("no Browse child"),
    }

    (object_id, starting_index, requested_count)
}

fn generate_browse_root_response(collection: &Collection) -> String {
    let album_count = collection
        .artists
        .iter()
        .map(|artist| artist.albums.len())
        .sum::<usize>();
    let albums = format!(
        r#"<container id="0$albums" parentID="0" restricted="1" searchable="1"><dc:title>{album_count} albums</dc:title><upnp:class>object.container</upnp:class></container>"#
    );
    let items_count = collection
        .artists
        .iter()
        .map(|artist| {
            artist
                .albums
                .iter()
                .map(|album| album.tracks.len())
                .sum::<usize>()
        })
        .sum::<usize>();
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
    let total_matches = collection
        .artists
        .iter()
        .map(|artist| artist.albums.len())
        .sum::<usize>();
    let starting_index = starting_index.unwrap().into();
    let requested_count: usize = requested_count.unwrap().into();
    let mut number_returned = 0;
    let mut result = String::new();
    let mut some_id = 0;
    let mut skipped = 0;
    'artists: for artist in &collection.artists {
        // move on quickly if we're not up to the starting index
        if skipped + artist.albums.len() <= starting_index {
            skipped += artist.albums.len();
            continue;
        }
        // let artist_name = &artist.name;
        let artist_name = xml::escape::escape_str_attribute(&artist.name);
        for album in artist
            .albums
            .iter()
            .skip(starting_index - skipped)
            .take(requested_count - number_returned)
        {
            number_returned += 1;
            let album_title = xml::escape::escape_str_attribute(&album.title);
            let date = album.date.to_string();
            let track_count = album.tracks.len();
            let cover = format!("{}/{}", addr, album.cover);
            let cover = xml::escape::escape_str_attribute(&cover);
            write!(
                result,
                r#"<container id="0$albums$*a{some_id}" parentID="0$albums" childCount="{track_count}" restricted="1" searchable="1"><dc:title>{album_title}</dc:title><dc:date>{date}</dc:date><upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist><upnp:albumArtURI dlna:profileID="JPEG_MED">{cover}</upnp:albumArtURI><upnp:class>object.container.album.musicAlbum</upnp:class></container>"#,
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
    'artists: for artist in &collection.artists {
        for album in &artist.albums {
            if format!("*a{}", some_id + 1) == album_id {
                found = Some((artist, album));
                break 'artists;
            }
            some_id += 1;
        }
    }
    let (artist, album) = found.unwrap_or_else(|| panic!("album {album_id} not found"));
    let total_matches = album.tracks.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let artist_name = xml::escape::escape_str_attribute(&artist.name);
    let album_title = &album.title;
    let date = album.date.to_string();
    let cover = format!("{}/{}", addr, album.cover);
    let cover = xml::escape::escape_str_attribute(&cover);
    let mut result = String::new();
    for (i, track) in album
        .tracks
        .iter()
        .skip(starting_index)
        .take(requested_count)
        .enumerate()
    {
        number_returned += 1;
        let id = starting_index + i + 1; // WTF
        let track_title = xml::escape::escape_str_attribute(&track.title);
        let track_number = track.number;
        let file = format!("{}/{}", addr, track.file);
        let file = xml::escape::escape_str_attribute(&file);
        write!(
            result,
            r#"<item id="0$albums${album_id}$*i{id}" parentID="0$albums${album_id}" restricted="1"><dc:title>{track_title}</dc:title><dc:date>{date}</dc:date><upnp:album>{album_title}</upnp:album><upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist><upnp:originalTrackNumber>{track_number}</upnp:originalTrackNumber><upnp:albumArtURI dlna:profileID="JPEG_MED">{cover}</upnp:albumArtURI><res duration="0:02:18.893" size="18323574" bitsPerSample="16" bitrate="176400" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">{file}</res><upnp:class>object.item.audioItem.musicTrack</upnp:class></item>"#,
        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    format_response(&result, number_returned, total_matches)
}

fn generate_browse_artists_response(
    collection: &Collection,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
) -> String {
    let total_matches = collection.artists.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let mut result = String::new();
    for (i, artist) in collection
        .artists
        .iter()
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
        .artists
        .get(artist_id.parse::<usize>().unwrap() - 1)
        .unwrap();
    let mut number_returned = 0;
    let mut result = String::new();

    for thing in things.iter().skip(starting_index).take(requested_count) {
        number_returned += 1;
        let (sub_id, title) = match *thing {
            "albums" => {
                let sub_id = (*thing).to_string();
                let albums = artist.albums.len();
                let title = format!("{albums} albums");
                (sub_id, title)
            }
            "items" => {
                let sub_id = (*thing).to_string();
                let items = artist
                    .albums
                    .iter()
                    .map(|album| album.tracks.len())
                    .sum::<usize>();
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
        .artists
        .get(artist_id.parse::<usize>().unwrap() - 1)
        .unwrap();
    let total_matches = artist.albums.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let artist_name = xml::escape::escape_str_attribute(&artist.name);
    let mut result = String::new();
    for (i, album) in artist
        .albums
        .iter()
        .skip(starting_index)
        .take(requested_count)
        .enumerate()
    {
        number_returned += 1;
        let id = starting_index + i + 1; // WTF
        let title = xml::escape::escape_str_attribute(&album.title);
        let date = album.date.to_string();
        let track_count = album.tracks.len();
        let cover = format!("{}/{}", addr, album.cover);
        let cover = xml::escape::escape_str_attribute(&cover);
        write!(
            result,
            r#"<container id="0$=Artist${artist_id}$albums${id}" parentID="0$=Artist${artist_id}$albums" childCount="{track_count}" restricted="1" searchable="1"><dc:title>{title}</dc:title><dc:date>{date}</dc:date><upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist><upnp:albumArtURI dlna:profileID="JPEG_MED">{cover}</upnp:albumArtURI><upnp:class>object.container.album.musicAlbum</upnp:class></container>"#,
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
        .artists
        .get(artist_id.parse::<usize>().unwrap() - 1)
        .unwrap();
    let album = artist
        .albums
        .get(album_id.parse::<usize>().unwrap() - 1)
        .unwrap();
    let total_matches = album.tracks.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let artist_name = xml::escape::escape_str_attribute(&artist.name);
    let album_title = xml::escape::escape_str_attribute(&album.title);
    let date = album.date.to_string();
    let cover = format!("{}/{}", addr, album.cover);
    let cover = xml::escape::escape_str_attribute(&cover);
    let mut result = String::new();
    for (i, track) in album
        .tracks
        .iter()
        .skip(starting_index)
        .take(requested_count)
        .enumerate()
    {
        number_returned += 1;
        let id = starting_index + i + 1; // WTF
        let track_title = xml::escape::escape_str_attribute(&track.title);
        let track_number = track.number;
        let file = format!("{}/{}", addr, track.file);
        let file = xml::escape::escape_str_attribute(&file);
        write!(
            result,
            r#"<item id="0$=Artist${artist_id}$albums${album_id}${id}" parentID="0$=Artist${artist_id}$albums${album_id}" restricted="1"><dc:title>{track_title}</dc:title><dc:date>{date}</dc:date><upnp:album>{album_title}</upnp:album><upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist><upnp:originalTrackNumber>{track_number}</upnp:originalTrackNumber><upnp:albumArtURI dlna:profileID="JPEG_MED">{cover}</upnp:albumArtURI><res duration="0:02:18.893" size="18323574" bitsPerSample="16" bitrate="176400" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">{file}</res><upnp:class>object.item.audioItem.musicTrack</upnp:class></item>"#,
        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    format_response(&result, number_returned, total_matches)
}

fn generate_browse_all_artists_response(
    collection: &Collection,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
) -> String {
    let total_matches = collection.artists.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let mut result = String::new();
    for (i, artist) in collection
        .artists
        .iter()
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
                println!("control: unexpected object ID: {object_id:?}");
                None
            }
        };
    browse_response.map_or_else(|| (String::new(), "400 BAD REQUEST"), |browse_response| {
        let body = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">{browse_response}
        </u:BrowseResponse>
    </s:Body>
</s:Envelope>"#
        );
        (body, HTTP_RESPONSE_OK)
    })
}

fn handle_device_connection(
    device_uuid: Uuid,
    addr: &str,
    peer_addr: &str,
    collection: &Collection,
    input_stream: impl std::io::Read,
    mut output_stream: impl std::io::Write,
) {
    let mut buf_reader = BufReader::new(input_stream);

    let request_line = parse_some_request_line(&mut buf_reader, peer_addr);
    println!("Request: {request_line}");

    let http_request_headers = parse_some_headers(&mut buf_reader);
    println!("  headers: {http_request_headers:#?}");

    let content_length = get_content_length(&request_line, &http_request_headers);
    println!("content length: {content_length}");

    let body = parse_body(content_length, &mut buf_reader);

    let body = body.map(|body| {
        println!("  body: {body}");
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
            http_request_headers.get("Soapaction").map_or_else(
                || {
                    println!("control: no soap action");
                    (String::new(), "400 BAD REQUEST")
                },
                |soap_action| {
                    if soap_action == "\"urn:schemas-upnp-org:service:ContentDirectory:1#Browse\"" {
                        let (object_id, starting_index, requested_count) = body.map_or_else(
                            || {
                                panic!("no body");
                            },
                            |body| parse_soap_request(&body),
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
                    } else {
                        println!("control: unexpected soap action: {soap_action}");
                        (String::new(), "400 BAD REQUEST")
                    }
                },
            )
        }
        something if something.starts_with("GET /Content/") => {
            let content = if something.contains("cover.jpg") {
                Some(("image/jpeg", &include_bytes!("cover.jpg")[..]))
            } else if something.contains(".flac") {
                Some(("audio/flac", &include_bytes!("riff.flac")[..]))
            } else {
                println!("unsupported /Content request for {something}");

                None
            };

            if let Some((content_type, content)) = content {
                let length = content.len();
                let status_line =
                    format!("{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {HTTP_RESPONSE_OK}");
                let response_headers = format!(
                    "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {length}\r\n\r\n"
                );
                let response = [response_headers.as_bytes(), content].concat();
                if let Err(err) = output_stream.write_all(&response[..]) {
                    println!("error writing response: {err}");
                }
                return;
            }

            (
                format!("unsupported /Content request for {something}"),
                "501 NOT IMPLEMENTED",
            )
        }
        _ => {
            println!("unknown request line: {request_line}");

            (String::new(), "404 NOT FOUND")
        }
    };
    let length = content.len();
    let status_line = format!("{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {result}");
    let response = format!(
        "{status_line}\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: {length}\r\n\r\n{content}"
    );
    if let Err(err) = output_stream.write_all(response.as_bytes()) {
        println!("error writing response: {err}");
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
    // To advertise its capabilities, a device multicasts a number of discovery messages. Specifically,
    // a root device shall multicast:

    // Three discovery messages for the root device.

    let nt = "upnp:rootdevice";
    let usn = format!("uuid:{device_uuid}::upnp:rootdevice");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\n{HTTP_HEADER_HOST}: {SSDP_IPV4_MULTICAST_ADDRESS}\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_NT}: {nt}\r\n{HTTP_HEADER_NTS}: {NTS_ALIVE}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    if let Err(err) = socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr)) {
        println!("error sending advertisement: {err}");
    }

    let nt = format!("uuid:{device_uuid}");
    let usn = format!("uuid:{device_uuid}");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\n{HTTP_HEADER_HOST}: {SSDP_IPV4_MULTICAST_ADDRESS}\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_NT}: {nt}\r\n{HTTP_HEADER_NTS}: {NTS_ALIVE}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    if let Err(err) = socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr)) {
        println!("error sending advertisement: {err}");
    }

    let device_type = "MediaServer";
    let ver = 1;
    let nt = format!("urn:schemas-upnp-org:device:{device_type}:{ver}");
    let usn = format!("uuid:{device_uuid}::urn:schemas-upnp-org:device:{device_type}:{ver}");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\n{HTTP_HEADER_HOST}: {SSDP_IPV4_MULTICAST_ADDRESS}\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_NT}: {nt}\r\n{HTTP_HEADER_NTS}: {NTS_ALIVE}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    if let Err(err) = socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr)) {
        println!("error sending advertisement: {err}");
    }

    // - Two discovery messages for each embedded device - I don't have any embedded devices

    // - Once for each service type in each device.

    let service_type = "ContentDirectory";
    let ver = 1;
    let nt = format!("urn:schemas-upnp-org:service:{service_type}:{ver}");
    let usn = format!("uuid:{device_uuid}::urn:schemas-upnp-org:service:{service_type}:{ver}");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\n{HTTP_HEADER_HOST}: {SSDP_IPV4_MULTICAST_ADDRESS}\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_NT}: {nt}\r\n{HTTP_HEADER_NTS}: {NTS_ALIVE}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    if let Err(err) = socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr)) {
        println!("error sending advertisement: {err}");
    }

    // TODO ConnectionManager service
    // let service_type = "ConnectionManager";
    // let ver = 1;
    // let nt = format!("urn:schemas-upnp-org:service:{service_type}:{ver}");
    // let usn = format!("uuid:{device_uuid}::urn:schemas-upnp-org:service:{service_type}:{ver}");
    // let advertisement = format!(
    //     "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\n{HTTP_HEADER_HOST}: {SSDP_IPV4_MULTICAST_ADDRESS}\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_NT}: {nt}\r\n{HTTP_HEADER_NTS}: {NTS_ALIVE}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
    //     max_age.as_secs()
    // );
    // if let Err(err) = socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr)) {
    //     println!("error sending advertisement: {err}");
    // }

    // TODO above messages should be resent periodically
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
        println!("unicast search");
        let unicast = host.parse::<SocketAddr>().unwrap();
        println!("  - {}:{}", unicast.ip(), unicast.port());
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
    println!("send {usn}");
    if let Err(err) = socket.send_to(advertisement.as_bytes(), src) {
        println!("error sending advertisement: {err}");
    }
}

#[derive(Debug)]
enum HandleSearchMessageError {
    InvalidSSDPMessage(String),
    UnhandledRequestLine(String),
    NoIPv4(Box<SockAddr>),
    MissingHostHeader,
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
        HTTP_METHOD_NOTIFY => {
            // println!(
            //     "notify from {:?}: {ssdp_message:?}",
            //     src.as_socket_ipv4().unwrap().ip()
            // );
            Err(HandleSearchMessageError::MethodNotSupported(
                HTTP_METHOD_NOTIFY.to_string(),
            ))
        }
        HTTP_METHOD_SEARCH => {
            let cp_ip = src
                .as_socket_ipv4()
                .ok_or_else(|| HandleSearchMessageError::NoIPv4(Box::new(src.clone())))?;
            println!("search from {:?}: {ssdp_message:?}", cp_ip.ip());

            // expect like:
            // M-SEARCH * HTTP/1.1
            // HOST: 239.255.255.250:1900
            // MAN: "ssdp:discover"
            // MX: seconds to delay response
            // ST: search target
            // USER-AGENT: OS/version UPnP/2.0 product/version
            // CPFN.UPNP.ORG: friendly name of the control point
            // CPUUID.UPNP.ORG: uuid of the control point

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
            let st = extract_st(&ssdp_message)?;

            // TODO ConnectionManager service
            if st == "ssdp:all"
                || st == "upnp:rootdevice"
                || st == format!("uuid:{device_uuid}").as_str()
                || st == "urn:schemas-upnp-org:device:MediaServer:1"
                || st == "urn:schemas-upnp-org:service:ContentDirectory:1"
            // || st == "urn:schemas-upnp-org:service:ConnectionManager:1"
            {
                println!("ok search target: {st}");
            } else if st.starts_with(format!("uuid:{device_uuid}").as_str()) {
                println!("unexpected search target format: {st}");
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

            if st == "ssdp:all" || st == "upnp:rootdevice" {
                let st = "upnp:rootdevice";
                let usn = format!("uuid:{device_uuid}::upnp:rootdevice");
                let advertisement =
                    generate_advertisement(&response_date, sys_info, st, &usn, location, max_age);
                send_advertisement(&usn, &advertisement, socket, src);
            }

            if st == "ssdp:all" || st == format!("uuid:{device_uuid}").as_str() {
                let st = format!("uuid:{device_uuid}");
                let usn = format!("uuid:{device_uuid}");
                let advertisement =
                    generate_advertisement(&response_date, sys_info, &st, &usn, location, max_age);
                send_advertisement(&usn, &advertisement, socket, src);
            }

            if st == "ssdp:all" || st == "urn:schemas-upnp-org:device:MediaServer:1" {
                let st = "urn:schemas-upnp-org:device:MediaServer:1";
                let usn = format!("uuid:{device_uuid}::{st}");
                let advertisement =
                    generate_advertisement(&response_date, sys_info, st, &usn, location, max_age);
                send_advertisement(&usn, &advertisement, socket, src);
            }

            if st == "ssdp:all" || st == "urn:schemas-upnp-org:service:ContentDirectory:1" {
                let st = "urn:schemas-upnp-org:service:ContentDirectory:1";
                let usn = format!("uuid:{device_uuid}::{st}");
                let advertisement =
                    generate_advertisement(&response_date, sys_info, st, &usn, location, max_age);
                send_advertisement(&usn, &advertisement, socket, src);
            }

            // TODO ConnectionManager service
            // if st == "ssdp:all"
            //     || st == "urn:schemas-upnp-org:service:ConnectionManager:1"
            // {
            //     let st = "urn:schemas-upnp-org:service:ConnectionManager:1";
            //     let usn = format!("uuid:{device_uuid}::{st}");
            //     let advertisement = format!(
            //         "{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {HTTP_RESPONSE_OK}\r\n{HTTP_HEADER_DATE}: {response_date}\r\n{HTTP_HEADER_EXT}:\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_ST}: {st}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
            //         max_age.as_secs()
            //     );
            //     println!("send {usn}");
            //     if let Err(err) = socket.send_to(advertisement.as_bytes(), &src)
            //     {
            //         println!("error sending advertisement: {err}");
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
            date,
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
            number: track_number,
            title: track_title.to_string(),
            file: format!("Music/{artist_name}/{album_title}/{track_number:02} {track_title}.flac")
                .replace(' ', "*20"),
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = "GET /Device.xml HTTP/1.1\r\n";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = "GET /ContentDirectory.xml HTTP/1.1\r\n";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
        println!("about to parse {body}");
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = generate_browse_request("0", 0, 500);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$albums", 0, 5);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$albums$*a3", 0, 500);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
    <item id="0$albums$*a3$*i1" parentID="0$albums$*a3" restricted="1">
        <dc:title>g&lt;11</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>1</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" bitrate="176400" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/01*20g&lt;11.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$albums$*a3$*i2" parentID="0$albums$*a3" restricted="1">
        <dc:title>g12</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>2</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" bitrate="176400" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/02*20g12.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$albums$*a3$*i3" parentID="0$albums$*a3" restricted="1">
        <dc:title>g13</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>3</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" bitrate="176400" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/03*20g13.flac</res>
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist", 0, 5);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$3", 0, 500);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$3$albums", 0, 500);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$3$albums$1", 0, 500);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" bitrate="176400" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/01*20g&lt;11.flac</res>
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
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" bitrate="176400" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/02*20g12.flac</res>
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
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" bitrate="176400" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/03*20g13.flac</res>
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=All Artists", 0, 5);
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = "GET /Content/something/cover.jpg HTTP/1.1\r\n\r\n";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
        let peer_addr = "1.2.3.4";
        let collection = generate_test_collection();
        let input = "GET /Content/something/06*20big*20noise.flac HTTP/1.1\r\n\r\n";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(
            test_device_uuid,
            addr,
            peer_addr,
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
}
