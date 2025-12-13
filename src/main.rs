extern crate socket2;

use std::collections::HashMap;
use std::fs::File;
use std::fs::read_to_string;
use std::io::BufRead;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::io::Write;
use std::net::TcpListener;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

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

    let listener = TcpListener::bind("0.0.0.0:7878").unwrap();
    thread::spawn(move || {
        println!("listening on {}", listener.local_addr().unwrap());
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            let peer_addr = stream
                .peer_addr()
                .map_or_else(|_| "unknown".to_string(), |a| a.to_string());

            thread::spawn(move || {
                handle_device_connection(device_uuid, &peer_addr, &stream, &stream);
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

fn parse_soap_request(body: &str) -> Option<Vec<String>> {
    let mut object_id = None;
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
                        let starting_index = child.as_element().unwrap().get_text().unwrap();
                        if starting_index == "0" {
                            println!("start from zero. simple.");
                        } else {
                            println!("start from: {starting_index}. what's up");
                        }
                    }
                    "RequestedCount" => {
                        let requested_count = child.as_element().unwrap().get_text().unwrap();
                        println!("only want: {requested_count}. what's up");
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

    object_id
}

fn generate_browse_response(object_id: &[String]) -> (String, &'static str) {
    let browse_response = match object_id {
        [root] if root == "0" => {
            // TODO generate based on what i have?
            let response = "
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$albums&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;2093 albums&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$items&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;22366 items&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$playlists&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;706 playlists&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Artist&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Date&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Date&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Genre&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Genre&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=All Artists&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;All Artists&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Composer&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Composer&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$untagged&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;[untagged]&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$folders&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;[folder view]&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.storageFolder&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>10</NumberReturned>
            <TotalMatches>10</TotalMatches>
            <UpdateID>25</UpdateID>";
            Some(response.to_string())
        }
        [root, next] if root == "0" && next == "albums" => {
            // TODO generate based on what i have?
            let response = "
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$albums$*a0&quot; parentID=&quot;0$albums&quot; childCount=&quot;5&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;&amp;apos;74 Jailbreak&lt;/dc:title&gt;&lt;dc:date&gt;1984-10-15&lt;/dc:date&gt;&lt;upnp:artist&gt;AC/DC&lt;/upnp:artist&gt;&lt;dc:creator&gt;AC/DC&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;AC/DC&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/AC_DC/*2774*20Jailbreak/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$albums$*a1&quot; parentID=&quot;0$albums&quot; childCount=&quot;1&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;&amp;apos;Allelujah! Don&amp;apos;t Bend! Ascend!&lt;/dc:title&gt;&lt;dc:date&gt;2012-10-15&lt;/dc:date&gt;&lt;upnp:artist&gt;Godspeed You! Black Emperor&lt;/upnp:artist&gt;&lt;dc:creator&gt;Godspeed You! Black Emperor&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Godspeed You! Black Emperor&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Godspeed*20You!*20Black*20Emperor/*27Allelujah!*20Don*27t*20Bend!*20Ascend!/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$albums$*a2&quot; parentID=&quot;0$albums&quot; childCount=&quot;9&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;&amp;apos;Sno Angel Like You&lt;/dc:title&gt;&lt;upnp:genre&gt;Indie&lt;/upnp:genre&gt;&lt;dc:date&gt;2006-03-21&lt;/dc:date&gt;&lt;upnp:artist&gt;Howe Gelb&lt;/upnp:artist&gt;&lt;dc:creator&gt;Howe Gelb&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Howe Gelb&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Howe*20Gelb/*27Sno*20Angel*20Like*20You/02*20Paradise*20Here*20Abouts.mp3/$!picture-1938-34544.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$albums$*a3&quot; parentID=&quot;0$albums&quot; childCount=&quot;12&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;(VV:2) Venomous Villain&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:artist&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;MF Doom, D. Dumile, W. Pentz, A. Brooks, Di, ile, D., G. Jr. Valencia, I. Vasquetelle, G. Lamar Owens, W. Tolbert, L. McConnell, K. Thornton, M. Delaey, M. Delaney, L. Herron&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/01*20Viktor*20Vaughn*20-*20Viktormizer*20(intro).mp3/$!picture-2699-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$albums$*a4&quot; parentID=&quot;0$albums&quot; childCount=&quot;1&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;(What&amp;apos;s the Story) Morning Glory?&lt;/dc:title&gt;&lt;upnp:genre&gt;Rock&lt;/upnp:genre&gt;&lt;dc:date&gt;1995-01-01&lt;/dc:date&gt;&lt;upnp:artist&gt;Oasis&lt;/upnp:artist&gt;&lt;dc:creator&gt;Oasis&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Oasis&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;Noel Gallagher&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Oasis/(What*27s*20the*20Story)*20Morning*20Glory_/12*20Champagne*20Supernova.mp3/$!picture-636-65528.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>500</NumberReturned>
            <TotalMatches>2094</TotalMatches>
            <UpdateID>25</UpdateID>";
            Some(response.to_string())
        }
        [root, next, _album_id] if root == "0" && next == "albums" => {
            // TODO generate based on what i have?
            let response = "
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;item id=&quot;0$albums$*a3$*i20771&quot; parentID=&quot;0$albums$*a3&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Viktormizer (intro)&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:album&gt;(VV:2) Venomous Villain&lt;/upnp:album&gt;&lt;upnp:artist&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;MF Doom&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;1&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/01*20Viktor*20Vaughn*20-*20Viktormizer*20(intro).mp3/$!picture-2699-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:02:48.884&quot; size=&quot;6836179&quot; bitrate=&quot;40000&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/mpeg:DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/01*20Viktor*20Vaughn*20-*20Viktormizer*20(intro).mp3&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$albums$*a3$*i1635&quot; parentID=&quot;0$albums$*a3&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Back End&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:album&gt;(VV:2) Venomous Villain&lt;/upnp:album&gt;&lt;upnp:artist&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;MF Doom, D. Dumile, W. Pentz&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;2&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/02*20Viktor*20Vaughn*20-*20Back*20End.mp3/$!picture-2696-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:33.161&quot; size=&quot;8609049&quot; bitrate=&quot;40000&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/mpeg:DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/02*20Viktor*20Vaughn*20-*20Back*20End.mp3&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$albums$*a3$*i6218&quot; parentID=&quot;0$albums$*a3&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Fall Back / Titty Fat&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:album&gt;(VV:2) Venomous Villain&lt;/upnp:album&gt;&lt;upnp:artist&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;A. Brooks, D. Dumile, Di, ile, D., G. Jr. Valencia&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;3&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/03*20Viktor*20Vaughn*20-*20Fall*20Back*20_*20Titty*20Fat.mp3/$!picture-2743-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:33.762&quot; size=&quot;8633152&quot; bitrate=&quot;40000&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/mpeg:DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/03*20Viktor*20Vaughn*20-*20Fall*20Back*20_*20Titty*20Fat.mp3&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$albums$*a3$*i5207&quot; parentID=&quot;0$albums$*a3&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Doom on Vik&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:album&gt;(VV:2) Venomous Villain&lt;/upnp:album&gt;&lt;upnp:artist&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;MF Doom, D. Dumile, G. Jr. Valencia, I. Vasquetelle&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;4&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/04*20Viktor*20Vaughn*20-*20Doom*20on*20Vik.mp3/$!picture-2724-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:01:53.505&quot; size=&quot;4618805&quot; bitrate=&quot;40000&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/mpeg:DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/04*20Viktor*20Vaughn*20-*20Doom*20on*20Vik.mp3&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$albums$*a3$*i15037&quot; parentID=&quot;0$albums$*a3&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;R.A.P. G.A.M.E.&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:album&gt;(VV:2) Venomous Villain&lt;/upnp:album&gt;&lt;upnp:artist&gt;Viktor Vaughn feat. Manchild &amp;amp; Iz-Real&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn feat. Manchild &amp;amp; Iz-Real&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;MF Doom, G. Lamar Owens, I. Vasquetelle, W. Tolbert&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;5&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/05*20Viktor*20Vaughn*20feat.*20Manchild*20*26*20Iz-Real*20-*20R.A.P.*20G.A.M.E..mp3/$!picture-3014-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:04:20.208&quot; size=&quot;10493110&quot; bitrate=&quot;40000&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/mpeg:DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/05*20Viktor*20Vaughn*20feat.*20Manchild*20*26*20Iz-Real*20-*20R.A.P.*20G.A.M.E..mp3&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>5</NumberReturned>
            <TotalMatches>12</TotalMatches>
            <UpdateID>25</UpdateID>";
            Some(response.to_string())
        }
        [root, next] if root == "0" && next == "=Artist" => {
            // TODO generate based on what i have?
            let response = "
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$=Artist$10167&quot; parentID=&quot;0$=Artist&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;[package radio]&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$24015&quot; parentID=&quot;0$=Artist&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;1 Giant Leap&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$16832&quot; parentID=&quot;0$=Artist&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;1QA&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$1511&quot; parentID=&quot;0$=Artist&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;8 Foot Sativa&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$7&quot; parentID=&quot;0$=Artist&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Á Móti Sól&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>5</NumberReturned>
            <TotalMatches>864</TotalMatches>
            <UpdateID>25</UpdateID>";
            Some(response.to_string())
        }
        [root, next, _artist_id] if root == "0" && next == "=Artist" => {
            // TODO generate based on what i have?
            let response = "
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$=Artist$3187$albums&quot; parentID=&quot;0$=Artist$3187&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;3 albums&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$3187$items&quot; parentID=&quot;0$=Artist$3187&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;43 items&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$3187$=Date&quot; parentID=&quot;0$=Artist$3187&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Date&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>3</NumberReturned>
            <TotalMatches>3</TotalMatches>
            <UpdateID>25</UpdateID>";
            Some(response.to_string())
        }
        [root, next, _artist_id, _artist_what] if root == "0" && next == "=Artist" => {
            // TODO generate based on what i have?
            let response = "
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$=Artist$3187$albums$*a251&quot; parentID=&quot;0$=Artist$3187$albums&quot; childCount=&quot;14&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Amen&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$3187$albums$*a535&quot; parentID=&quot;0$=Artist$3187$albums&quot; childCount=&quot;15&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Death Before Musick&lt;/dc:title&gt;&lt;dc:date&gt;2004-04-05&lt;/dc:date&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Death*20Before*20Musick/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$3187$albums$*a2012&quot; parentID=&quot;0$=Artist$3187$albums&quot; childCount=&quot;14&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;We Have Come for Your Parents&lt;/dc:title&gt;&lt;dc:date&gt;2000-10-10&lt;/dc:date&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/We*20Have*20Come*20for*20Your*20Parents/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>3</NumberReturned>
            <TotalMatches>3</TotalMatches>
            <UpdateID>25</UpdateID>";
            Some(response.to_string())
        }
        [root, next, _artist_id, _artist_what, _artist_that]
            if root == "0" && next == "=Artist" =>
        {
            // TODO generate based on what i have?
            let response = "
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;item id=&quot;0$=Artist$3187$albums$*a251$*i3830&quot; parentID=&quot;0$=Artist$3187$albums$*a251&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Coma America&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:album&gt;Amen&lt;/upnp:album&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;1&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:02:18.893&quot; size=&quot;18323574&quot; bitsPerSample=&quot;16&quot; bitrate=&quot;176400&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/01*20Coma*20America.flac&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$=Artist$3187$albums$*a251$*i5260&quot; parentID=&quot;0$=Artist$3187$albums$*a251&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Down Human&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:album&gt;Amen&lt;/upnp:album&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;2&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:44.266&quot; size=&quot;30269257&quot; bitsPerSample=&quot;16&quot; bitrate=&quot;176400&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/02*20Down*20Human.flac&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$=Artist$3187$albums$*a251$*i5397&quot; parentID=&quot;0$=Artist$3187$albums$*a251&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Drive&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:album&gt;Amen&lt;/upnp:album&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;3&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:08.000&quot; size=&quot;25014468&quot; bitsPerSample=&quot;16&quot; bitrate=&quot;176400&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/03*20Drive.flac&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$=Artist$3187$albums$*a251$*i13217&quot; parentID=&quot;0$=Artist$3187$albums$*a251&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;No Cure for the Pure&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:album&gt;Amen&lt;/upnp:album&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;4&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:23.466&quot; size=&quot;25228115&quot; bitsPerSample=&quot;16&quot; bitrate=&quot;176400&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/04*20No*20Cure*20for*20the*20Pure.flac&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$=Artist$3187$albums$*a251$*i21351&quot; parentID=&quot;0$=Artist$3187$albums$*a251&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;When a Man Dies a Woman&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:album&gt;Amen&lt;/upnp:album&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;5&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:30.600&quot; size=&quot;28354574&quot; bitsPerSample=&quot;16&quot; bitrate=&quot;176400&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/05*20When*20a*20Man*20Dies*20a*20Woman.flac&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>5</NumberReturned>
            <TotalMatches>14</TotalMatches>
            <UpdateID>25</UpdateID>";
            Some(response.to_string())
        }
        [root, next] if root == "0" && next == "=All Artists" => {
            // TODO generate based on what i have?
            let response = "
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$=All Artists$18368&quot; parentID=&quot;0$=All Artists&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;&amp;amp;U&amp;amp;I&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=All Artists$19631&quot; parentID=&quot;0$=All Artists&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;(Damn) This Desert Air&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=All Artists$18913&quot; parentID=&quot;0$=All Artists&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;-(16)-&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=All Artists$20777&quot; parentID=&quot;0$=All Artists&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;? and the Mysterians&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=All Artists$7222&quot; parentID=&quot;0$=All Artists&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;[dialogue]&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>5</NumberReturned>
            <TotalMatches>3092</TotalMatches>
            <UpdateID>25</UpdateID>";
            Some(response.to_string())
        }
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
    peer_addr: &str,
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
                        let object_id = body.map_or_else(
                            || {
                                panic!("no body");
                            },
                            |body| parse_soap_request(&body),
                        );

                        object_id.map_or_else(
                            || {
                                panic!("no object id");
                            },
                            |object_id| generate_browse_response(&object_id),
                        )
                    } else {
                        println!("control: unexpected soap action: {soap_action}");
                        (String::new(), "400 BAD REQUEST")
                    }
                },
            )
        }
        _ => {
            println!("unknown request line: {request_line}");

            (String::new(), "404 NOT FOUND")
        }
    };
    let length = content.len();
    let status_line = format!("{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {result}");
    let response = format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{content}");
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

    use super::*;

    #[test]
    fn test_handle_get_device() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let peer_addr = "1.2.3.4";
        let input = "GET /Device.xml HTTP/1.1\r\n";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(test_device_uuid, peer_addr, input.as_bytes(), &mut cursor);

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
        let peer_addr = "1.2.3.4";
        let input = "GET /ContentDirectory.xml HTTP/1.1\r\n";
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(test_device_uuid, peer_addr, input.as_bytes(), &mut cursor);

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

    fn generate_browse_request(object_id: &str) -> String {
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
            <StartingIndex>0</StartingIndex>
            <RequestedCount>500</RequestedCount>
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

    #[test]
    fn test_handle_browse_content_root() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let peer_addr = "1.2.3.4";
        let input = generate_browse_request("0");
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(test_device_uuid, peer_addr, input.as_bytes(), &mut cursor);

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

        assert_eq!(
            body,
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$albums&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;2093 albums&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$items&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;22366 items&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$playlists&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;706 playlists&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Artist&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Date&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Date&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Genre&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Genre&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=All Artists&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;All Artists&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Composer&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Composer&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$untagged&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;[untagged]&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$folders&quot; parentID=&quot;0&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;[folder view]&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.storageFolder&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>10</NumberReturned>
            <TotalMatches>10</TotalMatches>
            <UpdateID>25</UpdateID>
        </u:BrowseResponse>
    </s:Body>
</s:Envelope>
"#
        );
    }

    #[test]
    fn test_handle_browse_albums_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let peer_addr = "1.2.3.4";
        let input = generate_browse_request("0$albums");
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(test_device_uuid, peer_addr, input.as_bytes(), &mut cursor);

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

        assert_eq!(
            body,
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$albums$*a0&quot; parentID=&quot;0$albums&quot; childCount=&quot;5&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;&amp;apos;74 Jailbreak&lt;/dc:title&gt;&lt;dc:date&gt;1984-10-15&lt;/dc:date&gt;&lt;upnp:artist&gt;AC/DC&lt;/upnp:artist&gt;&lt;dc:creator&gt;AC/DC&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;AC/DC&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/AC_DC/*2774*20Jailbreak/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$albums$*a1&quot; parentID=&quot;0$albums&quot; childCount=&quot;1&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;&amp;apos;Allelujah! Don&amp;apos;t Bend! Ascend!&lt;/dc:title&gt;&lt;dc:date&gt;2012-10-15&lt;/dc:date&gt;&lt;upnp:artist&gt;Godspeed You! Black Emperor&lt;/upnp:artist&gt;&lt;dc:creator&gt;Godspeed You! Black Emperor&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Godspeed You! Black Emperor&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Godspeed*20You!*20Black*20Emperor/*27Allelujah!*20Don*27t*20Bend!*20Ascend!/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$albums$*a2&quot; parentID=&quot;0$albums&quot; childCount=&quot;9&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;&amp;apos;Sno Angel Like You&lt;/dc:title&gt;&lt;upnp:genre&gt;Indie&lt;/upnp:genre&gt;&lt;dc:date&gt;2006-03-21&lt;/dc:date&gt;&lt;upnp:artist&gt;Howe Gelb&lt;/upnp:artist&gt;&lt;dc:creator&gt;Howe Gelb&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Howe Gelb&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Howe*20Gelb/*27Sno*20Angel*20Like*20You/02*20Paradise*20Here*20Abouts.mp3/$!picture-1938-34544.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$albums$*a3&quot; parentID=&quot;0$albums&quot; childCount=&quot;12&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;(VV:2) Venomous Villain&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:artist&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;MF Doom, D. Dumile, W. Pentz, A. Brooks, Di, ile, D., G. Jr. Valencia, I. Vasquetelle, G. Lamar Owens, W. Tolbert, L. McConnell, K. Thornton, M. Delaey, M. Delaney, L. Herron&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/01*20Viktor*20Vaughn*20-*20Viktormizer*20(intro).mp3/$!picture-2699-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$albums$*a4&quot; parentID=&quot;0$albums&quot; childCount=&quot;1&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;(What&amp;apos;s the Story) Morning Glory?&lt;/dc:title&gt;&lt;upnp:genre&gt;Rock&lt;/upnp:genre&gt;&lt;dc:date&gt;1995-01-01&lt;/dc:date&gt;&lt;upnp:artist&gt;Oasis&lt;/upnp:artist&gt;&lt;dc:creator&gt;Oasis&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Oasis&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;Noel Gallagher&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Oasis/(What*27s*20the*20Story)*20Morning*20Glory_/12*20Champagne*20Supernova.mp3/$!picture-636-65528.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>500</NumberReturned>
            <TotalMatches>2094</TotalMatches>
            <UpdateID>25</UpdateID>
        </u:BrowseResponse>
    </s:Body>
</s:Envelope>
"#
        );
    }

    #[test]
    fn test_handle_browse_an_album_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let peer_addr = "1.2.3.4";
        let input = generate_browse_request("0$albums$*a3");
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(test_device_uuid, peer_addr, input.as_bytes(), &mut cursor);

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

        assert_eq!(
            body,
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;item id=&quot;0$albums$*a3$*i20771&quot; parentID=&quot;0$albums$*a3&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Viktormizer (intro)&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:album&gt;(VV:2) Venomous Villain&lt;/upnp:album&gt;&lt;upnp:artist&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;MF Doom&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;1&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/01*20Viktor*20Vaughn*20-*20Viktormizer*20(intro).mp3/$!picture-2699-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:02:48.884&quot; size=&quot;6836179&quot; bitrate=&quot;40000&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/mpeg:DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/01*20Viktor*20Vaughn*20-*20Viktormizer*20(intro).mp3&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$albums$*a3$*i1635&quot; parentID=&quot;0$albums$*a3&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Back End&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:album&gt;(VV:2) Venomous Villain&lt;/upnp:album&gt;&lt;upnp:artist&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;MF Doom, D. Dumile, W. Pentz&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;2&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/02*20Viktor*20Vaughn*20-*20Back*20End.mp3/$!picture-2696-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:33.161&quot; size=&quot;8609049&quot; bitrate=&quot;40000&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/mpeg:DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/02*20Viktor*20Vaughn*20-*20Back*20End.mp3&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$albums$*a3$*i6218&quot; parentID=&quot;0$albums$*a3&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Fall Back / Titty Fat&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:album&gt;(VV:2) Venomous Villain&lt;/upnp:album&gt;&lt;upnp:artist&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;A. Brooks, D. Dumile, Di, ile, D., G. Jr. Valencia&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;3&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/03*20Viktor*20Vaughn*20-*20Fall*20Back*20_*20Titty*20Fat.mp3/$!picture-2743-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:33.762&quot; size=&quot;8633152&quot; bitrate=&quot;40000&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/mpeg:DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/03*20Viktor*20Vaughn*20-*20Fall*20Back*20_*20Titty*20Fat.mp3&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$albums$*a3$*i5207&quot; parentID=&quot;0$albums$*a3&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Doom on Vik&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:album&gt;(VV:2) Venomous Villain&lt;/upnp:album&gt;&lt;upnp:artist&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;MF Doom, D. Dumile, G. Jr. Valencia, I. Vasquetelle&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;4&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/04*20Viktor*20Vaughn*20-*20Doom*20on*20Vik.mp3/$!picture-2724-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:01:53.505&quot; size=&quot;4618805&quot; bitrate=&quot;40000&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/mpeg:DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/04*20Viktor*20Vaughn*20-*20Doom*20on*20Vik.mp3&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$albums$*a3$*i15037&quot; parentID=&quot;0$albums$*a3&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;R.A.P. G.A.M.E.&lt;/dc:title&gt;&lt;upnp:genre&gt;Hip Hop&lt;/upnp:genre&gt;&lt;dc:date&gt;2004-08-03&lt;/dc:date&gt;&lt;upnp:album&gt;(VV:2) Venomous Villain&lt;/upnp:album&gt;&lt;upnp:artist&gt;Viktor Vaughn feat. Manchild &amp;amp; Iz-Real&lt;/upnp:artist&gt;&lt;dc:creator&gt;Viktor Vaughn feat. Manchild &amp;amp; Iz-Real&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Viktor Vaughn&lt;/upnp:artist&gt;&lt;upnp:artist role=&quot;Composer&quot;&gt;MF Doom, G. Lamar Owens, I. Vasquetelle, W. Tolbert&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;5&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/05*20Viktor*20Vaughn*20feat.*20Manchild*20*26*20Iz-Real*20-*20R.A.P.*20G.A.M.E..mp3/$!picture-3014-70292.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:04:20.208&quot; size=&quot;10493110&quot; bitrate=&quot;40000&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/mpeg:DLNA.ORG_PN=MP3;DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Viktor*20Vaughn/(VV*3a2)*20Venomous*20Villain/05*20Viktor*20Vaughn*20feat.*20Manchild*20*26*20Iz-Real*20-*20R.A.P.*20G.A.M.E..mp3&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>5</NumberReturned>
            <TotalMatches>12</TotalMatches>
            <UpdateID>25</UpdateID>
        </u:BrowseResponse>
    </s:Body>
</s:Envelope>
"#
        );
    }

    #[test]
    fn test_handle_browse_artists_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let peer_addr = "1.2.3.4";
        let input = generate_browse_request("0$=Artist");
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(test_device_uuid, peer_addr, input.as_bytes(), &mut cursor);

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

        assert_eq!(
            body,
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$=Artist$10167&quot; parentID=&quot;0$=Artist&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;[package radio]&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$24015&quot; parentID=&quot;0$=Artist&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;1 Giant Leap&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$16832&quot; parentID=&quot;0$=Artist&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;1QA&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$1511&quot; parentID=&quot;0$=Artist&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;8 Foot Sativa&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$7&quot; parentID=&quot;0$=Artist&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Á Móti Sól&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>5</NumberReturned>
            <TotalMatches>864</TotalMatches>
            <UpdateID>25</UpdateID>
        </u:BrowseResponse>
    </s:Body>
</s:Envelope>
"#
        );
    }

    #[test]
    fn test_handle_browse_an_artist_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let peer_addr = "1.2.3.4";
        let input = generate_browse_request("0$=Artist$3187");
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(test_device_uuid, peer_addr, input.as_bytes(), &mut cursor);

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

        assert_eq!(
            body,
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$=Artist$3187$albums&quot; parentID=&quot;0$=Artist$3187&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;3 albums&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$3187$items&quot; parentID=&quot;0$=Artist$3187&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;43 items&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$3187$=Date&quot; parentID=&quot;0$=Artist$3187&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Date&lt;/dc:title&gt;&lt;upnp:class&gt;object.container&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>3</NumberReturned>
            <TotalMatches>3</TotalMatches>
            <UpdateID>25</UpdateID>
        </u:BrowseResponse>
    </s:Body>
</s:Envelope>
"#
        );
    }

    #[test]
    fn test_handle_browse_an_artist_albums_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let peer_addr = "1.2.3.4";
        let input = generate_browse_request("0$=Artist$3187$albums");
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(test_device_uuid, peer_addr, input.as_bytes(), &mut cursor);

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

        assert_eq!(
            body,
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$=Artist$3187$albums$*a251&quot; parentID=&quot;0$=Artist$3187$albums&quot; childCount=&quot;14&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Amen&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$3187$albums$*a535&quot; parentID=&quot;0$=Artist$3187$albums&quot; childCount=&quot;15&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;Death Before Musick&lt;/dc:title&gt;&lt;dc:date&gt;2004-04-05&lt;/dc:date&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Death*20Before*20Musick/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=Artist$3187$albums$*a2012&quot; parentID=&quot;0$=Artist$3187$albums&quot; childCount=&quot;14&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;We Have Come for Your Parents&lt;/dc:title&gt;&lt;dc:date&gt;2000-10-10&lt;/dc:date&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/We*20Have*20Come*20for*20Your*20Parents/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;upnp:class&gt;object.container.album.musicAlbum&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>3</NumberReturned>
            <TotalMatches>3</TotalMatches>
            <UpdateID>25</UpdateID>
        </u:BrowseResponse>
    </s:Body>
</s:Envelope>
"#
        );
    }

    #[test]
    fn test_handle_browse_an_artist_album_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let peer_addr = "1.2.3.4";
        let input = generate_browse_request("0$=Artist$3187$albums$*a251");
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(test_device_uuid, peer_addr, input.as_bytes(), &mut cursor);

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

        assert_eq!(
            body,
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;item id=&quot;0$=Artist$3187$albums$*a251$*i3830&quot; parentID=&quot;0$=Artist$3187$albums$*a251&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Coma America&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:album&gt;Amen&lt;/upnp:album&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;1&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:02:18.893&quot; size=&quot;18323574&quot; bitsPerSample=&quot;16&quot; bitrate=&quot;176400&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/01*20Coma*20America.flac&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$=Artist$3187$albums$*a251$*i5260&quot; parentID=&quot;0$=Artist$3187$albums$*a251&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Down Human&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:album&gt;Amen&lt;/upnp:album&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;2&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:44.266&quot; size=&quot;30269257&quot; bitsPerSample=&quot;16&quot; bitrate=&quot;176400&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/02*20Down*20Human.flac&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$=Artist$3187$albums$*a251$*i5397&quot; parentID=&quot;0$=Artist$3187$albums$*a251&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;Drive&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:album&gt;Amen&lt;/upnp:album&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;3&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:08.000&quot; size=&quot;25014468&quot; bitsPerSample=&quot;16&quot; bitrate=&quot;176400&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/03*20Drive.flac&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$=Artist$3187$albums$*a251$*i13217&quot; parentID=&quot;0$=Artist$3187$albums$*a251&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;No Cure for the Pure&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:album&gt;Amen&lt;/upnp:album&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;4&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:23.466&quot; size=&quot;25228115&quot; bitsPerSample=&quot;16&quot; bitrate=&quot;176400&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/04*20No*20Cure*20for*20the*20Pure.flac&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;item id=&quot;0$=Artist$3187$albums$*a251$*i21351&quot; parentID=&quot;0$=Artist$3187$albums$*a251&quot; restricted=&quot;1&quot;&gt;&lt;dc:title&gt;When a Man Dies a Woman&lt;/dc:title&gt;&lt;dc:date&gt;1999-09-21&lt;/dc:date&gt;&lt;upnp:album&gt;Amen&lt;/upnp:album&gt;&lt;upnp:artist&gt;Amen&lt;/upnp:artist&gt;&lt;dc:creator&gt;Amen&lt;/dc:creator&gt;&lt;upnp:artist role=&quot;AlbumArtist&quot;&gt;Amen&lt;/upnp:artist&gt;&lt;upnp:originalTrackNumber&gt;5&lt;/upnp:originalTrackNumber&gt;&lt;upnp:albumArtURI dlna:profileID=&quot;JPEG_MED&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/cover.jpg&lt;/upnp:albumArtURI&gt;&lt;res duration=&quot;0:03:30.600&quot; size=&quot;28354574&quot; bitsPerSample=&quot;16&quot; bitrate=&quot;176400&quot; sampleFrequency=&quot;44100&quot; nrAudioChannels=&quot;2&quot; protocolInfo=&quot;http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000&quot;&gt;http://192.168.1.2:9790/minimserver/*/Music/Amen/Amen/05*20When*20a*20Man*20Dies*20a*20Woman.flac&lt;/res&gt;&lt;upnp:class&gt;object.item.audioItem.musicTrack&lt;/upnp:class&gt;&lt;/item&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>5</NumberReturned>
            <TotalMatches>14</TotalMatches>
            <UpdateID>25</UpdateID>
        </u:BrowseResponse>
    </s:Body>
</s:Envelope>
"#
        );
    }

    #[test]
    fn test_handle_browse_all_artists_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let peer_addr = "1.2.3.4";
        let input = generate_browse_request("0$=All Artists");
        let output = Vec::new();
        let mut cursor = Cursor::new(output);

        handle_device_connection(test_device_uuid, peer_addr, input.as_bytes(), &mut cursor);

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

        assert_eq!(
            body,
            r#"<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
        <u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
            <Result>&lt;DIDL-Lite xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&quot; xmlns:dc=&quot;http://purl.org/dc/elements/1.1/&quot; xmlns:upnp=&quot;urn:schemas-upnp-org:metadata-1-0/upnp/&quot; xmlns:dlna=&quot;urn:schemas-dlna-org:metadata-1-0/&quot;&gt;
&lt;container id=&quot;0$=All Artists$18368&quot; parentID=&quot;0$=All Artists&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;&amp;amp;U&amp;amp;I&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=All Artists$19631&quot; parentID=&quot;0$=All Artists&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;(Damn) This Desert Air&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=All Artists$18913&quot; parentID=&quot;0$=All Artists&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;-(16)-&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=All Artists$20777&quot; parentID=&quot;0$=All Artists&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;? and the Mysterians&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;container id=&quot;0$=All Artists$7222&quot; parentID=&quot;0$=All Artists&quot; restricted=&quot;1&quot; searchable=&quot;1&quot;&gt;&lt;dc:title&gt;[dialogue]&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.person.musicArtist&lt;/upnp:class&gt;&lt;/container&gt;&lt;/DIDL-Lite&gt;</Result>
            <NumberReturned>5</NumberReturned>
            <TotalMatches>3092</TotalMatches>
            <UpdateID>25</UpdateID>
        </u:BrowseResponse>
    </s:Body>
</s:Envelope>
"#
        );
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
