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

    advertise_discovery_messages(
        device_uuid,
        boot_id,
        &os_version,
        location,
        max_age,
        addr,
        &socket,
    );

    loop {
        let mut buffer = Vec::with_capacity(1024);
        match socket.recv_from(buffer.spare_capacity_mut()) {
            Ok((received, src)) => {
                unsafe {
                    buffer.set_len(received);
                }

                let os_version = os_version.clone();
                let socket = socket.try_clone().unwrap();
                thread::spawn(move || {
                    let mut rng = rand::rng();

                    handle_search_message(
                        device_uuid,
                        boot_id,
                        &os_version,
                        location,
                        max_age,
                        &mut rng,
                        &buffer,
                        &src,
                        &socket,
                    );
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

fn handle_device_connection(
    device_uuid: Uuid,
    peer_addr: &str,
    input_stream: impl std::io::Read,
    mut output_stream: impl std::io::Write,
) {
    let mut buf_reader = BufReader::new(input_stream);

    let mut line: String = String::with_capacity(100);
    let request_line = match buf_reader.read_line(&mut line) {
        Ok(size) => {
            if size == 0 {
                println!("empty request from {peer_addr}");
                return;
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
            return;
        }
    };

    println!("Request: {request_line}");

    // TODO probably should be case-insensitive for header names
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

    println!("  headers: {http_request_headers:#?}");

    // get content-length from the headers. if none and a GET request then assume zero. otherwise i don't know.
    let content_length: usize = http_request_headers.get("Content-Length").map_or_else(
        || {
            if request_line.starts_with("GET ") {
                // assume no body
                0
            } else {
                panic!("no content length");
            }
        },
        |content_length| content_length.parse().unwrap(),
    );
    println!("content length: {content_length}");

    let body = if content_length > 0 {
        let mut buf = vec![0; content_length];
        if let Err(e) = buf_reader.read_exact(&mut buf) {
            println!("could not ready body: {e}");
        }

        Some(String::from_utf8(buf).expect("body is not UTF8"))
    } else {
        None
    };

    if let Some(body) = body {
        println!("  body: {body}");
    }

    let (content, result) = match &request_line[..] {
        "GET /Device.xml HTTP/1.1" => {
            let content = format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0" configId="1">
    <specVersion>
        <major>1</major>
        <minor>0</minor>
    </specVersion>
    <device>
        <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
        <UDN>uuid:{device_uuid}</UDN>
        <friendlyName>strumur</friendlyName>
        <serviceList>
            <!--service>
                <serviceType>urn:schemas-upnp-org:service:ConnectionManager:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:ConnectionManager</serviceId>
                <SCPDURL>/ConnectionManager.xml</SCPDURL>
                <eventSubURL>/ConnectionManager/Event</eventSubURL>
                <controlURL>/ConnectionManager/Control</controlURL>
            </service-->
            <service>
                <serviceType>urn:schemas-upnp-org:service:ContentDirectory:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:ContentDirectory</serviceId>
                <SCPDURL>/ContentDirectory.xml</SCPDURL>
                <eventSubURL>/ContentDirectory/Event</eventSubURL>
                <controlURL>/ContentDirectory/Control</controlURL>
            </service>
        </serviceList>
        <presentationURL>/</presentationURL>
    </device>
</root>"#
            );

            (content, HTTP_RESPONSE_OK)
        }
        "GET /ConnectionManager.xml HTTP/1.1" => {
            unimplemented!("GET /ConnectionManager.xml not implemented");
        }
        "GET /ContentDirectory.xml HTTP/1.1" => {
            let content = include_str!("ContentDirectory.xml");

            (content.to_string(), HTTP_RESPONSE_OK)
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
    device_uuid: Uuid,
    boot_id: u64,
    os_version: &str,
    location: &str,
    max_age: Duration,
    addr: SocketAddr,
    socket: &Socket,
) {
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

fn handle_search_message(
    device_uuid: Uuid,
    boot_id: u64,
    os_version: &str,
    location: &str,
    max_age: Duration,
    rng: &mut ThreadRng,
    data: &[u8],
    src: &SockAddr,
    socket: &Socket,
) {
    // When a new control point is added to the network, it is allowed to multicast a discovery
    // message searching for interesting devices, services, or both.
    // All devices shall listen to the standard multicast address for these messages and shall
    // respond if any of their root devices, embedded devices or services matches the search criteria
    // in the discovery message.
    // All devices shall listen to incoming unicast search messages on port 1900 or, if provided, the
    // port number specified in the SEARCHPORT.UPNP.ORG header field and shall respond if any
    // of their root devices, embedded devices or services matches the search criteria in the
    // discovery message.
    match parse_ssdp_message(data) {
        Ok(ssdp_message) => {
            if ssdp_message.request_line
                == format!("{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {HTTP_RESPONSE_OK}")
            {
                println!("what do i do with {ssdp_message:#?}");
                return;
            }
            let (method, _request_target, _protocol) =
                parse_request_line(&ssdp_message.request_line).unwrap();
            match method.as_str() {
                HTTP_METHOD_NOTIFY => {
                    // println!(
                    //     "notify from {:?}: {ssdp_message:?}",
                    //     src.as_socket_ipv4().unwrap().ip()
                    // );
                }
                HTTP_METHOD_SEARCH => {
                    let Some(cp_ip) = src.as_socket_ipv4() else {
                        println!("{src:?} is not an IPv4 source");
                        return;
                    };
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
                    let host_key = ssdp_message
                        .headers
                        .keys()
                        .find(|k| k.eq_ignore_ascii_case("HOST"));
                    let Some(host_key) = host_key else {
                        println!("missing HOST header, ignoring");
                        return;
                    };
                    let host = ssdp_message.headers.get(host_key).unwrap();
                    let multicast = if host == SSDP_IPV4_MULTICAST_ADDRESS {
                        true
                    } else {
                        println!("unicast search");
                        let unicast = host.parse::<SocketAddr>().unwrap();
                        println!("  - {}:{}", unicast.ip(), unicast.port());
                        false
                    };

                    // if multicast and contains TCPPORT.UPNP.ORG header then TODO
                    if multicast && ssdp_message.headers.contains_key("TCPPORT.UPNP.ORG") {
                        unimplemented!("TCPPORT.UPNP.ORG handling not implemented");
                    }

                    // For multicast M-SEARCH requests, if the search request does not contain an MX header field,
                    // the device shall silently discard and ignore the search request. If the MX header field specifies
                    // a field value greater than 5, the device should assume that it contained the value 5 or less.
                    let mx = if multicast {
                        let mx_key = ssdp_message
                            .headers
                            .keys()
                            .find(|k| k.eq_ignore_ascii_case("MX"));
                        if let Some(mx_key) = mx_key {
                            let mx = ssdp_message.headers.get(mx_key).unwrap();
                            let mx = mx.parse::<u64>().unwrap();
                            Some(if mx > 5 { 5 } else { mx })
                        } else {
                            println!("multicast search missing MX header, ignoring");
                            return;
                        }
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
                    let st_key = ssdp_message
                        .headers
                        .keys()
                        .find(|k| k.eq_ignore_ascii_case("ST"));
                    let Some(st_key) = st_key else {
                        println!("missing ST header");
                        return;
                    };
                    let Some(st) = ssdp_message.headers.get(st_key) else {
                        println!("error getting {st_key} header");
                        return;
                    };

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
                        println!("unintended search target reciptient: {st}");
                        return;
                    } else {
                        println!("unknown search target {st}");
                        return;
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
                        let advertisement = format!(
                            "{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {HTTP_RESPONSE_OK}\r\n{HTTP_HEADER_DATE}: {response_date}\r\n{HTTP_HEADER_EXT}:\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_ST}: {st}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
                            max_age.as_secs()
                        );
                        println!("send {usn}");
                        if let Err(err) = socket.send_to(advertisement.as_bytes(), src) {
                            println!("error sending advertisement: {err}");
                        }
                    }

                    if st == "ssdp:all" || st == format!("uuid:{device_uuid}").as_str() {
                        let st = format!("uuid:{device_uuid}");
                        let usn = format!("uuid:{device_uuid}");
                        let advertisement = format!(
                            "{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {HTTP_RESPONSE_OK}\r\n{HTTP_HEADER_DATE}: {response_date}\r\n{HTTP_HEADER_EXT}:\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_ST}: {st}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
                            max_age.as_secs()
                        );
                        println!("send {usn}");
                        if let Err(err) = socket.send_to(advertisement.as_bytes(), src) {
                            println!("error sending advertisement: {err}");
                        }
                    }

                    if st == "ssdp:all" || st == "urn:schemas-upnp-org:device:MediaServer:1" {
                        let st = "urn:schemas-upnp-org:device:MediaServer:1";
                        let usn = format!("uuid:{device_uuid}::{st}");
                        let advertisement = format!(
                            "{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {HTTP_RESPONSE_OK}\r\n{HTTP_HEADER_DATE}: {response_date}\r\n{HTTP_HEADER_EXT}:\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_ST}: {st}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
                            max_age.as_secs()
                        );
                        println!("send {usn}");
                        if let Err(err) = socket.send_to(advertisement.as_bytes(), src) {
                            println!("error sending advertisement: {err}");
                        }
                    }

                    if st == "ssdp:all" || st == "urn:schemas-upnp-org:service:ContentDirectory:1" {
                        let st = "urn:schemas-upnp-org:service:ContentDirectory:1";
                        let usn = format!("uuid:{device_uuid}::{st}");
                        let advertisement = format!(
                            "{HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION} {HTTP_RESPONSE_OK}\r\n{HTTP_HEADER_DATE}: {response_date}\r\n{HTTP_HEADER_EXT}:\r\n{HTTP_HEADER_BOOTID}: {boot_id}\r\n{HTTP_HEADER_CONFIGID}: 1\r\n{HTTP_HEADER_SERVER}: {os_version} {UPNP_VERSION} {NAME}/{VERSION}\r\n{HTTP_HEADER_ST}: {st}\r\n{HTTP_HEADER_USN}: {usn}\r\n{HTTP_HEADER_LOCATION}: {location}\r\n{HTTP_HEADER_CACHE_CONTROL}: max-age={}\r\n\r\n",
                            max_age.as_secs()
                        );
                        println!("send {usn}");
                        if let Err(err) = socket.send_to(advertisement.as_bytes(), src) {
                            println!("error sending advertisement: {err}");
                        }
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
                }
                _ => println!("something else: {}", ssdp_message.request_line),
            }
        }
        Err(err) => {
            println!("failed to parse ssdp message: {err}");
        }
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
}
