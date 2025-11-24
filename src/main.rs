extern crate socket2;

use std::collections::HashMap;
use std::io::BufRead;
use std::io::BufReader;
use std::io::ErrorKind;
use std::io::Result;
use std::io::Write;
use std::net::TcpListener;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::Utc;
use rand::Rng;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use uuid::Uuid;

const SSDP_IPV4_MULTICAST_ADDRESS: &str = "239.255.255.250:1900";

const HTTP_PROTOCOL_NAME: &str = "HTTP";

const HTTP_PROTOCOL_VERSION: &str = "1.1";

const HTTP_MATCH_ANY_RESOURCE: &str = "*";

const HTTP_HEADER_SEP: &str = ":";

const HTTP_METHOD_NOTIFY: &str = "NOTIFY";

const HTTP_METHOD_SEARCH: &str = "M-SEARCH";

fn main() -> Result<()> {
    let mut rng = rand::rng();
    let listener = TcpListener::bind("0.0.0.0:7878").unwrap();
    thread::spawn(move || {
        println!("listening on {}", listener.local_addr().unwrap());
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();

            let buf_reader = BufReader::new(&stream);
            let http_request = buf_reader
                .lines()
                .map(|result| result.unwrap())
                .take_while(|line| !line.is_empty())
                .collect::<Vec<_>>();

            println!("Request: {http_request:#?}");

            let status_line = "HTTP/1.1 200 OK";
            // TODO what is this content?
            let content = r#"<?xml version="1.0" encoding="utf-8"?><root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><device></device></root>"#;
            let length = content.len();

            let response = format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{content}");

            stream.write_all(response.as_bytes()).unwrap();
        }
    });

    // let device_uuid = Uuid::now_v6();
    let device_uuid = Uuid::new_v4(); // TODO only do this once then store

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

    let location = "http://192.168.1.34:7878/"; // TODO get this IP address properly
    let max_age = Duration::from_secs(1800);

    let info = os_info::get();

    let os_version = format!("{}/{}", info.os_type(), info.version());

    // A convenient mechanism is to set this field value to the time that the device sends
    // its initial announcement, expressed as seconds elapsed since midnight January 1, 1970.
    let boot_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // To advertise its capabilities, a device multicasts a number of discovery messages. Specifically,
    // a root device shall multicast:

    // Three discovery messages for the root device.

    let nt = "upnp:rootdevice";
    let usn = format!("uuid:{device_uuid}::upnp:rootdevice");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\nHOST: {SSDP_IPV4_MULTICAST_ADDRESS}\r\nBOOTID.UPNP.ORG: {boot_id}\r\nCONFIGID.UPNP.ORG: 1\r\nSERVER: {os_version} UPnP/2.0 strumur/0.1.0\r\nNT: {nt}\r\nNTS: ssdp:alive\r\nUSN: {usn}\r\nLOCATION: {location}\r\nCACHE-CONTROL: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr))?;

    let nt = format!("uuid:{device_uuid}");
    let usn = format!("uuid:{device_uuid}");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\nHOST: {SSDP_IPV4_MULTICAST_ADDRESS}\r\nBOOTID.UPNP.ORG: {boot_id}\r\nCONFIGID.UPNP.ORG: 1\r\nSERVER: {os_version} UPnP/2.0 strumur/0.1.0\r\nNT: {nt}\r\nNTS: ssdp:alive\r\nUSN: {usn}\r\nLOCATION: {location}\r\nCACHE-CONTROL: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr))?;

    let device_type = "MediaServer";
    let ver = 1;
    let nt = format!("urn:schemas-upnp-org:device:{device_type}:{ver}");
    let usn = format!("uuid:{device_uuid}::urn:schemas-upnp-org:device:{device_type}:{ver}");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\nHOST: {SSDP_IPV4_MULTICAST_ADDRESS}\r\nBOOTID.UPNP.ORG: {boot_id}\r\nCONFIGID.UPNP.ORG: 1\r\nSERVER: {os_version} UPnP/2.0 strumur/0.1.0\r\nNT: {nt}\r\nNTS: ssdp:alive\r\nUSN: {usn}\r\nLOCATION: {location}\r\nCACHE-CONTROL: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr))?;

    // - Two discovery messages for each embedded device - I don't have any embedded devices

    // - Once for each service type in each device.

    let service_type = "ContentDirectory";
    let ver = 1;
    let nt = format!("urn:schemas-upnp-org:service:{service_type}:{ver}");
    let usn = format!("uuid:{device_uuid}::urn:schemas-upnp-org:service:{service_type}:{ver}");
    let advertisement = format!(
        "{HTTP_METHOD_NOTIFY} {HTTP_MATCH_ANY_RESOURCE} {HTTP_PROTOCOL_NAME}/{HTTP_PROTOCOL_VERSION}\r\nHOST: {SSDP_IPV4_MULTICAST_ADDRESS}\r\nBOOTID.UPNP.ORG: {boot_id}\r\nCONFIGID.UPNP.ORG: 1\r\nSERVER: {os_version} UPnP/2.0 strumur/0.1.0\r\nNT: {nt}\r\nNTS: ssdp:alive\r\nUSN: {usn}\r\nLOCATION: {location}\r\nCACHE-CONTROL: max-age={}\r\n\r\n",
        max_age.as_secs()
    );
    socket.send_to(advertisement.as_bytes(), &SockAddr::from(addr))?;

    // TODO above messages should be resent periodically

    loop {
        let mut buffer = Vec::with_capacity(1024);
        match socket.recv_from(buffer.spare_capacity_mut()) {
            Ok((received, src)) => {
                unsafe {
                    buffer.set_len(received);
                }

                // When a new control point is added to the network, it is allowed to multicast a discovery
                // message searching for interesting devices, services, or both.
                // All devices shall listen to the standard multicast address for these messages and shall
                // respond if any of their root devices, embedded devices or services matches the search criteria
                // in the discovery message.
                // All devices shall listen to incoming unicast search messages on port 1900 or, if provided, the
                // port number specified in the SEARCHPORT.UPNP.ORG header field and shall respond if any
                // of their root devices, embedded devices or services matches the search criteria in the
                // discovery message.
                match parse_ssdp_message(&buffer) {
                    Ok(ssdp_message) => {
                        if ssdp_message.request_line == "HTTP/1.1 200 OK" {
                            println!("what do i do with {ssdp_message:#?}");
                            continue;
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
                                    continue;
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
                                    continue;
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
                                if multicast
                                    && ssdp_message.headers.contains_key("TCPPORT.UPNP.ORG")
                                {
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
                                        continue;
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
                                    continue;
                                };
                                let Some(st) = ssdp_message.headers.get(st_key) else {
                                    println!("error getting {st_key} header");
                                    continue;
                                };

                                if st == "ssdp:all"
                                    || st == "upnp:rootdevice"
                                    || st == format!("uuid:{device_uuid}").as_str()
                                    || st == "urn:schemas-upnp-org:device:MediaServer:1"
                                    || st == "urn:schemas-upnp-org:service:ContentDirectory:1"
                                {
                                    println!("ok search target: {st}");
                                } else if st.starts_with(format!("uuid:{device_uuid}").as_str()) {
                                    println!("unexpected search target format: {st}");
                                } else if st.starts_with("uuid:") {
                                    println!("unintended search target reciptient: {st}");
                                    continue;
                                } else {
                                    println!("unknown search target {st}");
                                    continue;
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
                                        "HTTP/1.1 200 OK\r\nDATE: {response_date}\r\nEXT:\r\nBOOTID.UPNP.ORG: {boot_id}\r\nCONFIGID.UPNP.ORG: 1\r\nSERVER: {os_version} UPnP/2.0 strumur/0.1.0\r\nST: {st}\r\nUSN: {usn}\r\nLOCATION: {location}\r\nCACHE-CONTROL: max-age={}\r\n\r\n",
                                        max_age.as_secs()
                                    );
                                    println!("send {usn}");
                                    socket.send_to(advertisement.as_bytes(), &src)?;
                                }

                                if st == "ssdp:all" || st == format!("uuid:{device_uuid}").as_str()
                                {
                                    let st = format!("uuid:{device_uuid}");
                                    let usn = format!("uuid:{device_uuid}");
                                    let advertisement = format!(
                                        "HTTP/1.1 200 OK\r\nDATE: {response_date}\r\nEXT:\r\nBOOTID.UPNP.ORG: {boot_id}\r\nCONFIGID.UPNP.ORG: 1\r\nSERVER: {os_version} UPnP/2.0 strumur/0.1.0\r\nST: {st}\r\nUSN: {usn}\r\nLOCATION: {location}\r\nCACHE-CONTROL: max-age={}\r\n\r\n",
                                        max_age.as_secs()
                                    );
                                    println!("send {usn}");
                                    socket.send_to(advertisement.as_bytes(), &src)?;
                                }

                                if st == "ssdp:all"
                                    || st == "urn:schemas-upnp-org:device:MediaServer:1"
                                {
                                    let st = "urn:schemas-upnp-org:device:MediaServer:1";
                                    let usn = format!("uuid:{device_uuid}::{st}");
                                    let advertisement = format!(
                                        "HTTP/1.1 200 OK\r\nDATE: {response_date}\r\nEXT:\r\nBOOTID.UPNP.ORG: {boot_id}\r\nCONFIGID.UPNP.ORG: 1\r\nSERVER: {os_version} UPnP/2.0 strumur/0.1.0\r\nST: {st}\r\nUSN: {usn}\r\nLOCATION: {location}\r\nCACHE-CONTROL: max-age={}\r\n\r\n",
                                        max_age.as_secs()
                                    );
                                    println!("send {usn}");
                                    socket.send_to(advertisement.as_bytes(), &src)?;
                                }

                                if st == "ssdp:all"
                                    || st == "urn:schemas-upnp-org:service:ContentDirectory:1"
                                {
                                    let st = "urn:schemas-upnp-org:service:ContentDirectory:1";
                                    let usn = format!("uuid:{device_uuid}::{st}");
                                    let advertisement = format!(
                                        "HTTP/1.1 200 OK\r\nDATE: {response_date}\r\nEXT:\r\nBOOTID.UPNP.ORG: {boot_id}\r\nCONFIGID.UPNP.ORG: 1\r\nSERVER: {os_version} UPnP/2.0 strumur/0.1.0\r\nST: {st}\r\nUSN: {usn}\r\nLOCATION: {location}\r\nCACHE-CONTROL: max-age={}\r\n\r\n",
                                        max_age.as_secs()
                                    );
                                    println!("send {usn}");
                                    socket.send_to(advertisement.as_bytes(), &src)?;
                                }
                            }
                            _ => println!("something else: {}", ssdp_message.request_line),
                        }
                    }
                    Err(err) => {
                        println!("failed to parse ssdp message: {err}");
                    }
                }
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
            .ok_or(format!("failed to get value for key {key}"))?
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
}
