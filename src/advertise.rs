extern crate socket2;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use chrono::Utc;
use log::{debug, error, info, trace, warn};
use rand::Rng;
use rand::rngs::ThreadRng;
use socket2::{SockAddr, Socket};

use crate::NAME;
use crate::SocketToMe;
use crate::SysInfo;
use crate::VERSION;

const UPNP_VERSION: &str = "UPnP/2.0";

pub const SSDP_IPV4_MULTICAST_ADDRESS: &str = "239.255.255.250:1900";

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

pub fn handle_search_error(err: &HandleSearchMessageError) {
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

pub fn advertise_discovery_messages(
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
pub enum HandleSearchMessageError {
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

impl From<InvalidSSDPMessage> for HandleSearchMessageError {
    fn from(e: InvalidSSDPMessage) -> Self {
        Self::InvalidSSDPMessage(e.msg)
    }
}

pub fn handle_search_message(
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

    let ssdp_message = parse_ssdp_message(data)?;

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

#[derive(Debug)]
struct InvalidSSDPMessage {
    msg: String,
}

impl From<&str> for InvalidSSDPMessage {
    fn from(msg: &str) -> Self {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl From<String> for InvalidSSDPMessage {
    fn from(msg: String) -> Self {
        Self { msg }
    }
}

fn parse_ssdp_message(data: &[u8]) -> std::result::Result<SSDPMessage, InvalidSSDPMessage> {
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

    use socket2::{Domain, Protocol, SockAddrStorage, Type};
    use uuid::Uuid;

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
}
