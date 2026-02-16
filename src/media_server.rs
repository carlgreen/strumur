extern crate socket2;

use std::collections::HashMap;
use std::fmt::Write;
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::net::TcpListener;
use std::thread;

use chrono::NaiveDate;
use chrono::NaiveTime;
use log::{debug, error, info, trace, warn};
use uuid::Uuid;
use xmltree::Element;

use crate::collection::{Album, Artist, Collection, Track};
use crate::search_parser::{
    BinOp, BoolVal, Error, ExistsOp, LogOp, QuotedVal, RelExp, Scanner, SearchCrit, SearchExp,
    StringOp, search_crit,
};

const HTTP_PROTOCOL_NAME: &str = "HTTP";

const HTTP_PROTOCOL_VERSION: &str = "1.1";

const HTTP_RESPONSE_OK: &str = "200 OK";

const HTTP_RESPONSE_INTERNAL_SERVER_ERROR: &str = "500 Internal Server Error";

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

pub fn listen(device_uuid: Uuid, collection: Collection) {
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

enum UPNPError {
    NoSuchObject,
}
impl UPNPError {
    const fn describe(&self) -> (u16, &str) {
        match self {
            Self::NoSuchObject => (701, "No such object"),
        }
    }
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
        + r#"<container id="0$=Artist" parentID="0" restricted="1" searchable="1"><dc:title>Artist</dc:title><upnp:class>object.container</upnp:class></container>"#
        + r#"<container id="0$=All Artists" parentID="0" restricted="1" searchable="1"><dc:title>All Artists</dc:title><upnp:class>object.container</upnp:class></container>"#;
    format_response(&result, 4, 4)
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
            let album_id = album.id;
            let album_title = xml::escape::escape_str_attribute(&album.title);
            let date = create_date_element(album.date);
            let track_count = album.get_tracks().len();
            let cover = create_album_art_element(addr, &album.cover);
            // TODO album art details
            write!(
                result,
                r#"<container id="0$albums$*a{album_id}" parentID="0$albums" childCount="{track_count}" restricted="1" searchable="1"><dc:title>{album_title}</dc:title>{date}<upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist>{cover}<upnp:class>object.container.album.musicAlbum</upnp:class></container>"#,
            ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
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
) -> std::result::Result<String, UPNPError> {
    let mut found = None;
    'artists: for artist in collection.get_artists() {
        for album in artist.get_albums() {
            if format!("*a{}", album.id) == album_id {
                found = Some((artist, album));
                break 'artists;
            }
        }
    }
    let Some((artist, album)) = found else {
        return Err(UPNPError::NoSuchObject);
    };
    let tracks = album.get_tracks();
    let total_matches = tracks.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let album_artist_name = xml::escape::escape_str_attribute(&artist.name);
    let album_title = &album.title;
    let date = create_date_element(album.date);
    let cover = create_album_art_element(addr, &album.cover);
    let mut result = String::new();
    for track in tracks.skip(starting_index).take(requested_count) {
        number_returned += 1;
        let track_id = track.id;
        let track_title = xml::escape::escape_str_attribute(&track.title);
        let artist_name = xml::escape::escape_str_attribute(&track.artist);
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
            r#"<item id="0$albums${album_id}$*i{track_id}" parentID="0$albums${album_id}" restricted="1"><dc:title>{track_title}</dc:title>{date}<upnp:album>{album_title}</upnp:album><upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{album_artist_name}</upnp:artist><upnp:originalTrackNumber>{track_number}</upnp:originalTrackNumber>{cover}<res duration="{duration}" size="{size}" bitsPerSample="{bits_per_sample}" sampleFrequency="{sample_frequency}" nrAudioChannels="{channels}" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">{file}</res><upnp:class>object.item.audioItem.musicTrack</upnp:class></item>"#,
        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    Ok(format_response(&result, number_returned, total_matches))
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
    for artist in artists.skip(starting_index).take(requested_count) {
        number_returned += 1;
        let id = artist.id;
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
) -> std::result::Result<String, UPNPError> {
    let things = ["albums", "items"];
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let total_matches = things.len();
    let Some(artist) = collection
        .get_artists()
        .find(|a| a.id.to_string() == artist_id)
    else {
        return Err(UPNPError::NoSuchObject);
    };
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
    Ok(format_response(&result, number_returned, total_matches))
}

fn generate_browse_an_artist_albums_response(
    collection: &Collection,
    artist_id: &str,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
    addr: &str,
) -> std::result::Result<String, UPNPError> {
    let Some(artist) = collection
        .get_artists()
        .find(|a| a.id.to_string() == artist_id)
    else {
        return Err(UPNPError::NoSuchObject);
    };
    let albums = artist.get_albums();
    let total_matches = albums.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let artist_id = artist.id;
    let artist_name = xml::escape::escape_str_attribute(&artist.name);
    let mut result = String::new();
    for album in albums.skip(starting_index).take(requested_count) {
        number_returned += 1;
        let id = album.id;
        let title = xml::escape::escape_str_attribute(&album.title);
        let date = create_date_element(album.date);
        let track_count = album.get_tracks().len();
        let cover = create_album_art_element(addr, &album.cover);
        write!(
            result,
            r#"<container id="0$=Artist${artist_id}$albums${id}" parentID="0$=Artist${artist_id}$albums" childCount="{track_count}" restricted="1" searchable="1"><dc:title>{title}</dc:title>{date}<upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{artist_name}</upnp:artist>{cover}<upnp:class>object.container.album.musicAlbum</upnp:class></container>"#,
        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    Ok(format_response(&result, number_returned, total_matches))
}

fn generate_browse_an_artist_album_response(
    collection: &Collection,
    artist_id: &str,
    album_id: &str,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
    addr: &str,
) -> std::result::Result<String, UPNPError> {
    let Some(artist) = collection
        .get_artists()
        .find(|a| a.id.to_string() == artist_id)
    else {
        return Err(UPNPError::NoSuchObject);
    };
    let Some(album) = artist.get_albums().find(|a| a.id.to_string() == album_id) else {
        return Err(UPNPError::NoSuchObject);
    };
    let tracks = album.get_tracks();
    let total_matches = tracks.len();
    let starting_index = starting_index.unwrap().into();
    let requested_count = requested_count.unwrap().into();
    let mut number_returned = 0;
    let album_artist_name = xml::escape::escape_str_attribute(&artist.name);
    let album_title = xml::escape::escape_str_attribute(&album.title);
    let date = create_date_element(album.date);
    let cover = create_album_art_element(addr, &album.cover);
    let mut result = String::new();
    for track in tracks.skip(starting_index).take(requested_count) {
        number_returned += 1;
        let id = track.id;
        let track_title = xml::escape::escape_str_attribute(&track.title);
        let artist_name = xml::escape::escape_str_attribute(&track.artist);
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
            r#"<item id="0$=Artist${artist_id}$albums${album_id}${id}" parentID="0$=Artist${artist_id}$albums${album_id}" restricted="1"><dc:title>{track_title}</dc:title>{date}<upnp:album>{album_title}</upnp:album><upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{album_artist_name}</upnp:artist><upnp:originalTrackNumber>{track_number}</upnp:originalTrackNumber>{cover}<res duration="{duration}" size="{size}" bitsPerSample="{bits_per_sample}" sampleFrequency="{sample_frequency}" nrAudioChannels="{channels}" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">{file}</res><upnp:class>object.item.audioItem.musicTrack</upnp:class></item>"#,
        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));
    }
    Ok(format_response(&result, number_returned, total_matches))
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
    for artist in artists.skip(starting_index).take(requested_count) {
        number_returned += 1;
        let id = artist.id;
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
            [root] if root == "0" => Ok(generate_browse_root_response(collection)),
            [root, next] if root == "0" && next == "albums" => Ok(generate_browse_albums_response(
                collection,
                starting_index,
                requested_count,
                addr,
            )),
            [root, next, album_id] if root == "0" && next == "albums" => {
                generate_browse_an_album_response(
                    collection,
                    album_id,
                    starting_index,
                    requested_count,
                    addr,
                )
            }
            [root, next] if root == "0" && next == "=Artist" => Ok(
                generate_browse_artists_response(collection, starting_index, requested_count),
            ),
            [root, next, artist_id] if root == "0" && next == "=Artist" => {
                generate_browse_an_artist_response(
                    collection,
                    artist_id,
                    starting_index,
                    requested_count,
                )
            }
            [root, next, artist_id, _artist_what] if root == "0" && next == "=Artist" => {
                generate_browse_an_artist_albums_response(
                    collection,
                    artist_id,
                    starting_index,
                    requested_count,
                    addr,
                )
            }
            [root, next, artist_id, artist_what, album_id]
                if root == "0" && next == "=Artist" && artist_what == "albums" =>
            {
                generate_browse_an_artist_album_response(
                    collection,
                    artist_id,
                    album_id,
                    starting_index,
                    requested_count,
                    addr,
                )
            }
            [root, next] if root == "0" && next == "=All Artists" => Ok(
                generate_browse_all_artists_response(collection, starting_index, requested_count),
            ),
            _ => {
                error!("control: unexpected object ID: {object_id:?}");
                Err(UPNPError::NoSuchObject)
            }
        };
    match browse_response {
        Ok(browse_response) => {
            let body = format!(
                r#"
        <u:BrowseResponse xmlns:u="{CONTENT_DIRECTORY_SERVICE_TYPE}">{browse_response}
        </u:BrowseResponse>"#
            );
            (wrap_with_envelope_body(&body), HTTP_RESPONSE_OK)
        }
        Err(e) => {
            let (code, description) = e.describe();
            soap_upnp_error(code, description)
        }
    }
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

/// based on "ContentDirectory:1 Service Template" section 2.5.5 Search Criteria
fn parse_search_criteria(input: &str) -> std::result::Result<Option<SearchCrit>, Error> {
    let mut scanner = Scanner::new(input);
    search_crit(&mut scanner)
}

fn generate_search_response(
    collection: &Collection,
    container_id: &[String],
    search_criteria: Option<&SearchCrit>,
    starting_index: Option<u16>,
    requested_count: Option<u16>,
    addr: &str,
) -> (String, &'static str) {
    let search_response = match container_id {
        [root] if root == "0" => {
            let starting_index = starting_index.unwrap().into();
            let requested_count: usize = requested_count.unwrap().into();
            let mut total_matches = 0;
            let mut number_returned = 0;
            let mut result = String::new();
            for artist in collection.get_artists() {
                let artist_id = artist.id;
                let album_artist_name = xml::escape::escape_str_attribute(&artist.name);
                let include =
                    include_this(search_criteria, &SearchWhat::Artist, None, None, artist);
                if include {
                    if total_matches >= starting_index && number_returned < requested_count {
                        write!(
                            result,
                            r#"<container id="0$=Artist${artist_id}" parentID="0$=Artist" restricted="1" searchable="1"><dc:title>{album_artist_name}</dc:title><upnp:class>object.container.person.musicArtist</upnp:class></container>"#
                        ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));

                        number_returned += 1;
                    }
                    total_matches += 1;
                }

                for album in artist.get_albums() {
                    let album_id = album.id;
                    let album_title = xml::escape::escape_str_attribute(&album.title);
                    let include = include_this(
                        search_criteria,
                        &SearchWhat::Album,
                        None,
                        Some(album),
                        artist,
                    );
                    if include {
                        if total_matches >= starting_index && number_returned < requested_count {
                            // let track_count = album.get_tracks().count();
                            // let date = create_date_element(album.date);
                            // let cover = create_album_art_element(addr, &album.cover);

                            write!(
                                result,
                                // childCount="{track_count}"
                                // {date}<upnp:artist>{artist_name}</upnp:artist>{cover}
                                r#"<container id="0$albums$*a{album_id}" parentID="0$albums" restricted="1" searchable="1"><dc:title>{album_title}</dc:title><dc:creator>{album_artist_name}</dc:creator><upnp:artist role="AlbumArtist">{album_artist_name}</upnp:artist><upnp:class>object.container.album.musicAlbum</upnp:class></container>"#,
                            ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));

                            number_returned += 1;
                        }
                        total_matches += 1;
                    }

                    for track in album.get_tracks() {
                        let include = include_this(
                            search_criteria,
                            &SearchWhat::Track,
                            Some(track),
                            Some(album),
                            artist,
                        );
                        if include {
                            if total_matches >= starting_index && number_returned < requested_count
                            {
                                // let date = create_date_element(album.date);
                                // let cover = create_album_art_element(addr, &album.cover);

                                let track_id = track.id;
                                let track_title: std::borrow::Cow<'_, str> =
                                    xml::escape::escape_str_attribute(&track.title);
                                let artist_name: std::borrow::Cow<'_, str> =
                                    xml::escape::escape_str_attribute(&track.artist);
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
                                    r#"<item id="0$albums$*a{album_id}$*i{track_id}" parentID="0$albums$*a{album_id}" restricted="1"><dc:title>{track_title}</dc:title><upnp:album>{album_title}</upnp:album><upnp:artist>{artist_name}</upnp:artist><dc:creator>{artist_name}</dc:creator><upnp:artist role="AlbumArtist">{album_artist_name}</upnp:artist><upnp:originalTrackNumber>{track_number}</upnp:originalTrackNumber><res duration="{duration}" size="{size}" bitsPerSample="{bits_per_sample}" sampleFrequency="{sample_frequency}" nrAudioChannels="{channels}" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">{file}</res><upnp:class>object.item.audioItem.musicTrack</upnp:class></item>"#,
                                ).unwrap_or_else(|err| panic!("should be a 500 response: {err}"));

                                number_returned += 1;
                            }
                            total_matches += 1;
                        }
                    }
                }
            }

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

enum SearchWhat {
    Artist,
    Album,
    Track,
}

fn include_this(
    search_criteria: Option<&SearchCrit>,
    what: &SearchWhat,
    track: Option<&Track>,
    album: Option<&Album>,
    artist: &Artist,
) -> bool {
    // if search_criteria is None then treat as All
    match search_criteria {
        Some(SearchCrit::All) | None => true,
        Some(search_criteria) => match search_criteria {
            SearchCrit::All => true,
            SearchCrit::SearchExp(search_exp) => {
                include_by_search_exp(search_exp, what, track, album, artist)
            }
        },
    }
}

fn include_by_search_exp(
    search_exp: &SearchExp,
    what: &SearchWhat,
    track: Option<&Track>,
    album: Option<&Album>,
    artist: &Artist,
) -> bool {
    match search_exp {
        SearchExp::Rel(rel_exp) => {
            match rel_exp {
                RelExp::BinOp(s, bin_op, quoted_val) => {
                    let QuotedVal::String(quoted_val) = quoted_val;
                    match bin_op {
                        BinOp::RelOp(rel_op) => {
                            todo!("BinOp::RelOp: {rel_op:?}")
                        }
                        BinOp::StringOp(string_op) => match string_op {
                            StringOp::Contains => {
                                if s.as_str() == "dc:title" {
                                    let title = match what {
                                        SearchWhat::Artist => artist.name.clone(),
                                        SearchWhat::Album => album.unwrap().title.clone(),
                                        SearchWhat::Track => track.unwrap().title.clone(),
                                    };
                                    title.to_ascii_lowercase().contains(quoted_val)
                                } else {
                                    warn!("unsupported property {s}");
                                    false
                                }
                            }
                            StringOp::DoesNotContain => {
                                todo!("doesn't contain")
                            }
                            StringOp::DerivedFrom => {
                                todo!("derived from")
                            }
                        },
                    }
                }
                RelExp::ExistsOp(s, exists_op, bool_val) => {
                    let bool_val = match bool_val {
                        BoolVal::True => true,
                        BoolVal::False => false,
                    };
                    if s.as_str() == "@refID" {
                        // i don't do ref IDs (yet anyway)
                        match exists_op {
                            ExistsOp::Exists => !bool_val,
                        }
                    } else {
                        warn!("unsupported property {s} for {exists_op:?}");
                        false
                    }
                }
            }
        }
        SearchExp::Log(search_exp1, log_op, search_exp2) => match log_op {
            LogOp::And => {
                include_by_search_exp(search_exp1, what, track, album, artist)
                    && include_by_search_exp(search_exp2, what, track, album, artist)
            }
            LogOp::Or => todo!("or"),
        },
        SearchExp::Brackets(search_exp) => {
            todo!("SearchExp::Brackets: {search_exp:?}")
        }
    }
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

            let search_criteria = search_criteria.unwrap_or_default();
            info!(
                "search:\n\tcontainer_id: {container_id:?}\n\tsearch_criteria: {search_criteria:?}\n\tstarting_index: {starting_index:?}\n\trequested_count: {requested_count:?}"
            );

            let search_criteria = match parse_search_criteria(&search_criteria) {
                Ok(search_criteria) => search_criteria,
                Err(err) => {
                    warn!("could not parse {search_criteria}: {err:?}");
                    return soap_upnp_error(708, "Invalid search criteria");
                }
            };
            trace!("search criteria: {search_criteria:?}");

            let container_id = container_id.unwrap_or_else(|| {
                warn!("no container id, assuming 0");
                vec!["0".to_string()]
            });

            generate_search_response(
                collection,
                &container_id,
                search_criteria.as_ref(),
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

// it seems based on the example in the docs that its always 500?
fn soap_upnp_error(error_code: u16, error_description: &str) -> (String, &'static str) {
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
    (
        wrap_with_envelope_body(&content),
        HTTP_RESPONSE_INTERNAL_SERVER_ERROR,
    )
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

#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::PathBuf};

    use x_diff_rs::diff::diff;
    use x_diff_rs::tree::XTree;

    use crate::collection::{Album, Artist, Track};

    use super::*;

    fn make_album(
        id: &mut u128,
        artist_name: &str,
        album_title: &str,
        release_date: &str,
        mut tracks: Vec<Track>,
    ) -> Album {
        let date = release_date.parse::<NaiveDate>().unwrap();
        tracks.iter_mut().for_each(|t| {
            *id += 1;
            t.id = *id;
        });
        *id += 1;
        Album::new(
            *id,
            album_title.to_string(),
            //  NaiveDate::from_ymd_opt(1996, 2, 12).expect("invalid or out-of-range date"),
            Some(date),
            tracks,
            format!("Music/{artist_name}/{album_title}/cover.jpg"),
        )
    }

    fn make_track(
        artist_name: &str,
        album_title: &str,
        track_number: u8,
        track_title: &str,
    ) -> Track {
        Track {
            id: 0, // placeholder
            disc: 0,
            number: track_number,
            title: track_title.to_string(),
            artist: format!("{artist_name} feat. X"),
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
        let mut last_id = 0;
        let a1 = make_album(
            &mut last_id,
            "a<bc",
            "a1",
            "1996-02-12",
            vec![
                make_track("a<bc", "a1", 1, "a11"),
                make_track("a<bc", "a1", 2, "a12"),
                make_track("a<bc", "a1", 3, "a13"),
                make_track("a<bc", "a1", 4, "a14"),
            ],
        );
        let g1 = make_album(
            &mut last_id,
            "ghi",
            "g1",
            "1996-02-12",
            vec![
                make_track("ghi", "g1", 1, "g<11"),
                make_track("ghi", "g1", 2, "g12"),
                make_track("ghi", "g1", 3, "g13"),
            ],
        );
        let h2 = make_album(
            &mut last_id,
            "ghi",
            "h2",
            "2002-07-30",
            vec![
                make_track("ghi", "h2", 1, "h21"),
                make_track("ghi", "h2", 2, "h22"),
                make_track("ghi", "h2", 3, "h23"),
                make_track("ghi", "h2", 4, "h24"),
            ],
        );
        let i3 = make_album(
            &mut last_id,
            "ghi",
            "i3",
            "2011-11-11",
            vec![
                make_track("ghi", "i3", 1, "i31"),
                make_track("ghi", "i3", 2, "i32"),
            ],
        );
        let j1 = make_album(&mut last_id, "jk", "j1", "1980-01-01", vec![]);
        let l1 = make_album(&mut last_id, "lm", "l1", "1982-02-02", vec![]);
        let n1 = make_album(&mut last_id, "nop", "n1", "1984-04-01", vec![]);
        let q1 = make_album(&mut last_id, "qrs", "q1", "1986-06-06", vec![]);
        let t1 = make_album(&mut last_id, "tuv", "t1", "1988-08-08", vec![]);
        let w1 = make_album(&mut last_id, "w", "w1", "1990-10-10", vec![]);
        let x1 = make_album(&mut last_id, "xyz", "x1", "1992-12-12", vec![]);

        Collection::new(
            7, // fun number for testing
            PathBuf::from("./"),
            vec![
                Artist::new(last_id + 1, "a<bc".to_string(), vec![a1]),
                Artist::new(
                    last_id + 2,
                    "def".to_string(),
                    vec![make_album(&mut last_id, "def", "d<1", "2005-07-02", vec![])],
                ),
                Artist::new(last_id + 3, "ghi".to_string(), vec![g1, h2, i3]),
                Artist::new(last_id + 4, "jk".to_string(), vec![j1]),
                Artist::new(last_id + 5, "lm".to_string(), vec![l1]),
                Artist::new(last_id + 6, "nop".to_string(), vec![n1]),
                Artist::new(last_id + 7, "qrs".to_string(), vec![q1]),
                Artist::new(last_id + 8, "tuv".to_string(), vec![t1]),
                Artist::new(last_id + 9, "w".to_string(), vec![w1]),
                Artist::new(last_id + 10, "xyz".to_string(), vec![x1]),
            ],
        )
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

    fn extract_error_response(body: &str) -> (u16, String) {
        let envelope = Element::parse(body.as_bytes()).unwrap();
        let body = envelope.get_child("Body").unwrap();
        let fault = body.get_child("Fault").unwrap();

        let upnp_error = fault
            .get_child("detail")
            .unwrap()
            .get_child("UPnPError")
            .unwrap();

        let error_code = upnp_error
            .get_child("errorCode")
            .unwrap()
            .get_text()
            .unwrap()
            .parse()
            .unwrap();

        let error_description = upnp_error
            .get_child("errorDescription")
            .unwrap()
            .get_text()
            .unwrap()
            .into();

        (error_code, error_description)
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
    <container id="0$=Artist" parentID="0" restricted="1" searchable="1">
        <dc:title>Artist</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$=All Artists" parentID="0" restricted="1" searchable="1">
        <dc:title>All Artists</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 4);
        assert_eq!(total_matches, 4);
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
    <container id="0$albums$*a5" parentID="0$albums" childCount="4" restricted="1" searchable="1">
        <dc:title>a1</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:artist>a&lt;bc</upnp:artist>
        <dc:creator>a&lt;bc</dc:creator>
        <upnp:artist role="AlbumArtist">a&lt;bc</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/a&lt;bc/a1/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$albums$*a25" parentID="0$albums" childCount="0" restricted="1" searchable="1">
        <dc:title>d&lt;1</dc:title>
        <dc:date>2005-07-02</dc:date>
        <upnp:artist>def</upnp:artist>
        <dc:creator>def</dc:creator>
        <upnp:artist role="AlbumArtist">def</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/def/d&lt;1/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$albums$*a9" parentID="0$albums" childCount="3" restricted="1" searchable="1">
        <dc:title>g1</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$albums$*a14" parentID="0$albums" childCount="4" restricted="1" searchable="1">
        <dc:title>h2</dc:title>
        <dc:date>2002-07-30</dc:date>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/h2/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$albums$*a17" parentID="0$albums" childCount="2" restricted="1" searchable="1">
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
        let input = generate_browse_request("0$albums$*a9", 0, 500);
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
    <item id="0$albums$*a9$*i6" parentID="0$albums$*a9" restricted="1">
        <dc:title>g&lt;11</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi feat. X</upnp:artist>
        <dc:creator>ghi feat. X</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>1</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/01*20g&lt;11.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$albums$*a9$*i7" parentID="0$albums$*a9" restricted="1">
        <dc:title>g12</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi feat. X</upnp:artist>
        <dc:creator>ghi feat. X</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>2</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/02*20g12.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$albums$*a9$*i8" parentID="0$albums$*a9" restricted="1">
        <dc:title>g13</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi feat. X</upnp:artist>
        <dc:creator>ghi feat. X</dc:creator>
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
    fn test_handle_browse_an_incorrect_album_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$albums$*a200", 0, 500);
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

        let (error_code, error_description) = extract_error_response(&body);
        assert_eq!(error_code, 701);
        assert_eq!(error_description, "No such object");
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
    <container id="0$=Artist$25" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>a&lt;bc</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=Artist$26" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>def</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=Artist$28" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>ghi</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=Artist$29" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>jk</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=Artist$30" parentID="0$=Artist" restricted="1" searchable="1">
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
        let input = generate_browse_request("0$=Artist$28", 0, 500);
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
    <container id="0$=Artist$28$albums" parentID="0$=Artist$28" restricted="1" searchable="1">
        <dc:title>3 albums</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
    <container id="0$=Artist$28$items" parentID="0$=Artist$28" restricted="1" searchable="1">
        <dc:title>9 items</dc:title>
        <upnp:class>object.container</upnp:class>
    </container>
</DIDL-Lite>"#,
        );
        assert_eq!(number_returned, 2);
        assert_eq!(total_matches, 2);
        assert_eq!(update_id, "25");
    }

    #[test]
    fn test_handle_browse_an_incorrect_artist_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$280", 0, 500);
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

        let (error_code, error_description) = extract_error_response(&body);
        assert_eq!(error_code, 701);
        assert_eq!(error_description, "No such object");
    }

    #[test]
    fn test_handle_browse_an_artist_albums_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$28$albums", 0, 500);
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
    <container id="0$=Artist$28$albums$9" parentID="0$=Artist$28$albums" childCount="3" restricted="1" searchable="1">
        <dc:title>g1</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$=Artist$28$albums$14" parentID="0$=Artist$28$albums" childCount="4" restricted="1" searchable="1">
        <dc:title>h2</dc:title>
        <dc:date>2002-07-30</dc:date>
        <upnp:artist>ghi</upnp:artist>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/h2/cover.jpg</upnp:albumArtURI>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <container id="0$=Artist$28$albums$17" parentID="0$=Artist$28$albums" childCount="2" restricted="1" searchable="1">
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
    fn test_handle_browse_an_incorrect_artist_albums_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$280$albums", 0, 500);
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

        let (error_code, error_description) = extract_error_response(&body);
        assert_eq!(error_code, 701);
        assert_eq!(error_description, "No such object");
    }

    #[test]
    fn test_handle_browse_an_artist_album_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$28$albums$9", 0, 500);
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
    <item id="0$=Artist$28$albums$9$6" parentID="0$=Artist$28$albums$9" restricted="1">
        <dc:title>g&lt;11</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi feat. X</upnp:artist>
        <dc:creator>ghi feat. X</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>1</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/01*20g&lt;11.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$=Artist$28$albums$9$7" parentID="0$=Artist$28$albums$9" restricted="1">
        <dc:title>g12</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi feat. X</upnp:artist>
        <dc:creator>ghi feat. X</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>2</upnp:originalTrackNumber>
        <upnp:albumArtURI dlna:profileID="JPEG_MED">http://1.2.3.100:1234/Content/Music/ghi/g1/cover.jpg</upnp:albumArtURI>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/02*20g12.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$=Artist$28$albums$9$8" parentID="0$=Artist$28$albums$9" restricted="1">
        <dc:title>g13</dc:title>
        <dc:date>1996-02-12</dc:date>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi feat. X</upnp:artist>
        <dc:creator>ghi feat. X</dc:creator>
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
    fn test_handle_browse_an_incorrect_artist_album_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$280$albums$9", 0, 500);
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

        let (error_code, error_description) = extract_error_response(&body);
        assert_eq!(error_code, 701);
        assert_eq!(error_description, "No such object");
    }

    #[test]
    fn test_handle_browse_an_artist_incorrect_album_content() {
        let test_device_uuid = Uuid::parse_str("5c863963-f2a2-491e-8b60-079cdadad147").unwrap();
        let addr = "http://1.2.3.100:1234/Content";
        let collection = generate_test_collection();
        let input = generate_browse_request("0$=Artist$3$albums$90", 0, 500);
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

        let (error_code, error_description) = extract_error_response(&body);
        assert_eq!(error_code, 701);
        assert_eq!(error_description, "No such object");
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

        // TODO expect feat. artists, etc.?
        compare_xml(
            &result,
            r#"<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/" xmlns:dlna="urn:schemas-dlna-org:metadata-1-0/">
    <container id="0$=All Artists$25" parentID="0$=All Artists" restricted="1" searchable="1">
        <dc:title>a&lt;bc</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=All Artists$26" parentID="0$=All Artists" restricted="1" searchable="1">
        <dc:title>def</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=All Artists$28" parentID="0$=All Artists" restricted="1" searchable="1">
        <dc:title>ghi</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=All Artists$29" parentID="0$=All Artists" restricted="1" searchable="1">
        <dc:title>jk</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$=All Artists$30" parentID="0$=All Artists" restricted="1" searchable="1">
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
    <container id="0$=Artist$28" parentID="0$=Artist" restricted="1" searchable="1">
        <dc:title>ghi</dc:title>
        <upnp:class>object.container.person.musicArtist</upnp:class>
    </container>
    <container id="0$albums$*a9" parentID="0$albums" restricted="1" searchable="1">
        <dc:title>g1</dc:title>
        <dc:creator>ghi</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:class>object.container.album.musicAlbum</upnp:class>
    </container>
    <item id="0$albums$*a9$*i6" parentID="0$albums$*a9" restricted="1">
        <dc:title>g&lt;11</dc:title>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi feat. X</upnp:artist>
        <dc:creator>ghi feat. X</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>1</upnp:originalTrackNumber>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/01*20g&lt;11.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$albums$*a9$*i7" parentID="0$albums$*a9" restricted="1">
        <dc:title>g12</dc:title>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi feat. X</upnp:artist>
        <dc:creator>ghi feat. X</dc:creator>
        <upnp:artist role="AlbumArtist">ghi</upnp:artist>
        <upnp:originalTrackNumber>2</upnp:originalTrackNumber>
        <res duration="0:02:18.893" size="18323574" bitsPerSample="16" sampleFrequency="44100" nrAudioChannels="2" protocolInfo="http-get:*:audio/x-flac:DLNA.ORG_OP=01;DLNA.ORG_FLAGS=01700000000000000000000000000000">http://1.2.3.100:1234/Content/Music/ghi/g1/02*20g12.flac</res>
        <upnp:class>object.item.audioItem.musicTrack</upnp:class>
    </item>
    <item id="0$albums$*a9$*i8" parentID="0$albums$*a9" restricted="1">
        <dc:title>g13</dc:title>
        <upnp:album>g1</upnp:album>
        <upnp:artist>ghi feat. X</upnp:artist>
        <dc:creator>ghi feat. X</dc:creator>
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
    fn test_format_time_nice() {
        let time = NaiveTime::from_hms_milli_opt(0, 0, 5, 712).unwrap();
        assert_eq!(format_time_nice(time), "0:00:05.712");
    }
}
