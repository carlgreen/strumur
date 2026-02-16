use std::fs;
use std::fs::DirEntry;
use std::fs::File;
use std::io::BufReader;
use std::io::Seek;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

use chrono::NaiveDate;
use chrono::NaiveTime;
use log::{debug, info, trace, warn};

use crate::flac::extract_flac_metadata;
use crate::flac::is_flac;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artist {
    pub id: u128,
    pub name: String,
    albums: Vec<Album>,
}

impl Artist {
    #[cfg(test)]
    pub const fn new(id: u128, name: String, albums: Vec<Album>) -> Self {
        Self { id, name, albums }
    }

    pub fn get_albums(&self) -> impl ExactSizeIterator<Item = &Album> {
        self.albums.iter()
    }

    pub fn get_tracks(&self) -> impl Iterator<Item = &Track> {
        self.albums.iter().flat_map(Album::get_tracks)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Album {
    pub id: u128,
    pub title: String,
    pub date: Option<NaiveDate>,
    tracks: Vec<Track>,
    pub cover: String,
}

impl Album {
    #[cfg(test)]
    pub const fn new(
        id: u128,
        title: String,
        date: Option<NaiveDate>,
        tracks: Vec<Track>,
        cover: String,
    ) -> Self {
        Self {
            id,
            title,
            date,
            tracks,
            cover,
        }
    }

    pub fn get_tracks(&self) -> impl ExactSizeIterator<Item = &Track> {
        self.tracks.iter()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Track {
    pub id: u128,
    pub disc: u8,
    pub number: u8,
    pub title: String,
    pub file: String,
    pub duration: NaiveTime,
    pub size: u64,
    pub bits_per_sample: u8,
    pub sample_frequency: u32,
    pub channels: u8,
}

#[derive(Clone, Debug)]
pub struct Collection {
    last_id: u128,
    system_update_id: u16, // TODO maintain this value
    pub base: PathBuf,
    artists: Vec<Artist>,
}

impl Collection {
    #[cfg(test)]
    pub const fn new(system_update_id: u16, base: PathBuf, artists: Vec<Artist>) -> Self {
        Self {
            last_id: 0,
            system_update_id,
            base,
            artists,
        }
    }

    const fn next_id(&mut self) -> u128 {
        self.last_id += 1;
        self.last_id
    }

    pub fn populate(location: &str) -> Self {
        info!("populating collection from {location:?}");
        let mut collection = Self {
            last_id: 0,
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

    pub const fn get_system_update_id(&self) -> u16 {
        self.system_update_id
    }

    pub fn get_artists(&self) -> impl ExactSizeIterator<Item = &Artist> {
        self.artists.iter()
    }

    pub fn get_albums(&self) -> impl Iterator<Item = &Album> {
        self.artists.iter().flat_map(Artist::get_albums)
    }

    pub fn get_tracks(&self) -> impl Iterator<Item = &Track> {
        self.artists
            .iter()
            .flat_map(|artist| artist.get_albums().flat_map(Album::get_tracks))
    }
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
                            id: collection.next_id(),
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

            // can't borrow mutable collection again by method, but can modify the same bits directly?
            // collection.next_id();
            collection.last_id += 1;
            let album_id = collection.last_id;
            let album = Album {
                id: album_id,
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
            id: collection.next_id(),
            title: album_title,
            date: release_date,
            tracks: vec![track],
            cover: cover_url.unwrap_or_default(),
        };

        let artist = Artist {
            id: collection.next_id(),
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
        let collection = Collection::populate(location);
        assert_eq!(
            collection.artists,
            vec![Artist {
                id: 3,
                name: "carl".to_string(),
                albums: vec![Album {
                    id: 2,
                    title: "none".to_string(),
                    date: None,
                    tracks: vec![Track {
                        id: 1,
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
