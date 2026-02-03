// FLAC stuff see https://www.rfc-editor.org/rfc/rfc9639

// TODO these should not require reading the entire file into memory

use std::io::{BufReader, Read};

use chrono::NaiveTime;
use log::{debug, error, warn};

const FLAC_MARKER: [u8; 4] = [0x66_u8, 0x4C_u8, 0x61_u8, 0x43_u8];

pub fn is_flac(reader: &mut BufReader<impl Read>) -> bool {
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
pub struct FlacMetadata {
    /// The minimum block size (in samples) used in the stream, excluding the last block.
    minimum_block_size: u16,

    /// The maximum block size (in samples) used in the stream.
    maximum_block_size: u16,

    /// The minimum frame size (in bytes) used in the stream. A value of 0 signifies that the value is not known.
    minimum_frame_size: u32,

    /// The maximum frame size (in bytes) used in the stream. A value of 0 signifies that the value is not known.
    maximum_frame_size: u32,

    /// Sample rate in Hz.
    pub sample_rate: u32,

    /// (number of channels)-1. FLAC supports from 1 to 8 channels.
    pub channels: u8,

    /// (bits per sample)-1. FLAC supports from 4 to 32 bits per sample.
    pub bits: u8,

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

    pub fn duration(&self) -> NaiveTime {
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

    pub fn get_field_names(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|f| f.name.as_str())
    }

    pub fn get_field(&self, name: &str) -> Option<String> {
        self.fields
            .iter()
            .find(|f| f.name.to_uppercase() == name)
            .map(|f| f.content.clone())
    }
}

#[derive(Debug, PartialEq, Eq)]
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

pub fn extract_flac_metadata(reader: &mut BufReader<impl Read>) -> FlacMetadata {
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
    use std::fs::File;

    use super::*;

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
}
