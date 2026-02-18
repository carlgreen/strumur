mod advertise;
mod collection;
mod flac;
mod media_server;
mod search_parser;

use std::env;
use std::fs::File;
use std::fs::read_to_string;
use std::io::ErrorKind;
use std::io::Result;
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::process;

use get_if_addrs::IfAddr;
use log::{Level, info};
use stderrlog::Timestamp;
use uuid::Uuid;

use crate::collection::Collection;

const DEVICEID_FILE: &str = ".deviceid";

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let config = Config::parse(&args).unwrap_or_else(|err| {
        println!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    stderrlog::new()
        .module(module_path!())
        .verbosity(Level::Debug)
        .timestamp(Timestamp::Second)
        .init()
        .unwrap();

    let device_uuid = match get_device_uuid(DEVICEID_FILE) {
        Ok(device_uuid) => device_uuid,
        Err(err) => panic!("{err}"),
    };

    let collection = Collection::populate(&config.location);

    let server_ip = {
        // start with localhost to use if nothing else is found
        let mut ip = Ipv4Addr::LOCALHOST;
        for iface in get_if_addrs::get_if_addrs().expect("could not get network interfaces") {
            match iface.addr {
                IfAddr::V4(addr) => {
                    if !addr.is_loopback() {
                        // this will do
                        ip = addr.ip;
                        break;
                    }
                }
                IfAddr::V6(_) => {
                    // ignore IPv6 for now
                }
            }
        }
        ip
    };
    let server = SocketAddrV4::new(server_ip, 7878);

    media_server::listen(device_uuid, server, collection);

    advertise::advertisement_loop(device_uuid, server)
}

struct Config {
    location: String,
}

impl Config {
    fn parse(args: &[String]) -> std::result::Result<Self, &'static str> {
        let location = args
            .get(1)
            .ok_or("required argument missing: collection location")?
            .clone();

        Ok(Self { location })
    }
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
                write!(f, "could not read device id: {err}")
            }
        }
    }
}

impl From<std::io::Error> for DeviceUuidError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl std::error::Error for DeviceUuidError {}

// TODO this file should probably be somewhere appropriate
fn get_device_uuid(deviceid_file: &str) -> std::result::Result<Uuid, DeviceUuidError> {
    match read_to_string(deviceid_file) {
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
                let mut file = File::create(deviceid_file)?;
                file.write_all(device_uuid.to_string().as_bytes())?;
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
    use std::fs;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_get_device_uuid() {
        let deviceid_file = NamedTempFile::new().expect("could not create a temporary file");
        fs::remove_file(deviceid_file.path()).expect("could not remove temp file");

        // first run it shouldn't be there but should create something
        let uuid = get_device_uuid(deviceid_file.path().to_str().unwrap())
            .expect("should create a new uuid");

        // second run it should be the same by loading it, not by chance. i'll take my chances
        let repeat_uuid = get_device_uuid(deviceid_file.path().to_str().unwrap())
            .expect("should return the uuid");

        assert_eq!(uuid, repeat_uuid);
    }

    #[test]
    fn test_get_device_uuid_corrupted() {
        let mut deviceid_file = NamedTempFile::new().expect("could not create a temporary file");

        let bad_uuid = "19fbe566-fadf-4e49-bd26-534e67e7ef2x".to_string();

        write!(deviceid_file, "{bad_uuid}").expect("could not write test data");

        let err = get_device_uuid(deviceid_file.path().to_str().unwrap())
            .expect_err("should fail to parse");
        if let DeviceUuidError::InvalidDeviceId(s, _) = err {
            assert_eq!(s, bad_uuid);
        } else {
            panic!("Expected DeviceUuidError");
        }
    }
}
