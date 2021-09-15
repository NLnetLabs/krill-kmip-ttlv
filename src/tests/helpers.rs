use std::io::Read;

use crate::Config; // for .take()

pub(crate) fn no_response_size_limit() -> Config {
    Config::default()
}

pub(crate) fn reject_if_response_larger_than(max_bytes: u32) -> Config {
    Config::default().with_max_bytes(max_bytes)
}

pub(crate) fn make_reader(bytes: Vec<u8>) -> impl std::io::Read {
    std::io::Cursor::new(bytes)
}

pub(crate) fn make_limited_reader(bytes: Vec<u8>, max_bytes: u64) -> impl std::io::Read {
    std::io::Cursor::new(bytes).take(max_bytes)
}
