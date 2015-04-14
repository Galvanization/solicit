//! The module contains the implementation of HTTP/2 frames.

/// A helper macro that unpacks a sequence of 4 bytes found in the buffer with
/// the given identifier, starting at the given offset, into the given integer
/// type. Obviously, the integer type should be able to support at least 4
/// bytes.
///
/// # Examples
///
/// ```rust
/// let buf: [u8; 4] = [0, 0, 0, 1];
/// assert_eq!(1u32, unpack_octets_4!(buf, 0, u32));
/// ```
macro_rules! unpack_octets_4 {
    ($buf:ident, $offset:expr, $tip:ty) => (
        (($buf[$offset + 0] as $tip) << 24) |
        (($buf[$offset + 1] as $tip) << 16) |
        (($buf[$offset + 2] as $tip) <<  8) |
        (($buf[$offset + 3] as $tip) <<  0)
    );
}

pub use self::frames::{
    Frame,
    Flag,
    parse_padded_payload,
    unpack_header,
    pack_header,
    RawFrame,
    FrameHeader
};
pub use self::dataframe::{
    DataFlag,
    DataFrame,
};
pub use self::settingsframe::{
    HttpSetting,
    SettingsFlag,
    SettingsFrame
};
pub use self::headersframe::{
    HeadersFlag,
    StreamDependency,
    HeadersFrame
};
pub use self::pingframe::{
    PingFlag,
    PingFrame
};
pub use self::rststreamframe::{
    ErrorFlag,
    RstStreamFrame,
}
pub use self::frames::*;
//use self::testconfig::*;
pub use self::dataframe::*;
pub use self::settingsframe::*;
pub use self::headersframe::*;
pub use self::rststreamframe::*;

pub mod frames;
mod test;
pub mod dataframe;
pub mod settingsframe;
pub mod headersframe;
pub mod pingframe;
pub mod rststreamframe;
