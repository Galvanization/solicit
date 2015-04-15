use super::super::StreamId;
use super::frames::{
    Frame,
    Flag,
    pack_header,
    RawFrame,
    FrameHeader
};

/// An enum representing the flags that a `PingFrame` can have.
/// The integer representation associated to each variant is that flag's
/// bitmask.
///
/// HTTP/2 spec, section 6.
#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Copy)]
pub enum NoFlag {
    None = 0x0,
}

impl Flag for NoFlag {
    #[inline]
    fn bitmask(&self) -> u8 {
        *self as u8
    }
}

/// The struct represents the dependency information that can be attached to a stream
/// and sent within HEADERS frame
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Clone)]
pub struct StreamDependency {
    /// The ID of the stream that a particular stream depends on
    pub stream_id: StreamId,
    /// The weight for the stream. The value exposed (and set) here is always
    /// in the range [0, 255], instead of [1, 256] so that the value fits
    /// into a `u8`.
    pub weight: u8,
    /// A flag indicating whether the stream dependency is exclusive.
    pub is_exclusive: bool,
}

impl StreamDependency {
    /// Creates a new `StreamDependency` with the given stream Id, weight, and
    /// exclusivity.
    pub fn new(stream_id: StreamId, weight: u8, is_exclusive: bool)
            -> StreamDependency {
        StreamDependency {
            stream_id: stream_id,
            weight: weight,
            is_exclusive: is_exclusive,
        }
    }

    /// Parses the 5-byte length frame
    ///
    /// # Panics
    ///
    /// If the frame is less than 5 bytes, the method will panic
    pub fn parse(buf: &[u8]) -> StreamDependency {
        // The most significant bit of the first byte is the "E" bit indicating
        // whether the dependency is exclusive.
        let is_exclusive = buf[0] & 0x80 != 0;
        let stream_id = {
            // Parse the first 4 bytes into a u32
            let mut id = unpack_octets_4!(buf, 0, u32);
            // and clear the first bit since the stream id is only 31 bits.
            id &= !(1 << 31);
            id
        };

        StreamDependency {
            stream_id: stream_id,
            weight: buf[4],
            is_exclusive: is_exclusive,
        }
    }

    /// Serializes the `StreamDependency` into a 5-byte buffer representing the
    /// dependency description.
    pub fn serialize(&self) -> [u8; 5] {
        let e_bit = if self.is_exclusive {
            1 << 7
        } else {
            0
        };
        [
            (((self.stream_id >> 24) & 0x000000FF) as u8) | e_bit,
            (((self.stream_id >> 16) & 0x000000FF) as u8),
            (((self.stream_id >>  8) & 0x000000FF) as u8),
            (((self.stream_id >>  0) & 0x000000FF) as u8),
            self.weight,
        ]
    }
}

/// A struct representing the PRIORITY frmas of HTTP/2
#[derive(PartialEq)]
#[derive(Debug)]
pub struct PriorityFrame {
    /// The id of the stream with which this frame is associated
    pub stream_id: StreamId,
    /// The stream dependency information
    pub stream_dep: StreamDependency,
}

impl PriorityFrame {
    pub fn new(stream_id: StreamId, stream_dep: StreamDependency)
            -> PriorityFrame {
        PriorityFrame {
            stream_id: stream_id,
            stream_dep: stream_dep,
        }
    }

    /// Returns the length of the payload of the current frame
    /// Priority frame must be 5 octets
    fn payload_len(&self) -> u32 {
        5
    }
}

impl Frame for PriorityFrame {
    /// `Priority` frame does not take a flag
    type FlagType = NoFlag;

    /// Creates a new `PriorityFrame` with the given `RawFrame` (i.e. header and
    /// payload), if possible.
    ///
    /// # Returns
    ///
    /// `None` if a valid `PriorityFrame` cannot be constructed from the given
    /// `RawFrame`. The stream ID *MUST NOT* be 0.
    ///
    /// Otherwise, returns a newly contructed `PriorityFrame`
    fn from_raw(raw_frame: RawFrame) -> Option<PriorityFrame> {
        // Unpack the header
        let (len, frame_type, flags, stream_id) = raw_frame.header;
        // Check that the frame type is correct for this frame implementation
        if frame_type != 0x2 {
            return None;
        }
        // Check that the length given in the header matches the payload
        // if not, soemthing went wrong and we do not consider this as
        // a valid frame.
        if (len as usize) != raw_frame.payload.len() {
            return None;
        }
        // Check that the length of the payload is 5 bytes
        // If not, this is not a valid frame
        if raw_frame.payload.len() != 5 {
            return None;
        }
        // Check that the PRIORITY frame is not associated to stream 0
        // If it is, this is not a valid frame
        if stream_id == 0 {
            return None;
        }
        // Extract the stream dependecy info from the payload
        let stream_dep = StreamDependency::parse(&raw_frame.payload);

        Some(PriorityFrame {
            stream_id: stream_id,
            stream_dep: stream_dep,
        })
    }

    /// `Priority` frame does not set any flags
    fn is_set(&self, flag: NoFlag) -> bool {
        true
    }

    /// Returns the `StreamId` of the stream to which the frame is associated
    ///
    fn get_stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Returns a `FrameHeader` based on the current state of the `Frame`.
    fn get_header(&self) -> FrameHeader {
        (self.payload_len(), 0x2, 0, self.stream_id)
    }

    /// `PriorityFrame` does not set any flags
    fn set_flag(&mut self, flag: NoFlag) {
    }

    /// Returns a `Vec` with the serialized representation of the frame.
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.payload_len() as usize);
        // The header
        buf.extend(pack_header(&self.get_header()).to_vec().into_iter());
        // and then the body
        buf.extend(self.stream_dep.serialize().to_vec().into_iter());

        buf
    }
}

