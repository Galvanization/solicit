use super::super::StreamId;
use super::frames::{
    Frame,
    Flag,
    RawFrame,
    FrameHeader,
    pack_header
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
pub enum PingFlag {
    Ack = 0x1,
}

impl Flag for PingFlag {
    #[inline]
    fn bitmask(&self) -> u8 {
        *self as u8
    }
}

/// A struct representing the PING frames of HTTP/2, as defined in the HTTP/2
/// spec, section 6.1.
#[derive(PartialEq)]
#[derive(Debug)]
pub struct PingFrame {
    /// The data found in the frame as an opaque byte sequence. It never
    /// includes padding bytes.
    pub data: Vec<u8>,
    /// Represents the flags currently set on the `PingFrame`, packed into a
    /// single byte.
    flags: u8,
}

impl PingFrame {
    /// Creates a new empty `PingFrame`, associated to the connection
    pub fn new() -> PingFrame {
        PingFrame {
            // No data stored in the frame yet
            data: Vec::new(),
            // All flags unset by default
            flags: 0,
        }
    }

    /// A convenience constructor that returns a `PingFrame` with the ACK
    /// flag already set and no data.
    pub fn new_ack() -> PingFrame {
        PingFrame {
            data: Vec::new(),
            flags: PingFlag::Ack.bitmask(),
        }
    }

    /// Sets the ACK flag for the frame. This method is just a convenience
    /// method for calling `frame.set_flag(PingFlag::Ack)`.
    pub fn set_ack(&mut self) {
        self.set_flag(PingFlag::Ack)
    }

    /// Checks whether the `PingFrame` has an ACK flag attached to it.
    pub fn is_ack(&self) -> bool {
        self.is_set(PingFlag::Ack)
    }

    /// Returns the total length of the payload in bytes
    fn payload_len(&self) -> u32 {
        self.data.len() as u32
    }

    /// Parses the given slice as a PING frame's payload.
    ///
    /// # Returns
    ///
    /// A `Vec` of opaque data
    ///
    /// If the payload was invalid (i.e. the length of the payload is
    /// not 8 octets long, returns `None`
    fn parse_payload(payload: &[u8]) -> Option<(Vec<u8>)> {
        if payload.len() != 8 {
            return None;
        }
        let data = payload;

        Some(data.to_vec())
    }
}

impl Frame for PingFrame {
    /// The type that represents the flags that the particular `Frame` can take.
    /// This makes sure that only valid `Flag`s are used with each `Frame`.
    type FlagType = PingFlag;

    /// Creates a new `PingFrame` with the given `RawFrame` (i.e. header and payload),
    /// if possible.
    ///
    /// # Returns
    ///
    /// `None` if a valid `PingFrame` cannot be contructed from the given
    /// `RawFrame`. The stream ID *MUST* be 0 in order for the frame to be
    /// valid. If the `ACK` flag is set, there *MUST NOT* be a payload. The total
    /// payload length must be 8 bytes long.
    ///
    /// Otherwise, returns a newly constructed `PingFrame`.
    fn from_raw(raw_frame: RawFrame) -> Option<PingFrame> {
        // Unpack the header
        let (len, frame_type, flags, stream_id) = raw_frame.header;
        // Check that the frame type is correct for this fram implementation
        if frame_type != 0x6 {
            return None;
        }
        // Check that the length given in the header mathes the payload
        // length; if not, something went wrong and we do not consider this a
        // valid frame.
        if (len as usize) != raw_frame.payload.len() {
            return None;
        }
        // Check that the PING frame is associated to stream 0
        if stream_id != 0 {
            return None;
        }
        if (flags & PingFlag::Ack.bitmask()) != 0 {
            if len != 0 {
                // The PING flag MUST NOT have a payload if Ack is set
                return None;
            } else {
                // Ack is set and there's no payload => just an Ack frame
                return Some(PingFrame {
                    data: Vec::new(),
                    flags: flags,
                });
            }
        }

        match PingFrame::parse_payload(&raw_frame.payload) {
            Some(data) => {
                // The data extracted
                Some(PingFrame {
                    flags: flags,
                    data: data,
                })
            }
            None => None,
        }
    }

    /// Tests if the given flag is set for the frame.
    fn is_set(&self, flag: PingFlag) -> bool {
        (self.flags & flag.bitmask()) != 0
    }

    /// Returns the `StreamId` of the stream to which the frame is associated.
    ///
    /// A `PingFrame` always has to be associated to stream `0`.
    fn get_stream_id(&self) -> StreamId {
        0
    }

    /// Returns a `FrameHeader` based on the current state of the `Frame`.
    fn get_header(&self) -> FrameHeader {
        (self.payload_len(), 0x6, self.flags, 0)
    }

    /// Sets the given flag for the frame.
    fn set_flag(&mut self, flag: PingFlag) {
        self.flags |= flag.bitmask();
    }

    /// Returns a `Vec` with the serialized representation of the frame.
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.payload_len() as usize);
        // First the header
        buf.extend(pack_header(&self.get_header()).to_vec().into_iter());
        // now the body
        buf.extend(self.data.clone().into_iter());

        buf
    }

}

#[cfg(test)]
mod tests {
    use super::super::frames::{Frame, RawFrame, pack_header};
    use super::super::test::{build_test_frame};
    use super::{PingFlag, PingFrame};

    /// Tests that the `PingFrame` correctly handles a PING frame with
    /// no ACK flag and a payload
    #[test]
    fn test_ping_frame_parse_no_ack() {
        let payload = [0, 0, 0, 0, 1, 0, 0, 0];
        // A header with no ACK flag
        let header = (payload.len() as u32, 6, 0, 0);

        let frame = build_test_frame::<PingFrame>(&header, &payload);

        assert_eq!(frame.get_header(), header);
    }

    /// Tests that the `PingFrame` correctly handles a PING frame which
    /// was not associated to stream 0 by returning an error.
    #[test]
    fn test_ping_frame_parse_not_stream_zero() {
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8];
        // Header indicates that it is associated to stream 1
        let header = (payload.len() as u32, 6, 0, 1);

        let frame: Option<PingFrame> = Frame::from_raw(
            RawFrame::with_payload(header, payload));

        assert!(frame.is_none());
    }

    /// Tests that the `PingFrame` correctly handles a PING frame which
    /// does not have a payload of 8 bytes
    #[test]
    fn test_ping_frame_parse_not_eight_bytes() {
        let payload = vec![2, 4, 6, 8];

        let header = (payload.len() as u32, 6, 0, 0);

        let frame: Option<PingFrame> = Frame::from_raw(
            RawFrame::with_payload(header, payload)
        );

        assert!(frame.is_none());
    }

    /// Tests that a `PingFrame` gets correctly serialized when it contains
    /// a payload and ACK.
    #[test]
    fn test_ping_frame_serialize_payload_ack() {
        let mut frame = PingFrame::new_ack();
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
        frame.data = data.clone();
        let expected = {
            let headers = pack_header(&(8, 6, 1, 0));
            let mut res: Vec<u8> = Vec::new();
            res.extend(headers.to_vec().into_iter());
            res.extend(data.into_iter());

            res
        };

        let serialized = frame.serialize();

        assert_eq!(serialized, expected);
    }
}























