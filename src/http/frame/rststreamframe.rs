use super::super::StreamId;
use super::frames::{
    Frame,
    Flag,
    RawFrame,
    FrameHeader,
    pack_header,
};

/// 6.4.  RST_STREAM
///
///    The RST_STREAM frame (type=0x3) allows for immediate termination of a
///    stream.  RST_STREAM is sent to request cancellation of a stream, or
///    to indicate that an error condition has occurred.
///
///    The RST_STREAM frame contains a single unsigned, 32-bit integer
///    identifying the error code (Section 7).  The error code indicates why
///    the stream is being terminated.
///
///    The RST_STREAM frame does not define any flags.
///
///    The RST_STREAM frame fully terminates the referenced stream and
///    causes it to enter the closed state.  After receiving a RST_STREAM on
///    a stream, the receiver MUST NOT send additional frames for that
///    stream, with the exception of PRIORITY.  However, after sending the
///    RST_STREAM, the sending endpoint MUST be prepared to receive and
///    process additional frames sent on the stream that might have been
///    sent by the peer prior to the arrival of the RST_STREAM.
///
///    RST_STREAM frames MUST be associated with a stream.  If a RST_STREAM
///    frame is received with a stream identifier of 0x0, the recipient MUST
///    treat this as a connection error (Section 5.4.1) of type
///    PROTOCOL_ERROR.
///
///    RST_STREAM frames MUST NOT be sent for a stream in the "idle" state.
///    If a RST_STREAM frame identifying an idle stream is received, the
///    recipient MUST treat this as a connection error (Section 5.4.1) of
///    type PROTOCOL_ERROR.
///
///    A RST_STREAM frame with a length other than 4 octets MUST be treated
///    as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR.

#[derive(PartialEq)]
#[derive(Debug)]
pub struct RstStreamFrame {
    pub stream_id: StreamId,
    pub error_code: u32,
    flags: u8,
}

///An enum representing the possible error codes passed by an RST_STREAM frame, all identified by
///a single unsigned, 32-bit integer
pub enum Errors {
    NO_ERROR = 0x0,
    PROTOCOL_ERROR = 0x1,
    INTERNAL_ERROR = 0x2,
    FLOW_CONTROL_ERROR = 0x3,
    SETTINGS_TIMEOUT = 0x4,
    STREAM_CLOSED = 0x5,
    FRAME_SIZE_ERROR = 0x6,
    REFUSED_STREAM = 0x7,
    CANCEL = 0x8,
    COMPRESSION_ERROR = 0x9,
    CONNECT_ERROR = 0xa,
    ENHANCE_YOUR_CALM = 0xb,
    INADEQUATE_SECURITY = 0xc,
    HTTP_1_1_REQUIRED = 0xd,
}

impl Errors {
    /// Creates a new `Error` with the correct variant corresponding to
    /// the given value, based on the error codes defined in section 7

    pub fn from_val(val: u32) -> Option<Errors> {
        match val {
            0x0 => Some(Errors::NO_ERROR),
            0x1 => Some(Errors::PROTOCOL_ERROR),
            0x2 => Some(Errors::INTERNAL_ERROR),
            0x3 => Some(Errors::FLOW_CONTROL_ERROR),
            0x4 => Some(Errors::SETTINGS_TIMEOUT),
            0x5 => Some(Errors::STREAM_CLOSED),
            0x6 => Some(Errors::FRAME_SIZE_ERROR),
            0x7 => Some(Errors::REFUSED_STREAM),
            0x8 => Some(Errors::CANCEL),
            0x9 => Some(Errors::COMPRESSION_ERROR),
            0xa => Some(Errors::CONNECT_ERROR),
            0xb => Some(Errors::ENHANCE_YOUR_CALM),
            0xc => Some(Errors::INADEQUATE_SECURITY),
            0xd => Some(Errors::HTTP_1_1_REQUIRED),
            _ => None,
        }
    }

    fn parse_error(raw_error: &[u8]) -> Option<Errors> {
        let val: u32 = unpack_octets_4!(raw_error, 0, u32);

        Errors::from_val(val)
    }

}

///This implementation is rather sparse because the RstStreamFrame has no flags and the payload length is always a single u32
impl RstStreamFrame {
    /// Creates a new `RstStreamFrame` with no error code set
    pub fn new(stream_id: StreamId) -> RstStreamFrame {
        RstStreamFrame {
            stream_id: stream_id,
            error_code: 0, //should this be 0x0?
            flags: 0,
        }
    }

    /// Creates a new 'RstStreamFrame' with error code passed in and set
    pub fn with_error(stream_id: StreamId, error: u32) -> RstStreamFrame {
        RstStreamFrame {
            stream_id: stream_id,
            error_code: error,
            flags: 0,
        }
    }

    ///Sets the error code for a new 'RstStreamFrame'
    pub fn set_error(&mut self, error: u32) {
        self.error_code = error;
    }

    /// Parses the given buffer, considering it a representation of a RstStreamFrame
    /// payload.
    ///
    /// # Returns
    ///
    /// A single u32
    ///
    /// Any unknown error is ignored, as per the HTTP/2 spec requirement.
    ///
    /// If the frame is invalid (i.e. the length of the payload is not a
    /// u32) it returns `None`.
    fn parse_payload(payload: &[u8]) -> Option<Errors> {
        if payload.len() != 4 {
            //I'm not sure where this should return None or something else, following the trend from other frames
            return None;
        }

        // The payload has already been checked to insure a length of 4 octets,
        // since it is a known length we do not have to chunk, just unpack the buffer into a u32
        Errors::parse_error(payload)
    }
}

#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Copy)]
pub enum ErrorFlag {
    EndStream = 0x1,
    Padded = 0x8,
}

impl Flag for ErrorFlag {
    #[inline]
    fn bitmask(&self) -> u8 {
        *self as u8
    }
}

impl Frame for RstStreamFrame {

    type FlagType = ErrorFlag;

    /// Tests if the given flag is set for the frame.
    fn is_set(&self, flag: ErrorFlag) -> bool {
        (self.flags & flag.bitmask()) != 0
    }

    /// Sets the given flag for the frame.
    fn set_flag(&mut self, flag: ErrorFlag) {
        self.flags |= flag.bitmask();
    }

    /// Creates a new `RstStreamFrame` from the given `RawFrame` (i.e. header and
    /// payload), if possible.  Returns `None` if a valid `RstStreamFrame` cannot be
    /// constructed from the given `RawFrame`.
    fn from_raw(raw_frame: RawFrame) -> Option<RstStreamFrame> {
        // Unpack the header
        let (len, frame_type, flags, stream_id) = raw_frame.header;
        // Check that the frame type is correct for this frame implementation
        if frame_type != 0x3 {
            return None;
        }
        // Check that the length given in the header matches the payload
        // length; if not, something went wrong and we do not consider this a
        // valid frame.
        if (len as usize) != raw_frame.payload.len() {
            return None;
        }
        // A 'RstStreamFrame' frame cannot be associated to the connection itself.
        if stream_id == 0x0 {
            return None;
        }
        //Very basic, taking the raw frame's payload and converting it to an error BUT return u32 or error?
        let payload = raw_frame.payload;
        let error: u32 = unpack_octets_4!(payload, 0, u32);
        
        Some(RstStreamFrame {
            stream_id: stream_id,
            error_code: error,
            flags: 0,
        })
    }

    /// Returns the `StreamId` of the stream to which the frame is associated.
    fn get_stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Returns a `FrameHeader` based on the current state of the frame.
    fn get_header(&self) -> FrameHeader {
        (4, 0x0, self.flags, self.stream_id)
    }

    /// Returns a `Vec` with the serialized representation of the frame.
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(13 as usize);
        // First the header...
        buf.extend(pack_header(&self.get_header()).to_vec().into_iter());
        // No padding in an 'RstStreamFrame' so straight to payload
        let error = [(((self.error_code >> 24) & 0x000000FF) as u8),
            (((self.error_code >> 16) & 0x000000FF) as u8),
            (((self.error_code >> 8) & 0x000000FF) as u8),
            (((self.error_code >> 0) & 0x000000FF) as u8),
            ];
        buf.extend(error.to_vec().into_iter());

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::super::frames::{Frame, RawFrame, pack_header};
    use super::{ErrorFlag, RstStreamFrame};

/// Tests that a 'RstStreamFrame' properly gets instantiated using new()
#[test]
    fn test_rst_stream_frame_creation() {
        let frame = RstStreamFrame::new(1);
        assert_eq!(frame.error_code, 0);
        assert_eq!(frame.stream_id, 1);
    }

/// Tests that a 'RstStreamFrame' properly gets instantiated using
/// with the with_error() function
#[test]
    fn test_rst_stream_frame_with_error() {
        let frame = RstStreamFrame::with_error(1, 4);
        assert_eq!(frame.error_code, 4);
        assert_eq!(frame.stream_id, 1);
    }

/// Tests that a 'RstStreamFrame' that has been created with new()
/// can have an error code added to it using set_error()
#[test]
    fn test_rst_stream_frame_set_error() {
       let mut frame = RstStreamFrame::new(1);
       frame.set_error(3);
       assert_eq!(frame.error_code, 3);
    }
}







