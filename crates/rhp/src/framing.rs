// SPDX-License-Identifier: LGPL-3.0-or-later
//
// RHPv2 framing: a 2-byte big-endian length prefix followed by that many bytes
// of UTF-8 JSON. Maximum frame body is 65535 bytes.

use std::io::{self, Read, Write};

/// Maximum RHPv2 frame body size (the 16-bit length prefix ceiling).
pub const MAX_FRAME: usize = u16::MAX as usize;

/// Write one framed message: 2-byte big-endian length, then `payload`.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("RHP frame too large: {} > {}", payload.len(), MAX_FRAME),
        ));
    }
    let len = (payload.len() as u16).to_be_bytes();
    w.write_all(&len)?;
    w.write_all(payload)?;
    w.flush()
}

/// Read one framed message. Returns `Ok(None)` on a clean end of stream (EOF at
/// a frame boundary), `Ok(Some(bytes))` for a full frame body, or an error.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 2];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_round_trips() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"type\":\"ping\"}").unwrap();
        // 2-byte length prefix present and big-endian.
        assert_eq!(&buf[0..2], &[0x00, 0x0F]);
        let mut cursor = io::Cursor::new(buf);
        let frame = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(frame, b"{\"type\":\"ping\"}");
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut cursor = io::Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn oversize_payload_is_rejected() {
        let mut buf = Vec::new();
        let big = vec![0u8; MAX_FRAME + 1];
        assert!(write_frame(&mut buf, &big).is_err());
    }
}
