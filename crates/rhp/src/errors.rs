// SPDX-License-Identifier: LGPL-3.0-or-later
//
// RHPv2 errCode -> POSIX errno mapping.
//
// The mapping is defined by the pdn-libax25 spec so the interposer can surface
// meaningful errno values to unmodified apps. RHP error codes are documented in
// rhp2lib-net/docs/protocol.md (PWP-0222 / PWP-0245).

/// Map an RHPv2 `errCode` to a POSIX errno value.
///
/// Codes not listed map to `EIO`. `0` (Ok) maps to `0`.
pub fn errcode_to_errno(errcode: i64) -> i32 {
    match errcode {
        0 => 0,                       // Ok
        3 => libc::EBADF,             // Invalid handle
        6 => libc::EADDRNOTAVAIL,     // Invalid local address
        7 => libc::EINVAL,            // Invalid remote address
        8 => libc::EAFNOSUPPORT,      // Bad or missing family
        9 => libc::EADDRINUSE,        // Duplicate socket
        14 => libc::EACCES,           // Unauthorised
        15 => libc::EHOSTUNREACH,     // No route
        16 => libc::EOPNOTSUPP,       // Operation not supported
        17 => libc::ENOTCONN,         // Not connected
        12 => libc::EINVAL,           // Bad parameter
        _ => libc::EIO,
    }
}

/// Convenience: a human-readable name for a few common codes (diagnostics only).
pub fn errcode_name(errcode: i64) -> &'static str {
    match errcode {
        0 => "Ok",
        3 => "Invalid handle",
        6 => "Invalid local address",
        7 => "Invalid remote address",
        8 => "Bad or missing family",
        9 => "Duplicate socket",
        12 => "Bad parameter",
        14 => "Unauthorised",
        15 => "No route",
        16 => "Operation not supported",
        17 => "Not connected",
        _ => "Unspecified",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_codes() {
        assert_eq!(errcode_to_errno(0), 0);
        assert_eq!(errcode_to_errno(3), libc::EBADF);
        assert_eq!(errcode_to_errno(8), libc::EAFNOSUPPORT);
        assert_eq!(errcode_to_errno(17), libc::ENOTCONN);
    }

    #[test]
    fn unknown_codes_map_to_eio() {
        assert_eq!(errcode_to_errno(9999), libc::EIO);
        assert_eq!(errcode_to_errno(1), libc::EIO); // Unspecified
    }
}
