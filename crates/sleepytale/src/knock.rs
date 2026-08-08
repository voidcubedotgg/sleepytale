//! Recognising a player's arrival without answering it.
//!
//! The proxy deliberately never completes a QUIC handshake of its own. A client whose
//! handshake succeeds waits indefinitely for the login flow to continue, and a client that
//! is told `ServerDisconnect` before authentication closes the connection and reports it
//! as a network error rather than showing the reason (client 0.5.7 — verified against a
//! byte-perfect `ServerDisconnect`, which it read, acted on, and did not render). Silence
//! is the one response the client handles well: it times out after ten seconds and dials
//! again, and its retransmitted Initials land on the relay as soon as the backend is up.
//!
//! So the only thing the proxy needs from a sleeping port is "someone is trying to
//! connect", which the shape of a QUIC Initial packet answers.

/// Does this datagram look like a client opening a QUIC v1 connection?
///
/// Long header with the fixed bit set and packet type 0 (`RFC 9000 §17.2.2`), version 1,
/// and at least the 1200 bytes a client Initial must be padded to (`§14.1`). Stray
/// datagrams and short-header packets from a connection that has already gone away are
/// rejected, so a departing player cannot wake the backend on the way out.
pub fn is_quic_initial(datagram: &[u8]) -> bool {
    const MIN_INITIAL: usize = 1200;
    const LONG_HEADER_INITIAL: u8 = 0b1100_0000;
    const QUIC_V1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

    datagram.len() >= MIN_INITIAL
        && datagram[0] & 0b1111_0000 == LONG_HEADER_INITIAL
        && datagram[1..5] == QUIC_V1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initial() -> Vec<u8> {
        let mut datagram = vec![0u8; 1200];
        datagram[0] = 0xc3; // long header, fixed bit, Initial, 4-byte packet number
        datagram[1..5].copy_from_slice(&[0, 0, 0, 1]);
        datagram
    }

    #[test]
    fn accepts_a_client_initial() {
        assert!(is_quic_initial(&initial()));
    }

    #[test]
    fn rejects_a_short_header_packet() {
        // What a live connection's traffic looks like: the high bit is clear.
        let mut datagram = initial();
        datagram[0] = 0x40;
        assert!(!is_quic_initial(&datagram));
    }

    #[test]
    fn rejects_handshake_and_zero_rtt_long_headers() {
        for packet_type in [0b1101_0000, 0b1110_0000, 0b1111_0000] {
            let mut datagram = initial();
            datagram[0] = packet_type;
            assert!(!is_quic_initial(&datagram), "type bits {packet_type:08b}");
        }
    }

    #[test]
    fn rejects_another_quic_version() {
        let mut datagram = initial();
        datagram[1..5].copy_from_slice(&[0x6b, 0x33, 0x43, 0xcf]); // a version-negotiation probe
        assert!(!is_quic_initial(&datagram));
    }

    #[test]
    fn rejects_an_undersized_datagram() {
        let datagram = initial();
        assert!(!is_quic_initial(&datagram[..1199]));
        assert!(!is_quic_initial(b""));
    }
}
