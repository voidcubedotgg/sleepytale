//! Recognising a player's arrival without answering it.
//!
//! The proxy deliberately never completes a QUIC handshake of its own. A client whose
//! handshake succeeds waits indefinitely for the login flow to continue, and a client that
//! is told `ServerDisconnect` before authentication closes the connection and reports it
//! as a network error rather than showing the reason (client 0.5.7 — verified against a
//! byte-perfect `ServerDisconnect`, which it read, acted on, and did not render). Silence
//! is the one response *at that layer* the client handles well.
//!
//! It is not, however, infinitely patient: the client (Quiche under the hood) gives up
//! after about ten seconds with `QUIC handshake failed` and does not appear to auto-redial
//! — a player has to reconnect by hand. A real boot routinely takes longer than that, so
//! the ten-second window has to survive on its own; nothing about it makes a slow boot
//! safe by itself.
//!
//! A QUIC Retry looks like the missing answer here — it is sent before any handshake
//! exists, so it avoids the `ServerDisconnect` trap — but it cannot work through a relay
//! that does not terminate the handshake. `RFC 9000` requires the client to repeat the
//! Retry's token in every later Initial (§8.1.2) and to abort if the server omits
//! `retry_source_connection_id` (§7.3). Those Initials reach the *backend*, which issued
//! no token and sent no Retry, so it rejects them. A Retry with an empty token is worse
//! still: §17.2.5.2 makes the client discard it unread, which is silence dressed up as a
//! reply. This was tried and reverted.
//!
//! So the proxy answers nothing, and instead makes the client's own Initial count: it is
//! held while the backend boots and delivered the moment it is ready (see `state::wake`),
//! which needs no forged packets and no reply the proxy has no standing to send.
//!
//! The only thing the proxy needs from a sleeping port is therefore "someone is trying to
//! connect", which the shape of a QUIC Initial packet answers.

/// Does this datagram look like a client opening a QUIC v1 or v2 connection?
///
/// Long header with the fixed bit set and packet type 0 (`RFC 9000 §17.2.2`), version 1,
/// and at least the 1200 bytes a client Initial must be padded to (`§14.1`). QUIC v2
/// moves Initial to packet type 1 (`RFC 9369 §3.2`). Stray
/// datagrams and short-header packets from a connection that has already gone away are
/// rejected, so a departing player cannot wake the backend on the way out.
pub fn is_quic_initial(datagram: &[u8]) -> bool {
    const MIN_INITIAL: usize = 1200;
    const LONG_HEADER_INITIAL: u8 = 0b1100_0000;
    const QUIC_V1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
    const QUIC_V2: [u8; 4] = [0x6b, 0x33, 0x43, 0xcf];

    datagram.len() >= MIN_INITIAL
        && ((datagram[1..5] == QUIC_V1 && datagram[0] & 0b1111_0000 == LONG_HEADER_INITIAL)
            || (datagram[1..5] == QUIC_V2 && datagram[0] & 0b1111_0000 == 0b1101_0000))
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
    fn accepts_a_quic_v2_initial() {
        let mut datagram = initial();
        datagram[0] = 0xd3;
        datagram[1..5].copy_from_slice(&[0x6b, 0x33, 0x43, 0xcf]);
        assert!(is_quic_initial(&datagram));
    }

    #[test]
    fn rejects_another_quic_version() {
        let mut datagram = initial();
        datagram[1..5].copy_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        assert!(!is_quic_initial(&datagram));
    }

    #[test]
    fn rejects_an_undersized_datagram() {
        let datagram = initial();
        assert!(!is_quic_initial(&datagram[..1199]));
        assert!(!is_quic_initial(b""));
    }
}
