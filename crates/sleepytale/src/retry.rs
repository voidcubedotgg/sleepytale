//! Answering a client's QUIC Initial with a Retry while the backend is not ready.
//!
//! A Retry (`RFC 9000 §17.2.5`) is sent before any handshake state exists, so unlike
//! `ServerDisconnect` (see [`crate::knock`] for why that one backfires) it is exactly the
//! kind of reply a client's QUIC stack is built to treat as progress rather than failure:
//! "the server is here, retry with this token." It carries no session state and no
//! backend secret — the AEAD key and nonce below are the fixed QUIC v1 constants from
//! `RFC 9001 §5.8`, the same for every QUIC server on the internet — so sending one costs
//! sleepytale nothing before the backend exists to hand a connection to.
//!
//! The Retry Token this proxy issues is always empty. A real QUIC server encodes an
//! address-validation secret in the token and checks it on the client's next Initial;
//! sleepytale never does, because it never completes a handshake of its own to validate
//! anything against — the backend does that once relaying starts. An empty token is legal
//! per `RFC 9000 §17.2.5.1` and this proxy does not care what a retried Initial's token
//! contains, so there is nothing to encode.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Key, KeyInit, Nonce};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

/// Fixed AEAD key for the Retry Integrity Tag (`RFC 9001 §5.8`) — a QUIC v1 protocol
/// constant known to every implementation, not a secret sleepytale owns.
const RETRY_KEY: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// Fixed AEAD nonce for the Retry Integrity Tag (`RFC 9001 §5.8`).
const RETRY_NONCE: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

const QUIC_V1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// Length of the Source Connection ID this proxy picks for its Retry. The client echoes
/// it back as the Destination CID of its next Initial; sleepytale does not demultiplex
/// on it, so any length up to 20 bytes would do — 8 matches what the server itself uses.
const SCID_LEN: usize = 8;

/// Build a QUIC v1 Retry packet in reply to a client's Initial.
///
/// Returns `None` if the header cannot be parsed. Callers are expected to have already
/// checked [`crate::knock::is_quic_initial`], but that only inspects the first five
/// bytes — the connection ID fields still need their own bounds check.
pub fn build(initial: &[u8]) -> Option<Vec<u8>> {
    let (odcid, client_scid) = parse_ids(initial)?;
    let scid = new_scid();

    // Everything the Retry sends on the wire except the tag.
    let mut header = Vec::with_capacity(1 + 4 + 1 + client_scid.len() + 1 + scid.len());
    header.push(0b1111_0000); // long header, fixed bit, Retry type; unused bits unset
    header.extend_from_slice(&QUIC_V1);
    header.push(client_scid.len() as u8);
    header.extend_from_slice(client_scid); // the Retry's DCID echoes the client's SCID
    header.push(scid.len() as u8);
    header.extend_from_slice(&scid);
    // Retry Token: empty (see module docs).

    let tag = retry_integrity_tag(odcid, &header);
    header.extend_from_slice(&tag);
    Some(header)
}

/// Pull the Destination and Source Connection IDs out of a long-header packet.
///
/// Layout after the fixed 5-byte header (type byte + version): `DCID Len (8) || DCID ||
/// SCID Len (8) || SCID || ...`. Everything past the SCID (token, length, packet number,
/// payload) is irrelevant to building a Retry.
fn parse_ids(packet: &[u8]) -> Option<(&[u8], &[u8])> {
    const MAX_CID_LEN: usize = 20; // RFC 9000 §17.2

    let mut pos = 5;
    let dcid_len = *packet.get(pos)? as usize;
    pos += 1;
    let dcid = packet.get(pos..pos + dcid_len)?;
    pos += dcid_len;

    let scid_len = *packet.get(pos)? as usize;
    pos += 1;
    let scid = packet.get(pos..pos + scid_len)?;

    if dcid_len > MAX_CID_LEN || scid_len > MAX_CID_LEN {
        return None;
    }
    Some((dcid, scid))
}

/// A connection ID for the proxy's side of the Retry. No security or uniqueness property
/// is required of it — see the module docs — so this just needs to look plausible.
fn new_scid() -> [u8; SCID_LEN] {
    static CALLS: AtomicU64 = AtomicU64::new(0);

    let mut hasher = DefaultHasher::new();
    std::time::Instant::now().hash(&mut hasher);
    CALLS.fetch_add(1, Ordering::Relaxed).hash(&mut hasher);
    hasher.finish().to_ne_bytes()
}

/// `RFC 9001 §5.8`: AEAD_AES_128_GCM over an empty plaintext, with the Retry Pseudo-Packet
/// (the original client DCID, length-prefixed, followed by the Retry header) as
/// associated data.
fn retry_integrity_tag(odcid: &[u8], header: &[u8]) -> [u8; 16] {
    let mut aad = Vec::with_capacity(1 + odcid.len() + header.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(header);

    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&RETRY_KEY));
    let tag = cipher
        .encrypt(
            Nonce::from_slice(&RETRY_NONCE),
            Payload {
                msg: &[],
                aad: &aad,
            },
        )
        .expect("AES-128-GCM over an empty plaintext with a fixed-size key cannot fail");
    tag.try_into()
        .expect("AES-128-GCM's tag-only output for an empty plaintext is always 16 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RFC 9001 Appendix A.4`: a Retry sent for the Client Initial DCID
    /// `0x8394c8f03e515708`, with SCID `0xf067a5502a4262b5` and an empty token except for
    /// the literal bytes `"token"`. This is the RFC's own worked example, not a synthetic
    /// one, so it also happens to pin the wire format independent of `new_scid`.
    #[test]
    fn matches_the_rfc_9001_test_vector() {
        let odcid = hex("8394c8f03e515708");
        let mut header = vec![0xff];
        header.extend(hex("00000001")); // version
        header.push(0); // DCID len 0
        header.push(8); // SCID len
        header.extend(hex("f067a5502a4262b5"));
        header.extend(b"token");

        let tag = retry_integrity_tag(&odcid, &header);
        assert_eq!(hexstr(&tag), "04a265ba2eff4d829058fb3f0f2496ba");

        let mut expected_packet = header;
        expected_packet.extend_from_slice(&tag);
        assert_eq!(
            hexstr(&expected_packet),
            "ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"
        );
    }

    #[test]
    fn builds_a_well_formed_retry_for_a_synthetic_initial() {
        let initial = synthetic_initial(&hex("aabbccddeeff0011"), &hex("1122334455667788"));

        let retry = build(&initial).expect("a well-formed Initial parses");

        assert_eq!(
            retry[0] & 0b1111_0000,
            0b1111_0000,
            "long header, Retry type"
        );
        assert_eq!(&retry[1..5], &QUIC_V1);
        let scid_of_client = hex("1122334455667788");
        assert_eq!(
            retry[5] as usize,
            scid_of_client.len(),
            "DCID len echoes client SCID len"
        );
        assert_eq!(&retry[6..6 + scid_of_client.len()], &scid_of_client[..]);

        let scid_pos = 6 + scid_of_client.len();
        let scid_len = retry[scid_pos] as usize;
        assert_eq!(scid_len, SCID_LEN, "the proxy's own SCID length");
        assert_eq!(
            retry.len(),
            scid_pos + 1 + scid_len + 16,
            "header fields plus a 16-byte tag, nothing else"
        );
    }

    #[test]
    fn rejects_a_truncated_header() {
        assert!(
            build(&[0xff, 0, 0, 0, 1, 20]).is_none(),
            "DCID len claims more than is present"
        );
    }

    fn synthetic_initial(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut packet = vec![0xc3];
        packet.extend(&QUIC_V1);
        packet.push(dcid.len() as u8);
        packet.extend_from_slice(dcid);
        packet.push(scid.len() as u8);
        packet.extend_from_slice(scid);
        packet.resize(1200, 0); // pad to the minimum Initial size, like a real client would
        packet
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hexstr(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
