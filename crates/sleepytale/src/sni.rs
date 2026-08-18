//! Reading the `server_name` out of a client's first QUIC datagram.
//!
//! A QUIC Initial packet is protected with keys derived from the client's Destination
//! Connection ID and a salt published in the specification (RFC 9001, Section 5.2), so
//! anyone on the path can read it. That is what makes SNI routing possible here without
//! terminating anything: the proxy peeks at the first packet and forwards the original
//! bytes untouched, leaving QUIC and mTLS end-to-end.
//!
//! Only the first Initial packet of a datagram is examined, and only far enough to reach
//! the ClientHello's `server_name`. Anything unexpected — a short header, a version this
//! does not know, a ClientHello spread over several datagrams — returns `None`, and the
//! caller falls back to its default backend.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as _};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, Payload};
use hkdf::Hkdf;
use sha2::Sha256;

/// QUIC v1 (RFC 9000) and v2 (RFC 9369). Versions differ in their salt, their key labels
/// and how they number packet types, so each one has to be spelled out.
const V1: u32 = 0x0000_0001;
const V2: u32 = 0x6b33_43cf;

/// RFC 9001, Section 5.2.
const V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9369, Section 3.3.1.
const V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// A connection ID is at most 20 bytes in both versions.
const MAX_CID: usize = 20;

/// AEAD_AES_128_GCM's tag.
const TAG: usize = 16;

/// The bytes header protection samples, and the AES block size it feeds.
const SAMPLE: usize = 16;

/// A hostname is at most 253 characters; anything longer is not a name we could route.
const MAX_SERVER_NAME: usize = 253;

/// The `server_name` a client offered in its ClientHello.
///
/// `None` whenever this datagram is not an Initial packet whose ClientHello can be read
/// whole, which includes every datagram after the first of a connection.
pub fn peek_server_name(datagram: &[u8]) -> Option<String> {
    let (version, dcid, pn_offset, length) = parse_long_header(datagram)?;
    let keys = Keys::initial(version, dcid)?;
    let plaintext = keys.open(datagram, pn_offset, length)?;
    let crypto = reassemble_crypto(&plaintext)?;
    client_hello_server_name(&crypto)
}

/// Split a long header up to its packet number, which stays protected until [`Keys::open`].
///
/// Returns the version, the Destination Connection ID, the offset of the packet number,
/// and the byte count the Length field covers.
fn parse_long_header(datagram: &[u8]) -> Option<(u32, &[u8], usize, usize)> {
    let mut r = Reader::new(datagram);
    let first = r.u8()?;
    // Long header with the fixed bit set. QUIC bit greasing (RFC 9287) can clear the
    // fixed bit, but only once a connection is established, never on an Initial.
    if first & 0xc0 != 0xc0 {
        return None;
    }

    let version = r.u32()?;
    let initial_type = match version {
        V1 => 0,
        V2 => 1,
        _ => return None,
    };
    if (first & 0x30) >> 4 != initial_type {
        return None;
    }

    let dcid = r.cid()?;
    let _scid = r.cid()?;
    let token_len = r.varint()?;
    r.skip(usize::try_from(token_len).ok()?)?;

    let length = usize::try_from(r.varint()?).ok()?;
    let pn_offset = r.position();
    // The packet number is 1..=4 bytes of the length, so anything shorter than a sample
    // plus a tag cannot be a whole packet.
    if length < SAMPLE + TAG || datagram.len() < pn_offset + length {
        return None;
    }

    Some((version, dcid, pn_offset, length))
}

/// Initial keys for the client's side of a connection.
struct Keys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

impl Keys {
    /// Derive the client's Initial secret from the Destination Connection ID.
    fn initial(version: u32, dcid: &[u8]) -> Option<Self> {
        let (salt, key_label, iv_label, hp_label): (&[u8], &[u8], &[u8], &[u8]) = match version {
            V1 => (&V1_SALT, b"quic key", b"quic iv", b"quic hp"),
            V2 => (&V2_SALT, b"quicv2 key", b"quicv2 iv", b"quicv2 hp"),
            _ => return None,
        };

        let initial = Hkdf::<Sha256>::new(Some(salt), dcid);
        let mut client_initial = [0u8; 32];
        expand_label(&initial, b"client in", &mut client_initial)?;

        let client = Hkdf::<Sha256>::from_prk(&client_initial).ok()?;
        let mut keys = Self {
            key: [0u8; 16],
            iv: [0u8; 12],
            hp: [0u8; 16],
        };
        expand_label(&client, key_label, &mut keys.key)?;
        expand_label(&client, iv_label, &mut keys.iv)?;
        expand_label(&client, hp_label, &mut keys.hp)?;
        Some(keys)
    }

    /// Remove header protection, then decrypt the packet payload.
    fn open(&self, datagram: &[u8], pn_offset: usize, length: usize) -> Option<Vec<u8>> {
        // The sample starts four bytes past the packet number, as if it were always the
        // maximum four bytes long.
        let sample_at = pn_offset + 4;
        let sample = datagram.get(sample_at..sample_at + SAMPLE)?;

        let mut mask = [0u8; SAMPLE];
        mask.copy_from_slice(sample);
        Aes128::new_from_slice(&self.hp)
            .ok()?
            .encrypt_block((&mut mask).into());

        let first = datagram[0] ^ (mask[0] & 0x0f);
        let pn_len = usize::from(first & 0x03) + 1;

        // Rebuild the header with the packet number in the clear: it is the AEAD's
        // associated data, so it has to match byte for byte.
        let mut header = datagram.get(..pn_offset + pn_len)?.to_vec();
        header[0] = first;
        let mut packet_number = 0u64;
        for (i, byte) in header[pn_offset..].iter_mut().enumerate() {
            *byte ^= mask[1 + i];
            packet_number = (packet_number << 8) | u64::from(*byte);
        }

        // The nonce is the IV with the packet number xored into its tail. A client's first
        // Initial numbers from zero and cannot have wrapped, so the truncated number on
        // the wire is the full one.
        let mut nonce = self.iv;
        for (i, byte) in packet_number.to_be_bytes().iter().enumerate() {
            nonce[i + 4] ^= byte;
        }

        let ciphertext = datagram.get(pn_offset + pn_len..pn_offset + length)?;
        Aes128Gcm::new_from_slice(&self.key)
            .ok()?
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: ciphertext,
                    aad: &header,
                },
            )
            .ok()
    }
}

/// HKDF-Expand-Label from TLS 1.3, with the empty context QUIC always uses.
fn expand_label(prk: &Hkdf<Sha256>, label: &[u8], out: &mut [u8]) -> Option<()> {
    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(&u16::try_from(out.len()).ok()?.to_be_bytes());
    info.push(u8::try_from(6 + label.len()).ok()?);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    prk.expand(&info, out).ok()
}

/// Concatenate the packet's CRYPTO frames, in offset order.
///
/// Only frames a client may send in an Initial are understood; anything else ends the
/// walk. A ClientHello that does not start at offset zero or has a hole in it is one the
/// client split across datagrams, which this cannot reassemble — the caller falls back.
fn reassemble_crypto(payload: &[u8]) -> Option<Vec<u8>> {
    let mut r = Reader::new(payload);
    let mut pieces: Vec<(u64, &[u8])> = Vec::new();

    while let Some(frame) = r.u8() {
        match frame {
            // PADDING and PING carry nothing.
            0x00 | 0x01 => {}
            // ACK, with ECN counts in the 0x03 form.
            0x02 | 0x03 => {
                r.varint()?;
                r.varint()?;
                let ranges = r.varint()?;
                r.varint()?;
                for _ in 0..ranges {
                    r.varint()?;
                    r.varint()?;
                }
                if frame == 0x03 {
                    r.varint()?;
                    r.varint()?;
                    r.varint()?;
                }
            }
            0x06 => {
                let offset = r.varint()?;
                let len = usize::try_from(r.varint()?).ok()?;
                pieces.push((offset, r.take(len)?));
            }
            // CONNECTION_CLOSE and anything a client has no business sending here.
            _ => break,
        }
    }

    pieces.sort_by_key(|(offset, _)| *offset);
    let mut crypto = Vec::new();
    for (offset, data) in pieces {
        // Frames may overlap; skip what is already in hand and stop at the first hole.
        let have = u64::try_from(crypto.len()).ok()?;
        if offset > have {
            break;
        }
        let skip = usize::try_from(have - offset).ok()?;
        if let Some(fresh) = data.get(skip..) {
            crypto.extend_from_slice(fresh);
        }
    }

    (!crypto.is_empty()).then_some(crypto)
}

/// The `server_name` extension of a TLS ClientHello.
fn client_hello_server_name(handshake: &[u8]) -> Option<String> {
    let mut r = Reader::new(handshake);
    if r.u8()? != 0x01 {
        return None;
    }
    let body_len = r.u24()?;
    let mut r = Reader::new(r.take(body_len)?);

    r.skip(2 + 32)?; // legacy_version, random
    let session_id = usize::from(r.u8()?);
    r.skip(session_id)?;
    let cipher_suites = r.u16()?;
    r.skip(cipher_suites)?;
    let compression = usize::from(r.u8()?);
    r.skip(compression)?;

    let extensions_len = r.u16()?;
    let mut r = Reader::new(r.take(extensions_len)?);
    while let Some(extension) = r.u16() {
        let len = r.u16()?;
        let body = r.take(len)?;
        if extension != 0x0000 {
            continue;
        }

        // A ServerNameList in practice holds exactly one host_name entry.
        let mut r = Reader::new(body);
        let list_len = r.u16()?;
        let mut r = Reader::new(r.take(list_len)?);
        while let Some(kind) = r.u8() {
            let len = r.u16()?;
            let name = r.take(len)?;
            if kind == 0x00 && (1..=MAX_SERVER_NAME).contains(&name.len()) {
                return String::from_utf8(name.to_vec()).ok();
            }
        }
        return None;
    }
    None
}

/// A cursor that reads big-endian fields and QUIC varints, and refuses to run off the end.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn position(&self) -> usize {
        self.at
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<usize> {
        let b = self.take(2)?;
        Some(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A connection ID, length-prefixed by one byte.
    fn cid(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u8()?);
        if len > MAX_CID {
            return None;
        }
        self.take(len)
    }

    /// RFC 9000, Section 16: the first two bits give the encoded length.
    fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let len = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for byte in self.take(len - 1)? {
            value = (value << 8) | u64::from(*byte);
        }
        Some(value)
    }
}

/// The client Initial from RFC 9001, Appendix A.2, protected and complete. Its
/// ClientHello offers `example.com`. Shared with the relay's routing tests.
#[cfg(test)]
pub(crate) fn rfc9001_client_initial() -> Vec<u8> {
    const HEX: &str = "\
     c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123\
     dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b3\
     1f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1f\
     c8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89\
     eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf\
     012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5\
     a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7ba\
     d1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db\
     059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e8\
     46d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63\
     ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d50\
     8b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7\
     fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec\
     281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c481\
     9e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699d\
     bfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd\
     14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef\
     2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f254101\
     0ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f71\
     9595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd\
     d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705\
     769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d06\
     9fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb\
     5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2\
     162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f35\
     5e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db\
     82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8f\
     a9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723\
     c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b627\
     9ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc852\
     44259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f\
     5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064\
     7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44\
     860018ab0856972e194cd934";

    let hex: Vec<u8> = HEX.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    hex.chunks(2)
        .map(|pair| {
            let digit = |b: u8| char::from(b).to_digit(16).expect("not hex") as u8;
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_server_name_from_the_rfc_9001_client_initial() {
        let datagram = rfc9001_client_initial();
        assert_eq!(
            datagram.len(),
            1200,
            "the vector is a full Initial datagram"
        );
        assert_eq!(peek_server_name(&datagram).as_deref(), Some("example.com"));
    }

    /// The proxy sees the rest of a connection too, and must not spend keys on it.
    #[test]
    fn ignores_datagrams_that_are_not_initial_packets() {
        let datagram = rfc9001_client_initial();

        // Short header (bit 0x80 clear) — every packet after the handshake.
        let mut short = datagram.clone();
        short[0] &= 0x7f;
        assert_eq!(peek_server_name(&short), None);

        // Handshake packet: the same long header, a different type.
        let mut handshake = datagram.clone();
        handshake[0] = (handshake[0] & !0x30) | 0x20;
        assert_eq!(peek_server_name(&handshake), None);

        // A version this does not know how to unprotect.
        let mut future = datagram.clone();
        future[1..5].copy_from_slice(&0x0000_0002u32.to_be_bytes());
        assert_eq!(peek_server_name(&future), None);
    }

    #[test]
    fn a_corrupt_packet_fails_the_aead_rather_than_returning_a_name() {
        let mut datagram = rfc9001_client_initial();
        let last = datagram.len() - 1;
        datagram[last] ^= 0xff;
        assert_eq!(peek_server_name(&datagram), None);
    }

    #[test]
    fn truncated_and_junk_datagrams_return_none_without_panicking() {
        let datagram = rfc9001_client_initial();
        for len in 0..datagram.len() {
            assert_eq!(
                peek_server_name(&datagram[..len]),
                None,
                "truncated to {len}"
            );
        }

        assert_eq!(peek_server_name(b""), None);
        assert_eq!(peek_server_name(b"hello"), None);
        assert_eq!(peek_server_name(&[0xff; 64]), None);
        assert_eq!(peek_server_name(&[0xc0; 1200]), None);
    }
}
