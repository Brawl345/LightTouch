//! Apple's LZSS (4 KiB window, 18-byte matches), the complzss kernelcache wrapper and Adler-32.
//!
//! ```ignore
//! lzss::decompress(bytes, 0x20)      // raw stream; spaces for kernelcaches, zeros for iBootIm
//! lzss::compress(&kernel)            // raw stream that decompress reads back
//! lzss::complzss(&payload)?          // "complzss" header; length and Adler-32 checked
//! ```
use crate::error::Result;

pub const COMPLZSS_HEADER_SIZE: usize = 0x180;

const WINDOW: usize = 4096;
const MAX_MATCH: usize = 18;
const MIN_MATCH: usize = 3;
const HASH_BITS: usize = 16;
const HASH_SIZE: usize = 1 << HASH_BITS;
const NONE: usize = usize::MAX;

fn hash(data: &[u8], at: usize) -> usize {
    let value = ((data[at] as u32) << 16) | ((data[at + 1] as u32) << 8) | data[at + 2] as u32;
    (value.wrapping_mul(0x1E35_A7BD) >> (32 - HASH_BITS)) as usize
}

pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut heads = vec![NONE; HASH_SIZE];
    let mut previous = vec![NONE; WINDOW];
    let mut out = Vec::with_capacity(data.len() / 2);
    let mut at = 0;

    while at < data.len() {
        let flags_at = out.len();
        out.push(0);
        let mut flags = 0u8;

        for bit in 0..8 {
            if at >= data.len() {
                break;
            }
            let mut best_at = NONE;
            let mut best_len = 0;
            if at + MIN_MATCH <= data.len() {
                let mut candidate = heads[hash(data, at)];
                let limit = at.saturating_sub(WINDOW);
                while candidate != NONE && candidate >= limit {
                    let max = MAX_MATCH.min(data.len() - at);
                    let mut len = 0;
                    while len < max && data[candidate + len] == data[at + len] {
                        len += 1;
                    }
                    if len > best_len {
                        best_at = candidate;
                        best_len = len;
                        if len == max {
                            break;
                        }
                    }
                    candidate = previous[candidate & (WINDOW - 1)];
                }
            }

            let consumed = if best_len >= MIN_MATCH {
                let position = (WINDOW - MAX_MATCH + best_at) & (WINDOW - 1);
                out.push(position as u8);
                out.push((((position >> 4) & 0xF0) | (best_len - MIN_MATCH)) as u8);
                best_len
            } else {
                flags |= 1 << bit;
                out.push(data[at]);
                1
            };

            for position in at..at + consumed {
                if position + MIN_MATCH <= data.len() {
                    let key = hash(data, position);
                    previous[position & (WINDOW - 1)] = heads[key];
                    heads[key] = position;
                }
            }
            at += consumed;
        }
        out[flags_at] = flags;
    }
    out
}

/// `window_fill` is the window's initial byte; it shows through only when a match reaches back before the first
/// output byte.
pub fn decompress(s: &[u8], window_fill: u8) -> Vec<u8> {
    let mut ring = [window_fill; WINDOW];
    let mut r = WINDOW - MAX_MATCH;
    let mut out = Vec::with_capacity(s.len() * 2);
    let mut flags: u32 = 0;
    let mut i = 0;
    while i < s.len() {
        flags >>= 1;
        if flags & 0x100 == 0 {
            flags = s[i] as u32 | 0xFF00;
            i += 1;
        }
        if flags & 1 != 0 && i < s.len() {
            let c = s[i];
            i += 1;
            out.push(c);
            ring[r] = c;
            r = (r + 1) & (WINDOW - 1);
        } else if flags & 1 == 0 && i + 1 < s.len() {
            let pos = s[i] as usize | ((s[i + 1] as usize) & 0xF0) << 4;
            let n = (s[i + 1] as usize & 0x0F) + 3;
            i += 2;
            for k in 0..n {
                // byte by byte: a match may overlap what it is writing
                let c = ring[(pos + k) & (WINDOW - 1)];
                out.push(c);
                ring[r] = c;
                r = (r + 1) & (WINDOW - 1);
            }
        } else {
            break;
        }
    }
    out
}

/// A complzss payload (decrypted kernelcache): "complzss", adler32, ulen, clen (big-endian); data at 0x180.
pub fn complzss(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < 20 || !payload.starts_with(b"complzss") {
        return Err(crate::unsupported!("not complzss"));
    }
    let be = |o: usize| u32::from_be_bytes([payload[o], payload[o + 1], payload[o + 2], payload[o + 3]]);
    let adler = be(8);
    let ulen = be(12) as usize;
    let clen = be(16) as usize;
    let body = payload.get(COMPLZSS_HEADER_SIZE..).unwrap_or(&[]);
    let body = &body[..clen.min(body.len())];
    let out = decompress(body, 0x20);
    if out.len() != ulen || adler32(&out) != adler {
        return Err(crate::unsupported!("kernelcache checksum mismatch"));
    }
    Ok(out)
}

pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        // zlib's NMAX: no u32 overflow before the modulo
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    b << 16 | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_known_value() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn compression_round_trips() {
        let mut random = vec![0u8; 65_537];
        let mut state = 0x1234_5678u32;
        for byte in &mut random {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        for data in [b"".as_slice(), b"LightTouch LightTouch LightTouch", &[0u8; 8192], &random] {
            assert_eq!(decompress(&compress(data), 0x20), data);
        }
        assert!(compress(&vec![0u8; 8192]).len() < 1024);
    }

    #[test]
    fn literal_and_match() {
        // flags 0b1111_1110 >> : first item a match? Build: literals "ab" then a 3-byte match of "aba".
        // flags byte: bit0=1 (lit 'a'), bit1=1 (lit 'b'), bit2=0 (match), rest literal.
        let r = (4096 - 18) as usize; // where 'a' was written
        let pos = r;
        let stream = [0b1111_1011, b'a', b'b', (pos & 0xFF) as u8, (((pos >> 4) & 0xF0) | 0) as u8];
        assert_eq!(decompress(&stream, 0x20), b"ababa");
    }
}
