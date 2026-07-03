// Written for Graviola by Joe Birr-Pixton, 2024.
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT-0

//! Self-contained, portable SHA256.
//!
//! This is described in [FIPS180](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

/// A context for incremental computation of SHA256.
#[derive(Clone)]
pub(crate) struct Context {
    h: [u32; 8],
    blockwise: Blockwise<{ Self::BLOCK_SZ }>,
    nblocks: usize,
}

impl Context {
    /// Start a new SHA256 hash computation.
    pub(crate) const fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            blockwise: Blockwise::new(),
            nblocks: 0,
        }
    }

    /// Add `bytes` to the ongoing hash computation.
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        if self.blockwise.used == 0 && (bytes.len() % Self::BLOCK_SZ) == 0 {
            self.update_blocks(bytes);
            return;
        }

        let bytes = self.blockwise.add_leading(bytes);

        if let Some(block) = self.blockwise.take() {
            self.update_blocks(&block);
        }

        let (whole_blocks, remainder) = {
            let whole_len = bytes.len() - (bytes.len() & (Self::BLOCK_SZ - 1));
            (&bytes[..whole_len], &bytes[whole_len..])
        };

        self.update_blocks(whole_blocks);

        self.blockwise.add_trailing(remainder);
    }

    /// Complete the SHA256 computation, returning the hash output.
    pub(crate) fn finish(mut self) -> Digest {
        let bytes = self
            .nblocks
            .checked_mul(Self::BLOCK_SZ)
            .and_then(|bytes| bytes.checked_add(self.blockwise.used))
            .unwrap();

        let bits = bytes
            .checked_mul(8)
            .expect("excess data processed by hash function");

        let last_blocks = self
            .blockwise
            .md_pad_with_length(&(bits as u64).to_be_bytes());
        self.update_blocks(last_blocks.as_ref());

        let mut r = [0u8; Self::OUTPUT_SZ];
        for (out, state) in r.chunks_exact_mut(4).zip(self.h.iter()) {
            out.copy_from_slice(&state.to_be_bytes());
        }
        Digest(r)
    }

    fn update_blocks(&mut self, blocks: &[u8]) {
        debug_assert!(blocks.len() % Self::BLOCK_SZ == 0);
        if !blocks.is_empty() {
            sha256_compress_blocks(&mut self.h, blocks);
            self.nblocks = self
                .nblocks
                .saturating_add(blocks.len() / Self::BLOCK_SZ);
        }
    }

    /// The internal block size of SHA256.
    const BLOCK_SZ: usize = 64;

    /// The output size of SHA256.
    const OUTPUT_SZ: usize = 32;
}

/// A computed hash.
pub(crate) struct Digest(pub(crate) [u8; 32]);

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Compute a hash from a sequence of slices.
impl From<&[&[u8]]> for Digest {
    fn from(slices: &[&[u8]]) -> Self {
        let mut ctx = Context::new();
        for s in slices {
            ctx.update(s);
        }
        ctx.finish()
    }
}

// --- Intermediate buffering and padding

#[derive(Clone)]
struct Blockwise<const N: usize> {
    buffer: [u8; N],
    used: usize,
}

impl<const N: usize> Blockwise<N> {
    const fn new() -> Self {
        Self {
            buffer: [0u8; N],
            used: 0,
        }
    }

    fn add_leading<'a>(&mut self, bytes: &'a [u8]) -> &'a [u8] {
        if self.used == 0 {
            return bytes;
        }

        let space = N - self.used;
        let take = core::cmp::min(bytes.len(), space);
        let (taken, returned) = bytes.split_at(take);
        self.buffer[self.used..self.used + take].copy_from_slice(taken);
        self.used += take;
        returned
    }

    fn take(&mut self) -> Option<[u8; N]> {
        if self.used == N {
            self.used = 0;
            Some(self.buffer)
        } else {
            None
        }
    }

    fn add_trailing(&mut self, trailing: &[u8]) {
        self.buffer[..trailing.len()].copy_from_slice(trailing);
        self.used += trailing.len();
    }

    fn md_pad_with_length(&mut self, length_bits: &[u8]) -> FinalBlocks<N> {
        let space = N - self.used;
        let required = 1 + length_bits.len();

        if required > space {
            // two block case (not especially optimised)
            self.add_leading(&[0x80]);
            self.add_leading(&[0u8; N]);

            let first = self.take().unwrap();
            let mut second = [0u8; N];
            let (_, length) = second.split_at_mut(N - length_bits.len());
            length.copy_from_slice(length_bits);
            FinalBlocks::Two([first, second])
        } else {
            let (_used, trailer) = self.buffer.split_at_mut(self.used);
            let (padding, length) = trailer.split_at_mut(trailer.len() - length_bits.len());
            let (delim, zeroes) = padding.split_at_mut(1);
            delim[0] = 0x80;
            zeroes.fill(0x00);
            length.copy_from_slice(length_bits);
            self.used = 0;
            FinalBlocks::One(self.buffer)
        }
    }
}

enum FinalBlocks<const N: usize> {
    One([u8; N]),
    Two([[u8; N]; 2]),
}

impl<const N: usize> AsRef<[u8]> for FinalBlocks<N> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::One(one) => &one[..],
            Self::Two(two) => two.as_flattened(),
        }
    }
}

// --- Compression function

fn sha256_compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert!(blocks.len() % 64 == 0);

    for block in blocks.chunks_exact(64) {
        sha256_compress_block(state, block);
    }
}

fn sha256_compress_block(state: &mut [u32; 8], block: &[u8]) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // This is a 16-word window into the whole W array.
    let mut w: [u32; 16] = [0; 16];

    for t in 0..64 {
        // For W[0..16] we process the input into W.
        // For W[16..64] we compute the next W value:
        //
        // W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
        //
        // But all W indices are reduced mod 16 into our window.
        let w_t = if t < 16 {
            let w_t = u32::from_be_bytes(
                block[t * 4..(t + 1) * 4]
                    .try_into()
                    .unwrap(),
            );
            w[t] = w_t;
            w_t
        } else {
            let w_t = ssig1(w[(t - 2) % 16])
                .wrapping_add(w[(t - 7) % 16])
                .wrapping_add(ssig0(w[(t - 15) % 16]))
                .wrapping_add(w[(t - 16) % 16]);
            w[t % 16] = w_t;
            w_t
        };

        let t1 = h
            .wrapping_add(bsig1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w_t);
        let t2 = bsig0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn bsig0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn bsig1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn ssig0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn ssig1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

static K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vectors() {
        test(
            b"hello",
            b"\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e\
              \x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24",
        );
        test(
            b"",
            b"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\
              \x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
        );
        test(
            b"abc",
            b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\
              \xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad",
        );
        test(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            b"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\
              \xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1",
        );
        test(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
              hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            b"\xcf\x5b\x16\xa7\x78\xaf\x83\x80\x03\x6c\xe5\x9e\x7b\x04\x92\x37\
              \x0b\x24\x9b\x11\xe8\xf0\x7a\x51\xaf\xac\x45\x03\x7a\xfe\xe9\xd1",
        );

        fn test(input: &[u8], expected: &[u8; 32]) {
            // one-shot
            assert_eq!(Digest::from(&[input][..]).0, *expected);

            // context
            let mut ctx = Context::new();
            ctx.update(input);
            assert_eq!(ctx.finish().0, *expected);

            // incremental
            let mut ctx = Context::new();
            for byte in input {
                ctx.update(&[*byte]);
            }
            assert_eq!(ctx.finish().0, *expected);
        }
    }

    #[test]
    fn sha256_all_lengths() {
        // see cifra `vector_length` and associated
        let mut outer = Context::new();

        for len in 0..1024 {
            let mut inner = Context::new();

            for _ in 0..len {
                inner.update(&[len as u8]);
            }

            outer.update(&inner.finish().0);
        }

        assert_eq!(
            outer.finish().as_ref(),
            b"\x55\x7b\xfd\xd5\xef\xda\xfd\x63\x06\x5e\xb7\x98\x87\xde\x86\xdb\
              \x54\xc3\xfe\xdf\x7b\xcc\xcb\x97\x08\xfa\x87\xf0\x11\x87\x61\xdc"
        );
    }
}
