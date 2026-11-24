//! Nowhere Morph traffic ciphers, independent of TLS and QUIC encryption.

use std::io;

use aes::Aes128;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr::Ctr128BE;
use honk_config::node::NowhereCipher;

use super::{MorphKeyBytes, NONCE_LEN, exhausted, hmac_sha256};

type AesCtr = Ctr128BE<Aes128>;

pub(super) fn apply_datagram(
    cipher: NowhereCipher,
    key: &MorphKeyBytes,
    nonce: &[u8; NONCE_LEN],
    input: &[u8],
    output: &mut [u8],
) -> io::Result<()> {
    match cipher {
        NowhereCipher::ChaCha => ChaCha20::new(key.into(), nonce.into())
            .try_apply_keystream_b2b(input, output)
            .map_err(|_| exhausted()),
        NowhereCipher::Aes => {
            let mut counter = [0; 16];
            counter[..NONCE_LEN].copy_from_slice(nonce);
            AesCtr::new_from_slices(&key[..16], &counter)
                .expect("fixed AES key and counter lengths")
                .try_apply_keystream_b2b(input, output)
                .map_err(|_| io::Error::other("Morph AES datagram keystream exhausted"))
        }
    }
}

pub(super) enum TcpCipher {
    ChaCha(ChaCha20),
    Aes(Box<AesCtr>),
}

impl TcpCipher {
    pub(super) fn new(cipher: NowhereCipher, key: &MorphKeyBytes, nonce: &[u8; NONCE_LEN]) -> Self {
        match cipher {
            NowhereCipher::ChaCha => Self::ChaCha(ChaCha20::new(key.into(), nonce.into())),
            NowhereCipher::Aes => {
                let key = hmac_sha256(key, nonce);
                Self::Aes(Box::new(
                    AesCtr::new_from_slices(&key[..16], &[0; 16])
                        .expect("fixed AES key and counter lengths"),
                ))
            }
        }
    }

    pub(super) fn limit(&self) -> u64 {
        match self {
            Self::ChaCha(_) => (1 << 38) - 64,
            Self::Aes(_) => 1 << 48,
        }
    }

    pub(super) fn exhausted(&self) -> io::Error {
        match self {
            Self::ChaCha(_) => exhausted(),
            Self::Aes(_) => io::Error::other("Morph AES TCP keystream exhausted"),
        }
    }

    pub(super) fn try_apply_keystream(&mut self, data: &mut [u8]) -> io::Result<()> {
        match self {
            Self::ChaCha(cipher) => cipher.try_apply_keystream(data),
            Self::Aes(cipher) => cipher.try_apply_keystream(data),
        }
        .map_err(|_| self.exhausted())
    }

    pub(super) fn try_apply_keystream_b2b(
        &mut self,
        input: &[u8],
        output: &mut [u8],
    ) -> io::Result<()> {
        match self {
            Self::ChaCha(cipher) => cipher.try_apply_keystream_b2b(input, output),
            Self::Aes(cipher) => cipher.try_apply_keystream_b2b(input, output),
        }
        .map_err(|_| self.exhausted())
    }

    pub(super) fn try_seek(&mut self, offset: u64) -> io::Result<()> {
        match self {
            Self::ChaCha(cipher) => cipher.try_seek(offset),
            Self::Aes(cipher) => cipher.try_seek(offset),
        }
        .map_err(|_| self.exhausted())
    }
}
