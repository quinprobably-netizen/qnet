//! The panel PIN's hash, in the one line the Pi reads: `$pbkdf2-sha256$i=10000$<salt as 32 hex
//! digits>$<hash as 64 hex digits>`, PBKDF2-HMAC-SHA256 with 10,000 rounds, a random 16-byte salt
//! and the four digits as the password. qnet makes the line (the Pi never sees the digits) and
//! pushes it with `PUT /api/qbp/panel`; the Pi's own `PasswordHash::parse` takes it back.
//!
//! The digits live in a [`Zeroizing`] buffer from the moment they are read until they are hashed,
//! and nothing here puts them, the salt or the hash into an error, a `Debug` or a log line.
//! [`PinHash`] is the line itself, kept in the store: its `Debug` shows `<redacted>`.
//!
//! PBKDF2 is written out here (a few lines over `sha2`, which the tree has already) instead of
//! pulling in two more crates, and is checked against the published test vectors.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The rounds of the PIN's hash: what the Pi's `hash-pin` uses, which is the least it accepts.
pub const ROUNDS: u32 = 10_000;

/// The digits of a PIN.
pub const PIN_LEN: usize = 4;

/// The length of a salt, in bytes.
const SALT_LEN: usize = 16;

/// The block size of SHA-256, in bytes.
const BLOCK: usize = 64;

/// What every line starts with, up to the rounds.
const PREFIX: &str = "$pbkdf2-sha256$i=";

/// A PIN's hash as the Pi reads it. Secret: `Debug` shows nothing of it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PinHash(String);

impl PinHash {
    /// The line, for the body of the push to the Pi.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A line read back from the store, if it is one: the shape `new` makes (the rounds, 32 hex
    /// digits of salt and 64 of hash, all lower case) and nothing else.
    pub fn parse(text: &str) -> Option<PinHash> {
        let mut fields = text.strip_prefix(PREFIX)?.split('$');
        let (rounds, salt, hash) = (fields.next()?, fields.next()?, fields.next()?);
        let hex = |s: &str, len: usize| {
            s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        };
        let plain = !rounds.is_empty() && rounds.bytes().all(|b| b.is_ascii_digit());
        (fields.next().is_none() && plain && rounds == "10000" && hex(salt, 32) && hex(hash, 64))
            .then(|| PinHash(text.to_string()))
    }
}

impl fmt::Debug for PinHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Whether `pin` is exactly four ASCII digits.
pub fn valid_pin(pin: &str) -> bool {
    pin.len() == PIN_LEN && pin.bytes().all(|b| b.is_ascii_digit())
}

/// The hash line of `pin` (four digits) with `salt`; `None` for anything that is not four digits.
pub fn hash_with_salt(pin: &str, salt: [u8; SALT_LEN]) -> Option<PinHash> {
    if !valid_pin(pin) {
        return None;
    }
    let hash = pbkdf2_sha256(pin.as_bytes(), &salt, ROUNDS);
    Some(PinHash(format!(
        "{PREFIX}{ROUNDS}${}${}",
        hex(&salt),
        hex(hash.as_slice())
    )))
}

/// The hash line of `pin` with a salt from `/dev/urandom`.
pub fn hash(pin: &str) -> Result<PinHash, String> {
    if !valid_pin(pin) {
        return Err("a PIN is four digits".to_string());
    }
    let mut salt = [0u8; SALT_LEN];
    crate::util::urandom(&mut salt).map_err(|e| format!("no random salt: {e}"))?;
    hash_with_salt(pin, salt).ok_or_else(|| "a PIN is four digits".to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// HMAC-SHA256 with a key of at most one block, from the two hashers that hold the key's pads.
struct Hmac {
    inner: Sha256,
    outer: Sha256,
}

impl Hmac {
    fn new(key: &[u8]) -> Hmac {
        // A key longer than a block is hashed first (RFC 2104); a PIN never is.
        let mut block = Zeroizing::new([0u8; BLOCK]);
        if key.len() > BLOCK {
            block[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = Zeroizing::new([0x36u8; BLOCK]);
        let mut opad = Zeroizing::new([0x5cu8; BLOCK]);
        for i in 0..BLOCK {
            ipad[i] ^= block[i];
            opad[i] ^= block[i];
        }
        let mut inner = Sha256::new();
        inner.update(ipad.as_slice());
        let mut outer = Sha256::new();
        outer.update(opad.as_slice());
        Hmac { inner, outer }
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut inner = self.inner.clone();
        for part in parts {
            inner.update(part);
        }
        let mut outer = self.outer.clone();
        outer.update(inner.finalize());
        outer.finalize().into()
    }
}

/// The first 32 bytes of PBKDF2-HMAC-SHA256 of `password` and `salt`, `rounds` rounds: the one
/// block of output that the Pi's hash holds.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32) -> Zeroizing<[u8; 32]> {
    let hmac = Hmac::new(password);
    let mut u = hmac.mac(&[salt, &1u32.to_be_bytes()]);
    let mut t = u;
    for _ in 1..rounds {
        u = hmac.mac(&[&u]);
        for (t, u) in t.iter_mut().zip(u.iter()) {
            *t ^= u;
        }
    }
    Zeroizing::new(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(bytes: &[u8]) -> String {
        hex(bytes)
    }

    #[test]
    fn pbkdf2_matches_the_published_vectors() {
        // RFC 7914 section 11, and the usual PBKDF2-HMAC-SHA256 vectors (P "password", S "salt").
        assert_eq!(
            h(pbkdf2_sha256(b"passwd", b"salt", 1).as_slice()),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        for (rounds, want) in [
            (
                1,
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
            ),
            (
                2,
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
            ),
            (
                4096,
                "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
            ),
        ] {
            assert_eq!(
                h(pbkdf2_sha256(b"password", b"salt", rounds).as_slice()),
                want,
                "{rounds} rounds"
            );
        }
    }

    #[test]
    fn a_key_longer_than_a_block_is_hashed_first() {
        // RFC 4231 test case 6: a 131-byte key, which is the same as its own hash as the key.
        let key = [0xaau8; 131];
        let data: &[u8] = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let long = Hmac::new(&key).mac(&[data]);
        assert_eq!(long, Hmac::new(&Sha256::digest(key)).mac(&[data]));
        assert_eq!(
            h(&long),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn the_line_has_the_shape_the_pi_parses_and_the_digits_make_the_hash() {
        let line = hash_with_salt("1234", [7; 16]).unwrap();
        assert_eq!(
            line.as_str(),
            "$pbkdf2-sha256$i=10000$07070707070707070707070707070707$\
             83a21f487ebd7c29ae25e44ec11fa84134a3d13b2726ed0bf445f14983197c33"
        );
        let other = hash_with_salt("0000", core::array::from_fn(|i| i as u8)).unwrap();
        assert_eq!(
            other.as_str(),
            "$pbkdf2-sha256$i=10000$000102030405060708090a0b0c0d0e0f$\
             8a5a1a96f3ddf041b6e63aed667f9ea01b1466f0c2488064301ebf2bb5bd4d33"
        );
        assert_eq!(PinHash::parse(line.as_str()), Some(line));
    }

    #[test]
    fn only_four_digits_are_a_pin() {
        for bad in ["", "123", "12345", "12a4", " 123", "123 ", "١٢٣٤", "12\n4"] {
            assert!(!valid_pin(bad), "{bad:?}");
            assert!(hash_with_salt(bad, [0; 16]).is_none(), "{bad:?}");
            assert!(hash(bad).is_err(), "{bad:?}");
        }
        assert!(valid_pin("0000") && valid_pin("9999") && valid_pin("0123"));
    }

    #[test]
    fn a_random_salt_gives_a_different_line_each_time() {
        let a = hash("1234").unwrap();
        let b = hash("1234").unwrap();
        assert_ne!(a, b);
        assert!(PinHash::parse(a.as_str()).is_some());
        assert!(PinHash::parse(b.as_str()).is_some());
    }

    #[test]
    fn only_the_one_shape_parses_back() {
        let ok = hash_with_salt("1234", [1; 16]).unwrap();
        let line = ok.as_str().to_string();
        assert!(PinHash::parse(&line).is_some());
        for bad in [
            line.replace("i=10000", "i=100000"),
            line.replace("i=10000", "i=010000"),
            line.replace("$pbkdf2-sha256$", "$pbkdf2-sha512$"),
            line.to_uppercase(),
            format!("{line}$"),
            format!("{line}\n"),
            line[..line.len() - 1].to_string(),
            String::new(),
            "1234".to_string(),
        ] {
            assert!(PinHash::parse(&bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn the_debug_form_shows_nothing_of_the_hash() {
        let line = hash_with_salt("1234", [7; 16]).unwrap();
        assert_eq!(format!("{line:?}"), "<redacted>");
        assert_eq!(format!("{:?}", Some(&line)), "Some(<redacted>)");
    }
}
