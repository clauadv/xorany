//! Compile-time constant obfuscation for Rust.
//!
//! The user-facing surface is the [`xorany!`] and [`xorany_wide!`] macros.
//! Everything else here is called by their generated code at the call site
//! and is public only because the macro expansion needs it.

#![allow(clippy::missing_safety_doc)]

pub use xorany_macros::{xorany, xorany_wide};

pub mod obf;

/// Encrypt a single byte at position `i` under `key`.
///
/// Used by the macro at expansion time to produce the embedded ciphertext.
/// Formula: `((c + 7*key) ^ (i + key)) as u8`, wrapping.
#[inline(always)]
pub const fn encrypt_byte(c: u8, i: usize, key: u64) -> u8 {
    let a = (c as u64).wrapping_add(key.wrapping_mul(7));
    let b = (i as u64).wrapping_add(key);
    (a ^ b) as u8
}

/// Decrypt a single byte produced by [`encrypt_byte`] at the same position
/// under the same key.
#[inline(always)]
pub const fn decrypt_byte(c: u8, i: usize, key: u64) -> u8 {
    let b = (i as u64).wrapping_add(key);
    ((c as u64) ^ b).wrapping_sub(key.wrapping_mul(7)) as u8
}

/// Reinterpret the first `size_of::<T>()` bytes of `buf` as a value of `T`.
///
/// # Safety
/// `T` must be `Copy` and the first `size_of::<T>()` bytes of `buf` must be
/// a valid bit pattern for `T`. Called by the macro at the end of each
/// decrypt to convert the stack buffer back into the user's typed value.
#[inline(always)]
pub unsafe fn transmute_as<T: Copy, const N: usize>(buf: [u8; N]) -> T {
    assert!(core::mem::size_of::<T>() <= N);
    let mut v = core::mem::MaybeUninit::<T>::uninit();
    core::ptr::copy_nonoverlapping(
        buf.as_ptr(),
        v.as_mut_ptr() as *mut u8,
        core::mem::size_of::<T>(),
    );
    v.assume_init()
}

/// Obfuscated `&str` returned by [`xorany!`] on string literals.
///
/// Holds the decrypted bytes in a stack buffer of padded size `N`. The real
/// UTF-8 length is `LEN`. Derefs to `&str`.
pub struct OxoStr<const N: usize, const LEN: usize> {
    bytes: [u8; N],
}

impl<const N: usize, const LEN: usize> OxoStr<N, LEN> {
    /// Wrap a buffer of decrypted bytes. Called by the macro.
    #[inline(always)]
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Returns the decrypted string.
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.bytes[..LEN]) }
    }

    /// Returns the decrypted bytes.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..LEN]
    }
}

impl<const N: usize, const LEN: usize> core::ops::Deref for OxoStr<N, LEN> {
    type Target = str;
    #[inline(always)]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize, const LEN: usize> core::fmt::Display for OxoStr<N, LEN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<const N: usize, const LEN: usize> core::fmt::Debug for OxoStr<N, LEN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl<const N: usize, const LEN: usize> AsRef<str> for OxoStr<N, LEN> {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize, const LEN: usize> AsRef<[u8]> for OxoStr<N, LEN> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<const N: usize, const LEN: usize> core::borrow::Borrow<str> for OxoStr<N, LEN> {
    #[inline(always)]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize, const LEN: usize> core::hash::Hash for OxoStr<N, LEN> {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state)
    }
}

impl<const N: usize, const LEN: usize> PartialEq for OxoStr<N, LEN> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<const N: usize, const LEN: usize> Eq for OxoStr<N, LEN> {}

impl<const N: usize, const LEN: usize> PartialEq<str> for OxoStr<N, LEN> {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<const N: usize, const LEN: usize> PartialEq<&str> for OxoStr<N, LEN> {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl<const N: usize, const LEN: usize> PartialEq<OxoStr<N, LEN>> for str {
    #[inline]
    fn eq(&self, other: &OxoStr<N, LEN>) -> bool {
        self == other.as_str()
    }
}

impl<const N: usize, const LEN: usize> PartialEq<OxoStr<N, LEN>> for &str {
    #[inline]
    fn eq(&self, other: &OxoStr<N, LEN>) -> bool {
        *self == other.as_str()
    }
}

/// Obfuscated `&[u8]` returned by [`xorany!`] on byte-string literals.
///
/// Holds the decrypted bytes in a stack buffer of padded size `N`. The real
/// payload length is `LEN`. Derefs to `&[u8]`.
pub struct OxoBytes<const N: usize, const LEN: usize> {
    bytes: [u8; N],
}

impl<const N: usize, const LEN: usize> OxoBytes<N, LEN> {
    /// Wrap a buffer of decrypted bytes. Called by the macro.
    #[inline(always)]
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Returns the decrypted bytes.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..LEN]
    }
}

impl<const N: usize, const LEN: usize> core::ops::Deref for OxoBytes<N, LEN> {
    type Target = [u8];
    #[inline(always)]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize, const LEN: usize> AsRef<[u8]> for OxoBytes<N, LEN> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize, const LEN: usize> core::borrow::Borrow<[u8]> for OxoBytes<N, LEN> {
    #[inline(always)]
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize, const LEN: usize> core::hash::Hash for OxoBytes<N, LEN> {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

impl<const N: usize, const LEN: usize> PartialEq for OxoBytes<N, LEN> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize, const LEN: usize> Eq for OxoBytes<N, LEN> {}

impl<const N: usize, const LEN: usize> PartialEq<[u8]> for OxoBytes<N, LEN> {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl<const N: usize, const LEN: usize, const M: usize> PartialEq<[u8; M]> for OxoBytes<N, LEN> {
    #[inline]
    fn eq(&self, other: &[u8; M]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize, const LEN: usize> core::fmt::Debug for OxoBytes<N, LEN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_slice(), f)
    }
}

/// Obfuscated UTF-16 wide string returned by [`xorany_wide!`].
///
/// Holds the decrypted u16 units in a stack buffer of padded size `N`. The
/// real payload length is `LEN`. Derefs to `&[u16]`.
pub struct OxoWStr<const N: usize, const LEN: usize> {
    units: [u16; N],
}

impl<const N: usize, const LEN: usize> OxoWStr<N, LEN> {
    /// Wrap a buffer of decrypted u16 units. Called by the macro.
    #[inline(always)]
    pub fn new(units: [u16; N]) -> Self {
        Self { units }
    }

    /// Returns the decrypted u16 slice.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u16] {
        &self.units[..LEN]
    }
}

impl<const N: usize, const LEN: usize> core::ops::Deref for OxoWStr<N, LEN> {
    type Target = [u16];
    #[inline(always)]
    fn deref(&self) -> &[u16] {
        self.as_slice()
    }
}

impl<const N: usize, const LEN: usize> AsRef<[u16]> for OxoWStr<N, LEN> {
    #[inline(always)]
    fn as_ref(&self) -> &[u16] {
        self.as_slice()
    }
}

impl<const N: usize, const LEN: usize> core::hash::Hash for OxoWStr<N, LEN> {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

impl<const N: usize, const LEN: usize> PartialEq for OxoWStr<N, LEN> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize, const LEN: usize> Eq for OxoWStr<N, LEN> {}

impl<const N: usize, const LEN: usize> PartialEq<[u16]> for OxoWStr<N, LEN> {
    #[inline]
    fn eq(&self, other: &[u16]) -> bool {
        self.as_slice() == other
    }
}

impl<const N: usize, const LEN: usize> core::fmt::Debug for OxoWStr<N, LEN> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_slice(), f)
    }
}

/// Reinterpret a decrypted byte buffer as a little-endian `[u16; M]`.
///
/// Called by the macro after decrypting a wide string. `N_BYTES` is the
/// padded byte capacity and `M` is the output u16 count (`N_BYTES / 2`).
#[inline(always)]
pub fn u16_array_from_le<const N_BYTES: usize, const M: usize>(
    bytes: [u8; N_BYTES],
) -> [u16; M] {
    assert!(M * 2 <= N_BYTES);
    let mut out = [0u16; M];
    let mut i = 0;
    while i < M {
        out[i] = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_byte_roundtrip_exhaustive() {
        let keys = [
            0u64,
            1,
            0x7f,
            0xff,
            0xffff,
            0xdead_beef_cafe_babe,
            u64::MAX,
            u64::MAX / 7,
        ];
        for &key in &keys {
            for c in 0u8..=255 {
                for i in 0usize..256 {
                    let enc = encrypt_byte(c, i, key);
                    let dec = decrypt_byte(enc, i, key);
                    assert_eq!(dec, c, "roundtrip failed for c={c} i={i} key={key:#x}");
                }
            }
        }
    }

    fn split(key: u64) -> (u64, u64) {
        let a = 0xdeadbeef_cafebabeu64;
        (a, a ^ key)
    }

    #[test]
    fn transmute_as_recovers_primitive() {
        const N: usize = 16;
        let value: u32 = 0xdead_beef;
        let mut buf = [0u8; N];
        buf[..4].copy_from_slice(&value.to_le_bytes());
        let out: u32 = unsafe { transmute_as::<u32, N>(buf) };
        assert_eq!(out, value);
    }

    #[test]
    fn u16_array_from_le_matches() {
        const N_BYTES: usize = 16;
        const M: usize = 4;
        let plain_u16: [u16; M] = [0x1234, 0x5678, 0x9abc, 0xdef0];
        let mut buf = [0u8; N_BYTES];
        for i in 0..M {
            buf[2 * i..2 * i + 2].copy_from_slice(&plain_u16[i].to_le_bytes());
        }
        let out: [u16; M] = u16_array_from_le::<N_BYTES, M>(buf);
        assert_eq!(out, plain_u16);
    }

    #[test]
    fn _split_fn_exists() {
        let (a, b) = split(0xcafe_f00d_dead_beef);
        assert_eq!(a ^ b, 0xcafe_f00d_dead_beef);
    }
}
