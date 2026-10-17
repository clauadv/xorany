use std::fs;

use xorany::xorany;

const SENTINEL: &str = "xorany_leak_check_C8oamkDPlxQ2eKvv";

#[test]
fn plaintext_absent_from_test_binary() {
    let decrypted = xorany!("xorany_leak_check_C8oamkDPlxQ2eKvv");
    assert_eq!(&*decrypted, SENTINEL);

    let exe_bytes = read_test_binary();
    let needle = std::hint::black_box(SENTINEL.as_bytes());
    let count = count_substring(&exe_bytes, needle);

    assert!(
        count <= 1,
        "xorany leaked plaintext: found {count} copies of SENTINEL (expected 0 or 1 from the const item itself)",
    );
}

#[cfg(not(debug_assertions))]
#[test]
fn integer_plaintext_absent_release() {
    let a: u64 = std::hint::black_box(0x1111_2222_3333_4444);
    let b: u64 = std::hint::black_box(0xB6A7_E7F6_D0C1_5D4C);
    let expected = a ^ b;

    let got: u64 = xorany!(0xA7B6_C5D4_E3F2_1908u64);
    assert_eq!(got, expected);

    let exe_bytes = read_test_binary();
    let le = std::hint::black_box(expected.to_le_bytes());
    let be = std::hint::black_box(expected.to_be_bytes());
    let le_count = count_substring(&exe_bytes, &le);
    let be_count = count_substring(&exe_bytes, &be);

    assert_eq!(le_count, 0, "u64 LE plaintext leaked ({le_count} copies)");
    assert_eq!(be_count, 0, "u64 BE plaintext leaked ({be_count} copies)");
}

#[cfg(not(debug_assertions))]
#[test]
fn byte_string_plaintext_absent_release() {
    const SENTINEL: &[u8] =
        b"\x7a\xee\x11\xbc\x58\x40\x92\xd6\x0b\xfa\x33\x87\x6c\x25\xe9\x4f";

    let got = xorany!(
        b"\x7a\xee\x11\xbc\x58\x40\x92\xd6\x0b\xfa\x33\x87\x6c\x25\xe9\x4f"
    );
    let expected: &[u8] = std::hint::black_box(SENTINEL);
    assert_eq!(&*got, expected);

    let exe_bytes = read_test_binary();
    let needle = std::hint::black_box(SENTINEL);
    let count = count_substring(&exe_bytes, needle);
    assert!(
        count <= 1,
        "byte-string plaintext leaked ({count} copies, expected 0 or 1)"
    );
}

fn read_test_binary() -> Vec<u8> {
    let exe = std::env::current_exe().expect("current_exe");
    fs::read(&exe).expect("read exe")
}

fn count_substring(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    let mut n = 0;
    for w in haystack.windows(needle.len()) {
        if w == needle {
            n += 1;
        }
    }
    n
}
