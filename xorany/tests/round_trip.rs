use xorany::{xorany, xorany_wide};

#[test]
fn string_short() {
    let s = xorany!("hi");
    assert_eq!(&*s, "hi");
}

#[test]
fn string_long() {
    let s = xorany!(
        "the quick brown fox jumps over the lazy dog. the quick brown fox jumps over the lazy dog."
    );
    assert_eq!(
        &*s,
        "the quick brown fox jumps over the lazy dog. the quick brown fox jumps over the lazy dog."
    );
}

#[test]
fn string_with_escapes() {
    let s = xorany!("line1\nline2\ttab\0null\x41A");
    assert_eq!(&*s, "line1\nline2\ttab\0null\x41A");
}

#[test]
fn string_unicode() {
    let s = xorany!("héllo 世界 🌍");
    assert_eq!(&*s, "héllo 世界 🌍");
}

#[test]
fn string_empty_is_padded() {
    let s = xorany!("");
    assert_eq!(&*s, "");
}

#[test]
fn raw_string_no_escapes() {
    let s = xorany!(r"C:\path\with\no\escapes");
    assert_eq!(&*s, "C:\\path\\with\\no\\escapes");
}

#[test]
fn byte_string() {
    let bs = xorany!(b"\x00\x01\x02\xff\xfe\xfd");
    assert_eq!(&*bs, &[0, 1, 2, 0xff, 0xfe, 0xfd]);
}

#[test]
fn wide_string() {
    let ws = xorany_wide!("widé 世界");
    let decoded = String::from_utf16(&ws).unwrap();
    assert_eq!(decoded, "widé 世界");
}

#[test]
fn int_u8() {
    assert_eq!(xorany!(0u8), 0u8);
    assert_eq!(xorany!(255u8), 255u8);
    assert_eq!(xorany!(0x7fu8), 0x7fu8);
}

#[test]
fn int_u16_u32_u64() {
    assert_eq!(xorany!(0xdeadu16), 0xdeadu16);
    assert_eq!(xorany!(0xdead_beefu32), 0xdead_beefu32);
    assert_eq!(xorany!(0x1234_5678_9abc_def0u64), 0x1234_5678_9abc_def0u64);
}

#[test]
fn int_signed_negative() {
    assert_eq!(xorany!(-1i32), -1i32);
    assert_eq!(xorany!(-128i8), -128i8);
    let min: i64 = xorany!(i64::MIN);
    assert_eq!(min, i64::MIN);
}

#[test]
fn int_default_type_is_i32() {
    let x: i32 = xorany!(42);
    assert_eq!(x, 42);
}

#[test]
fn int_hex_oct_bin() {
    assert_eq!(xorany!(0xabu16), 0xab);
    assert_eq!(xorany!(0o777u16), 0o777);
    assert_eq!(xorany!(0b1010_1010u8), 0b1010_1010);
}

#[test]
fn int_u128() {
    assert_eq!(
        xorany!(0x0f0e0d0c0b0a09080706050403020100u128),
        0x0f0e0d0c0b0a09080706050403020100u128
    );
}

#[test]
fn int_usize_isize_target_width() {
    let u: usize = xorany!(0xdead_beefusize);
    assert_eq!(u, 0xdead_beefusize);

    let i: isize = xorany!(-12345isize);
    assert_eq!(i, -12345isize);

    let m: usize = xorany!(usize::MAX);
    assert_eq!(m, usize::MAX);
}

#[test]
fn float_f32() {
    assert_eq!(xorany!(1.0f32), 1.0f32);
    assert_eq!(xorany!(-0.5f32), -0.5f32);
    let nan: f32 = xorany!(f32::NAN);
    assert!(nan.is_nan());
}

#[test]
#[allow(clippy::approx_constant)]
fn float_f64_default() {
    let x: f64 = xorany!(3.141592653589793);
    assert_eq!(x, 3.141592653589793);
}

#[test]
fn float_scientific() {
    assert_eq!(xorany!(1e10), 1e10);
    assert_eq!(xorany!(2.5e-3f32), 2.5e-3f32);
}

#[test]
fn char_ascii() {
    assert_eq!(xorany!('x'), 'x');
}

#[test]
fn char_unicode() {
    assert_eq!(xorany!('界'), '界');
    assert_eq!(xorany!('🌍'), '🌍');
}

#[test]
fn char_escape() {
    assert_eq!(xorany!('\n'), '\n');
    assert_eq!(xorany!('\\'), '\\');
    assert_eq!(xorany!('\0'), '\0');
}

const INT_CONST: i64 = -0x1234_5678_9abc_def0;
const U32_CONST: u32 = 0xcafe_babe;

#[test]
fn const_item_i64() {
    let x: i64 = xorany!(INT_CONST);
    assert_eq!(x, INT_CONST);
}

#[test]
fn const_item_u32() {
    let x: u32 = xorany!(U32_CONST);
    assert_eq!(x, U32_CONST);
}

#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug)]
enum Color {
    Red = 0xff0000,
    Green = 0x00ff00,
    Blue = 0x0000ff,
}

#[test]
fn enum_variant() {
    let c: Color = xorany!(Color::Red);
    assert_eq!(c, Color::Red);
    let c: Color = xorany!(Color::Green);
    assert_eq!(c, Color::Green);
    let c: Color = xorany!(Color::Blue);
    assert_eq!(c, Color::Blue);
}

#[test]
fn const_expression() {
    let x: i32 = xorany!(1 + 2 * 3);
    assert_eq!(x, 7);
}

#[test]
fn cast_expression() {
    let x: i32 = xorany!(Color::Red as i32);
    assert_eq!(x, 0xff0000);
}

#[test]
fn same_literal_different_sites() {
    let a = xorany!("MATCH");
    let b = xorany!("MATCH");
    assert_eq!(&*a, "MATCH");
    assert_eq!(&*b, "MATCH");
}

#[test]
fn oxostr_partial_eq_with_native_str() {
    let s = xorany!("hello");
    assert!(s == *"hello");
    assert!(s == "hello");
    assert_eq!(s, "hello");
    assert!("hello" == s);
    assert!(s != "goodbye");
}

#[test]
fn oxostr_as_ref_borrow_hash() {
    use std::collections::HashSet;
    let s = xorany!("key1");
    fn takes_str<T: AsRef<str>>(t: T) -> String {
        t.as_ref().to_string()
    }
    assert_eq!(takes_str(&s), "key1");

    let mut set: HashSet<String> = HashSet::new();
    set.insert("key1".to_string());
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    s.hash(&mut h1);
    let mut h2 = DefaultHasher::new();
    "key1".hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn oxobytes_partial_eq_and_asref() {
    let b = xorany!(b"abcd");
    assert_eq!(*b, *b"abcd");
    assert!(b == *b"abcd".as_slice());
    assert!(b == *b"abcd");
    fn takes_bytes<T: AsRef<[u8]>>(t: T) -> Vec<u8> {
        t.as_ref().to_vec()
    }
    assert_eq!(takes_bytes(&b), b"abcd");
}

#[test]
fn multiple_in_one_expression() {
    let s = format!(
        "{} + {} = {}",
        xorany!("one"),
        xorany!("two"),
        xorany!("three"),
    );
    assert_eq!(s, "one + two = three");
}
