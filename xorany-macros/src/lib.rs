//! Proc-macro backend for the `xorany` crate.
//!
//! You do not use this crate directly. The `xorany` crate re-exports its
//! two proc-macros, and that is the user-facing surface.

use proc_macro::{Delimiter, Group, Literal, Punct, Spacing, TokenStream, TokenTree};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0x9E3779B97F4A7C15);

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

fn splitmix(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn shuffle_1_to_9(seed: u64) -> Vec<usize> {
    let mut v: Vec<usize> = (1..=9).collect();
    let mut s = seed;
    for i in (1..v.len()).rev() {
        let r = (splitmix(&mut s) as usize) % (i + 1);
        v.swap(i, r);
    }
    v
}

fn shuffle_bcf(seed: u64) -> [usize; 25] {
    let mut table: [usize; 25] = [
        1, 2, 3, 4, 5, 6, 8, 9, 10, 16, 32, 40, 64, 66, 100, 128, 512, 1000,
        1024, 4096, 97, 122, 65, 90, 42,
    ];
    let mut s = seed;
    for i in (1..table.len()).rev() {
        let r = (splitmix(&mut s) as usize) % (i + 1);
        table.swap(i, r);
    }
    table
}

fn format_bcf(table: &[usize; 25]) -> String {
    let mut s = String::from("[");
    for (i, v) in table.iter().enumerate() {
        if i > 0 { s.push_str(", "); }
        s.push_str(&v.to_string());
    }
    s.push(']');
    s
}

fn bogus_bytes(key: u64, slot: usize) -> String {
    let mut seed = key
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add((slot as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9));
    let roll = splitmix(&mut seed) & 0x7;
    let imm = |s: &mut u64| (splitmix(s) & 0xFF) as u8;

    match roll {
        0 => {
            let b: Vec<u8> = (0..6).map(|_| imm(&mut seed)).collect();
            format!(
                ".byte 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, {}",
                b.iter().map(|v| format!("0x{v:02X}")).collect::<Vec<_>>().join(", ")
            )
        }
        1 => {
            let b: Vec<u8> = (0..8).map(|_| imm(&mut seed)).collect();
            format!(
                ".byte 0x48, 0xB8, {}",
                b.iter().map(|v| format!("0x{v:02X}")).collect::<Vec<_>>().join(", ")
            )
        }
        2 => {
            let b: Vec<u8> = (0..4).map(|_| imm(&mut seed)).collect();
            format!(
                ".byte 0xE8, {}",
                b.iter().map(|v| format!("0x{v:02X}")).collect::<Vec<_>>().join(", ")
            )
        }
        3 => format!(".byte 0x0F, 0x31, 0x{:02X}, 0x{:02X}", imm(&mut seed), imm(&mut seed)),
        4 => ".byte 0x66, 0x66, 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00".to_string(),
        5 => format!(".byte 0x48, 0x{:02X}, 0x{:02X}, 0x{:02X}",
            imm(&mut seed), imm(&mut seed), imm(&mut seed)),
        6 => format!(".byte 0xEB, 0xFE, 0x{:02X}, 0x{:02X}, 0x{:02X}",
            imm(&mut seed), imm(&mut seed), imm(&mut seed)),
        _ => format!(".byte 0x0F, 0x22, 0x{:02X}, 0x{:02X}, 0x{:02X}, 0x{:02X}",
            imm(&mut seed), imm(&mut seed), imm(&mut seed), imm(&mut seed)),
    }
}

fn ur_target(descending: bool, modulo: usize) -> usize {
    if descending { 10 - modulo } else { modulo }
}

fn generate_chain(
    key: u64,
    chain_idx: usize,
    head_cmp: &str,
    head_body: &str,
    head_salt: u64,
    tail_body: &str,
    desc: bool,
    fake_salt_base: u64,
) -> String {
    let perm_seed = key
        .wrapping_mul(0xDEAD_BEEF_CAFE_BABE)
        .wrapping_add((chain_idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let full_perm = shuffle_1_to_9(perm_seed);
    let perm: Vec<usize> = full_perm.into_iter().take(3).collect();

    let mut s = String::new();
    s.push_str(&format!(
        "if stack_x {head_cmp} stack_y + limit(fk(key, {head_salt})) {{ {head_body} }}\n"
    ));
    for modulo in perm {
        let salt_cond = fake_salt_base + 2 * (modulo as u64);
        let salt_dec = salt_cond + 1;
        let raw_ur = ur_target(desc, modulo);
        let ur = ((raw_ur - 1) % 3) + 1;
        s.push_str(&format!(
            "else if stack_x == stack_y + limit(fk(key, {salt_cond})) % {modulo} + 1 {{\n\
                decrypted = ::xorany::decrypt_byte(source, i, fk(key, {salt_dec}));\n\
                loc = Loc::Ur{ur};\n\
            }}\n"
        ));
    }
    s.push_str(&format!("else {{ {tail_body} }}\n"));
    s
}

fn generate_ur(key: u64, slot: usize) -> String {
    let bog = bogus_bytes(key, slot);
    let bog_block = format!(
        "#[cfg(any(target_arch = \"x86_64\", target_arch = \"x86\"))]\n\
         unsafe {{ ::core::arch::asm!(\"2: jmp 3f\", \"{bog}\", \"3:\", options(nostack, preserves_flags)); }}\n"
    );
    let wild_salt = 300 + slot as u64 * 7;
    let wild_write = format!(
        "unsafe {{\n\
             let off = (fk(key, {wild_salt}) as usize) & 0x1F_FFFF | 0x14_0000;\n\
             ::core::ptr::write_volatile(buf.wrapping_add(off), decrypted);\n\
         }}\n"
    );

    match slot {
        1 => format!(
            "Loc::Ur1 => {{\n\
                let idx = i.min(len.saturating_sub(1));\n\
                unsafe {{ *buf.add(idx) = ::xorany::decrypt_byte(source, i, fk(key, 201)); }}\n\
                {wild_write}\
                {bog_block}\
                loc = Loc::Ur2;\n\
            }}\n"
        ),
        2 => format!(
            "Loc::Ur2 => {{\n\
                stack_y = stack_y.wrapping_add(1);\n\
                {wild_write}\
                {bog_block}\
                loc = Loc::Ur3;\n\
            }}\n"
        ),
        3 => format!(
            "Loc::Ur3 => {{\n\
                i = i.wrapping_sub(1).min(len - 1);\n\
                {wild_write}\
                {bog_block}\
                loc = Loc::Start9;\n\
            }}\n"
        ),
        4 => format!(
            "Loc::Ur4 => {{\n\
                let idx = i.min(len.saturating_sub(1));\n\
                unsafe {{ *buf.add(idx) = ::xorany::decrypt_byte(source, i, fk(key, 204)); }}\n\
                unsafe {{ *buf.add(idx) = (*buf.add(idx)).wrapping_add(decrypted); }}\n\
                {wild_write}\
                {bog_block}\
                loc = Loc::Ur5;\n\
            }}\n"
        ),
        5 => format!(
            "Loc::Ur5 => {{\n\
                stack_x = stack_x.wrapping_add(stack_y);\n\
                {wild_write}\
                {bog_block}\
                loc = Loc::Ur6;\n\
            }}\n"
        ),
        6 => format!(
            "Loc::Ur6 => {{\n\
                i = i.wrapping_sub(1).min(len - 1);\n\
                i = i.wrapping_sub(decrypted as usize).min(len - 1);\n\
                {wild_write}\
                {bog_block}\
                loc = Loc::Start9;\n\
            }}\n"
        ),
        7 => format!(
            "Loc::Ur7 => {{\n\
                let idx = i.min(len.saturating_sub(1));\n\
                unsafe {{ *buf.add(idx) = ::xorany::decrypt_byte(source, i, fk(key, 207)); }}\n\
                stack_y = stack_y.wrapping_add(1);\n\
                i = i.wrapping_sub(unsafe {{ *buf.add(idx) }} as usize).min(len - 1);\n\
                i = i.wrapping_sub(stack_y).min(len - 1);\n\
                {wild_write}\
                {bog_block}\
                loc = Loc::Ur8;\n\
            }}\n"
        ),
        8 => format!(
            "Loc::Ur8 => {{\n\
                let idx = i.min(len.saturating_sub(1));\n\
                unsafe {{ *buf.add(idx) = ::xorany::decrypt_byte(source, i, fk(key, 208)); }}\n\
                stack_x = stack_x.wrapping_add(1);\n\
                i = i.wrapping_sub(1).min(len - 1);\n\
                i = i.wrapping_sub(stack_x).min(len - 1);\n\
                {wild_write}\
                {bog_block}\
                loc = Loc::Ur9;\n\
            }}\n"
        ),
        9 => format!(
            "Loc::Ur9 => {{\n\
                let idx = i.min(len.saturating_sub(1));\n\
                i = i.wrapping_add(unsafe {{ *buf.add(idx) }} as usize).min(len);\n\
                i = i.wrapping_add(stack_y).min(len);\n\
                {wild_write}\
                {bog_block}\
                loc = Loc::Start2;\n\
            }}\n"
        ),
        _ => unreachable!(),
    }
}

fn generate_state_machine_body(key: u64) -> String {
    let mut seed = key
        .wrapping_add(0xDEAD_BEEF_CAFE_BABE)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let base_salt = splitmix(&mut seed) | 1;
    let bcf = shuffle_bcf(seed);
    let bcf_str = format_bcf(&bcf);

    let chain3 = generate_chain(
        key, 0, "<",
        "decrypted = ::xorany::decrypt_byte(source, i, fk(key, 31)); loc = Loc::Start4;",
        3, "loc = Loc::Start4;", true, 30,
    );
    let chain4 = generate_chain(
        key, 1, "<",
        "decrypted = ::xorany::decrypt_byte(source, i, fk(key, 51)); loc = Loc::Start5;",
        50, "loc = Loc::Start5;", false, 50,
    );
    let chain5 = generate_chain(
        key, 2, "<",
        "decrypted = ::xorany::decrypt_byte(source, i, key); loc = Loc::Start6;",
        70, "loc = Loc::Start6;", true, 70,
    );
    let chain6 = generate_chain(
        key, 3, ">",
        "decrypted = ::xorany::decrypt_byte(source, i, fk(key, 92)); loc = Loc::Start7;",
        91, "loc = Loc::Start7;", false, 90,
    );
    let chain7 = generate_chain(
        key, 4, ">",
        "decrypted = ::xorany::decrypt_byte(source, i, fk(key, 114)); loc = Loc::Start8;",
        113, "loc = Loc::Start8;", true, 110,
    );

    let ur1 = generate_ur(key, 1);
    let ur2 = generate_ur(key, 2);
    let ur3 = generate_ur(key, 3);

    format!(
        r#"
        use ::core::hint::black_box;

        #[derive(Clone, Copy)]
        enum Loc {{
            Start1, Start2, Start3, Start4, Start5, Start6, Start7, Start8, Start9,
            Ur1, Ur2, Ur3,
            Done,
        }}

        const BASE_SALT: u64 = {base_salt}u64;
        const LIMIT_BCF: [usize; 25] = {bcf_str};

        #[inline(always)]
        fn fk(k: u64, salt: u64) -> u64 {{
            ::core::hint::black_box(
                k.wrapping_mul(salt.wrapping_add(BASE_SALT))
                    .wrapping_add(salt.wrapping_mul(BASE_SALT ^ 0xBF58476D1CE4E5B9u64)),
            )
        }}

        #[inline(always)]
        fn limit(k: u64) -> usize {{
            LIMIT_BCF[(k as usize) % LIMIT_BCF.len()]
        }}

        unsafe {{ ::xorany::obf::__xorany_seed(); }}

        let mut key_a_v = key_a;
        let mut key_b_v = key_b;
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        unsafe {{
            ::core::arch::asm!("/* {{0}} */", inout(reg) key_a_v, options(nostack, preserves_flags));
            ::core::arch::asm!("/* {{0}} */", inout(reg) key_b_v, options(nostack, preserves_flags));
        }}
        let key: u64 = key_a_v ^ key_b_v;

        let mut stack_x: usize = black_box(unsafe {{ ::xorany::obf::__xorany_x() }});
        let mut stack_y: usize = black_box(unsafe {{ ::xorany::obf::__xorany_y() }});
        let mut i: usize = 0;
        let mut source: u8 = 0;
        let mut decrypted: u8 = 0;
        let mut loc = Loc::Start1;
        let mut guard: usize = len.saturating_mul(64) + 64;

        loop {{
            if guard == 0 {{ break; }}
            guard -= 1;
            match loc {{
                Loc::Start1 => {{
                    stack_x = black_box(unsafe {{ ::xorany::obf::__xorany_x() }});
                    stack_y = black_box(unsafe {{ ::xorany::obf::__xorany_y() }});
                    loc = Loc::Start2;
                }}
                Loc::Start2 => {{
                    if i >= len {{ loc = Loc::Done; }}
                    else {{ source = unsafe {{ *buf.add(i) }}; loc = Loc::Start3; }}
                }}
                Loc::Start3 => {{
                    if stack_x <= i {{ {chain3} }}
                    else {{ i = len; loc = Loc::Done; }}
                }}
                Loc::Start4 => {{
                    if stack_y <= i {{ {chain4} }}
                    else {{ i = len; loc = Loc::Done; }}
                }}
                Loc::Start5 => {{
                    if stack_x + stack_y <= i {{ {chain5} }}
                    else {{ loc = Loc::Start6; }}
                }}
                Loc::Start6 => {{
                    if stack_x + stack_y != limit(fk(key, 90)) {{ {chain6} }}
                    else {{
                        decrypted = ::xorany::decrypt_byte(source, i, fk(key, 111));
                        decrypted = decrypted.wrapping_sub(unsafe {{ *buf.add(i.min(len - 1)) }});
                        loc = Loc::Ur1;
                    }}
                }}
                Loc::Start7 => {{
                    if stack_x < limit(fk(key, 112)) {{ {chain7} }}
                    else {{
                        decrypted = ::xorany::decrypt_byte(source, i, fk(key, 133));
                        decrypted = decrypted.wrapping_add(unsafe {{ *buf.add(i.min(len - 1)) }});
                        loc = Loc::Ur1;
                    }}
                }}
                Loc::Start8 => {{
                    if stack_y < limit(fk(key, 134)) {{ loc = Loc::Start9; }}
                    else {{
                        decrypted = ::xorany::decrypt_byte(source, i, fk(key, 135));
                        decrypted = decrypted.wrapping_add(decrypted);
                        loc = Loc::Ur1;
                    }}
                }}
                Loc::Start9 => {{
                    unsafe {{ *buf.add(i) = decrypted; }}
                    i = i.wrapping_add(1);
                    loc = Loc::Start2;
                }}
                {ur1}
                {ur2}
                {ur3}
                Loc::Done => break,
            }}
        }}
"#
    )
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = FNV_OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

fn make_key(input_str: &str) -> u64 {
    let base = COUNTER.fetch_add(0x9E3779B97F4A7C15, Ordering::Relaxed);
    let hash = fnv1a(input_str.as_bytes());
    let pkg = std::env::var("CARGO_PKG_NAME").unwrap_or_default();
    let pkg_hash = fnv1a(pkg.as_bytes());
    let mut k = base
        .wrapping_mul(0x9E3779B97F4A7C15)
        .wrapping_add(hash)
        .wrapping_add(pkg_hash);
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51afd7ed558ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
    k ^= k >> 33;
    k | 1
}

fn split_key(key: u64) -> (u64, u64) {
    let mut a = key.wrapping_mul(0xff51afd7ed558ccd);
    a ^= a >> 33;
    a = a.wrapping_mul(0xc4ceb9fe1a85ec53);
    a ^= a >> 33;
    a = a.wrapping_add(0x9E3779B97F4A7C15);
    let b = a ^ key;
    (a, b)
}

fn prng(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = *seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

fn enc(c: u8, i: usize, key: u64) -> u8 {
    let a = (c as u64).wrapping_add(key.wrapping_mul(7));
    let b = (i as u64).wrapping_add(key);
    (a ^ b) as u8
}

fn pad_size(real_len: usize, key: u64) -> usize {
    let aligned = (real_len + 15) & !15;
    let extra = ((key >> 16) & 0xF) as usize;
    aligned + extra
}

/// Obfuscate any literal or const-evaluable expression.
///
/// Accepts string, byte-string, char, integer, and float literals, plus
/// const items, enum variants, and cast expressions. The plaintext is
/// encrypted at compile time and decrypted at runtime through a per-call-site
/// state machine. The decrypted value derefs to its native type
/// (`&str`, `&[u8]`, or the primitive).
///
/// Inputs that are not a plain literal take the const-block path, which has
/// two requirements: the value's type must be `Copy`, and it must have no
/// padding bytes. The value is transmuted to a byte array in a `const`
/// context, so a type with padding fails const evaluation and a non-`Copy`
/// type fails to compile.
///
/// ```ignore
/// let s = xorany!("secret");
/// let n: u32 = xorany!(0xdeadbeefu32);
/// ```
#[proc_macro]
pub fn xorany(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.clone().into_iter().collect();
    if tokens.is_empty() {
        return compile_error(
            "xorany! takes a literal or const-evaluable expression, got nothing",
        );
    }
    expand(input)
}

/// Obfuscate a string literal as a UTF-16 wide string.
///
/// Takes a single `&str` literal and encrypts it as `&[u16]` little-endian.
/// Useful on Windows for `wchar_t`-shaped FFI calls.
///
/// ```ignore
/// let w = xorany_wide!("hello");
/// // w: &[u16]
/// ```
#[proc_macro]
pub fn xorany_wide(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.clone().into_iter().collect();
    if tokens.is_empty() {
        return compile_error("xorany_wide! takes a string literal, got nothing");
    }
    let input_str = input.to_string();
    let key = make_key(&input_str);
    if tokens.len() == 1 {
        if let TokenTree::Literal(lit) = &tokens[0] {
            if let Some(s) = parse_str_literal(&lit.to_string()) {
                return emit_wide_string(&s, key);
            }
        }
    }
    compile_error(&format!(
        "xorany_wide! takes a single string literal, got: {}",
        input_str
    ))
}

fn expand(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.clone().into_iter().collect();
    let input_str = input.to_string();
    let key = make_key(&input_str);

    if tokens.len() == 1 {
        if let TokenTree::Literal(lit) = &tokens[0] {
            if let Some(ts) = try_emit_literal(&lit.to_string(), key, false) {
                return ts;
            }
        }
    }

    if tokens.len() == 2 {
        if let (TokenTree::Punct(p), TokenTree::Literal(lit)) = (&tokens[0], &tokens[1]) {
            if p.as_char() == '-' && p.spacing() == Spacing::Alone {
                if let Some(ts) = try_emit_literal(&lit.to_string(), key, true) {
                    return ts;
                }
            }
        }
    }

    emit_const_block(input, key)
}

fn try_emit_literal(s: &str, key: u64, negate: bool) -> Option<TokenStream> {
    if negate {
        if let Some((val, ty)) = parse_float_literal(s) {
            return Some(emit_float(-val, ty, key));
        }
        if let Some((val, ty)) = parse_int_literal(s) {
            if matches!(ty, IntTy::Isize) {
                return Some(emit_int_ptr_width(val.wrapping_neg(), true, key));
            }
            return Some(emit_int(val.wrapping_neg(), ty, key));
        }
        return None;
    }
    if let Some(bytes) = parse_byte_str_literal(s) {
        return Some(emit_byte_string(&bytes, key));
    }
    if let Some(text) = parse_str_literal(s) {
        return Some(emit_string(&text, key));
    }
    if let Some(c) = parse_char_literal(s) {
        return Some(emit_char(c, key));
    }
    if let Some((val, ty)) = parse_float_literal(s) {
        return Some(emit_float(val, ty, key));
    }
    if let Some((val, ty)) = parse_int_literal(s) {
        if matches!(ty, IntTy::Isize | IntTy::Usize) {
            return Some(emit_int_ptr_width(val, matches!(ty, IntTy::Isize), key));
        }
        return Some(emit_int(val, ty, key));
    }
    None
}

fn parse_str_literal(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.first().copied() == Some(b'"') {
        return unescape(&s[1..s.len() - 1]);
    }
    if bytes.first().copied() == Some(b'r') {
        let rest = &s[1..];
        let (open, close) = raw_bounds(rest)?;
        let inner = &rest[open..rest.len() - close];
        return Some(inner.to_string());
    }
    None
}

fn parse_byte_str_literal(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.starts_with(b"b\"") {
        return unescape_bytes(&s[2..s.len() - 1]);
    }
    if bytes.starts_with(b"br") || bytes.starts_with(b"rb") {
        let rest = &s[2..];
        let (open, close) = raw_bounds(rest)?;
        let inner = &rest[open..rest.len() - close];
        return Some(inner.as_bytes().to_vec());
    }
    None
}

fn unescape_bytes(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= b.len() {
            return None;
        }
        match b[i] {
            b'n' => { out.push(b'\n'); i += 1; }
            b't' => { out.push(b'\t'); i += 1; }
            b'r' => { out.push(b'\r'); i += 1; }
            b'0' => { out.push(0); i += 1; }
            b'\\' => { out.push(b'\\'); i += 1; }
            b'\'' => { out.push(b'\''); i += 1; }
            b'"' => { out.push(b'"'); i += 1; }
            b'x' => {
                if i + 2 >= b.len() {
                    return None;
                }
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok()?;
                let n = u8::from_str_radix(hex, 16).ok()?;
                out.push(n);
                i += 3;
            }
            _ => return None,
        }
    }
    Some(out)
}

fn raw_bounds(rest: &str) -> Option<(usize, usize)> {
    let b = rest.as_bytes();
    let mut hashes = 0;
    while hashes < b.len() && b[hashes] == b'#' {
        hashes += 1;
    }
    if b.get(hashes).copied() != Some(b'"') {
        return None;
    }
    Some((hashes + 1, hashes + 1))
}

fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            '0' => out.push('\0'),
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            'x' => {
                let h1 = chars.next()?;
                let h2 = chars.next()?;
                let mut buf = [0u8; 2];
                h1.encode_utf8(&mut buf[..1]);
                h2.encode_utf8(&mut buf[1..]);
                let hex: String = [h1, h2].iter().collect();
                let n = u8::from_str_radix(&hex, 16).ok()?;
                out.push(n as char);
            }
            'u' => {
                if chars.next()? != '{' {
                    return None;
                }
                let mut hex = String::new();
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                    hex.push(c);
                }
                let n = u32::from_str_radix(&hex, 16).ok()?;
                out.push(char::from_u32(n)?);
            }
            _ => return None,
        }
    }
    Some(out)
}

fn parse_char_literal(s: &str) -> Option<char> {
    if !s.starts_with('\'') || !s.ends_with('\'') {
        return None;
    }
    let inner = &s[1..s.len() - 1];
    let unescaped = unescape(inner)?;
    let mut it = unescaped.chars();
    let c = it.next()?;
    if it.next().is_some() {
        return None;
    }
    Some(c)
}

#[derive(Clone, Copy)]
enum IntTy {
    I8, I16, I32, I64, I128, Isize,
    U8, U16, U32, U64, U128, Usize,
}

impl IntTy {
    fn size(self) -> usize {
        match self {
            IntTy::I8 | IntTy::U8 => 1,
            IntTy::I16 | IntTy::U16 => 2,
            IntTy::I32 | IntTy::U32 => 4,
            IntTy::I64 | IntTy::U64 => 8,
            IntTy::I128 | IntTy::U128 => 16,
            IntTy::Isize | IntTy::Usize => 8,
        }
    }
    fn name(self) -> &'static str {
        match self {
            IntTy::I8 => "i8", IntTy::I16 => "i16", IntTy::I32 => "i32",
            IntTy::I64 => "i64", IntTy::I128 => "i128", IntTy::Isize => "isize",
            IntTy::U8 => "u8", IntTy::U16 => "u16", IntTy::U32 => "u32",
            IntTy::U64 => "u64", IntTy::U128 => "u128", IntTy::Usize => "usize",
        }
    }
}

fn parse_int_ty_suffix(s: &str) -> Option<(&str, IntTy)> {
    for (suf, ty) in [
        ("i128", IntTy::I128), ("u128", IntTy::U128),
        ("isize", IntTy::Isize), ("usize", IntTy::Usize),
        ("i64", IntTy::I64), ("u64", IntTy::U64),
        ("i32", IntTy::I32), ("u32", IntTy::U32),
        ("i16", IntTy::I16), ("u16", IntTy::U16),
        ("i8", IntTy::I8), ("u8", IntTy::U8),
    ] {
        if let Some(stripped) = s.strip_suffix(suf) {
            return Some((stripped, ty));
        }
    }
    None
}

fn parse_int_literal(s: &str) -> Option<(i128, IntTy)> {
    if s.contains('.') || s.contains("e+") || s.contains("e-") {
        return None;
    }
    let (num_part, ty) = match parse_int_ty_suffix(s) {
        Some((n, t)) => (n, t),
        None => (s, IntTy::I32),
    };
    let num_part = num_part.replace('_', "");
    let (radix, body) = if let Some(rest) = num_part.strip_prefix("0x").or_else(|| num_part.strip_prefix("0X")) {
        (16, rest.to_string())
    } else if let Some(rest) = num_part.strip_prefix("0o").or_else(|| num_part.strip_prefix("0O")) {
        (8, rest.to_string())
    } else if let Some(rest) = num_part.strip_prefix("0b").or_else(|| num_part.strip_prefix("0B")) {
        (2, rest.to_string())
    } else {
        if num_part.is_empty() || !num_part.chars().next().unwrap().is_ascii_digit() {
            return None;
        }
        (10, num_part)
    };
    let value = u128::from_str_radix(&body, radix).ok()?;
    Some((value as i128, ty))
}

#[derive(Clone, Copy)]
enum FloatTy { F32, F64 }

fn parse_float_literal(s: &str) -> Option<(f64, FloatTy)> {
    let (num_part, ty) = if let Some(rest) = s.strip_suffix("f64") {
        (rest, FloatTy::F64)
    } else if let Some(rest) = s.strip_suffix("f32") {
        (rest, FloatTy::F32)
    } else if is_float_shape(s) {
        (s, FloatTy::F64)
    } else {
        return None;
    };
    let cleaned = num_part.replace('_', "");
    let v = f64::from_str(&cleaned).ok()?;
    Some((v, ty))
}

fn is_float_shape(s: &str) -> bool {
    let first = s.as_bytes().first().copied();
    let is_decimal = matches!(first, Some(b'0'..=b'9'))
        && !s.starts_with("0x") && !s.starts_with("0X")
        && !s.starts_with("0o") && !s.starts_with("0O")
        && !s.starts_with("0b") && !s.starts_with("0B");
    if !is_decimal {
        return false;
    }
    s.contains('.') || s.contains('e') || s.contains('E')
}

fn parse_ts(s: &str) -> TokenStream {
    TokenStream::from_str(s).expect("xorany: generated TokenStream failed to parse")
}

fn compile_error(msg: &str) -> TokenStream {
    parse_ts(&format!("::core::compile_error!({msg:?})"))
}

fn fmt_ct_array(bytes: &[u8]) -> String {
    let mut s = String::from("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("{b:#04x}u8"));
    }
    s.push(']');
    s
}

fn encrypted_payload(plain: &[u8], key: u64) -> (Vec<u8>, usize) {
    let n = pad_size(plain.len(), key);
    let mut rng_seed = key;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let byte = if i < plain.len() {
            plain[i]
        } else {
            (prng(&mut rng_seed) & 0xFF) as u8
        };
        out.push(enc(byte, i, key));
    }
    (out, n)
}

fn decrypt_scaffold(ct: &[u8], n: usize, key: u64, final_expr: &str) -> String {
    let (ka, kb) = split_key(key);
    let fn_name = format!("__oxo_dec_{key:016x}");
    let state_machine = generate_state_machine_body(key);
    let mut ct_writes = String::new();
    for (i, b) in ct.iter().enumerate() {
        ct_writes.push_str(&format!(
            "unsafe {{ *buf.add({i}) = {b:#04x}u8; }}\n",
        ));
    }
    format!(
        r#"{{
            #[inline(never)]
            #[allow(clippy::all)]
            unsafe fn {fn_name}(buf: *mut u8, len: usize, key_a: u64, key_b: u64) {{
                {ct_writes}
                {state_machine}
            }}

            let mut buf: [u8; {n}] = [0u8; {n}];
            unsafe {{ {fn_name}(buf.as_mut_ptr(), {n}, {ka}u64, {kb}u64); }}
            {final_expr}
        }}"#,
    )
}

fn emit_string(text: &str, key: u64) -> TokenStream {
    let bytes = text.as_bytes();
    let len = bytes.len();
    let (ct, n) = encrypted_payload(bytes, key);
    let final_expr = format!("::xorany::OxoStr::<{n}, {len}>::new(buf)");
    let code = decrypt_scaffold(&ct, n, key, &final_expr);
    parse_ts(&code)
}

fn emit_byte_string(bytes: &[u8], key: u64) -> TokenStream {
    let len = bytes.len();
    let (ct, n) = encrypted_payload(bytes, key);
    let final_expr = format!("::xorany::OxoBytes::<{n}, {len}>::new(buf)");
    let code = decrypt_scaffold(&ct, n, key, &final_expr);
    parse_ts(&code)
}

fn emit_wide_string(text: &str, key: u64) -> TokenStream {
    let units: Vec<u16> = text.encode_utf16().collect();
    let m = units.len();
    let mut flat: Vec<u8> = Vec::with_capacity(units.len() * 2);
    for u in &units {
        flat.extend_from_slice(&u.to_le_bytes());
    }
    let (ct, n_bytes) = encrypted_payload(&flat, key);
    let n_u16 = n_bytes / 2;
    let final_expr = format!(
        "::xorany::OxoWStr::<{n_u16}, {m}>::new(::xorany::u16_array_from_le::<{n_bytes}, {n_u16}>(buf))"
    );
    let code = decrypt_scaffold(&ct, n_bytes, key, &final_expr);
    parse_ts(&code)
}

fn emit_char(c: char, key: u64) -> TokenStream {
    let code_point = c as u32;
    let plain = code_point.to_le_bytes();
    let (ct, n) = encrypted_payload(&plain, key);
    let final_expr = format!(
        "{{ let code: u32 = unsafe {{ ::xorany::transmute_as::<u32, {n}>(buf) }}; \
             unsafe {{ ::core::char::from_u32_unchecked(code) }} }}"
    );
    let code = decrypt_scaffold(&ct, n, key, &final_expr);
    parse_ts(&code)
}

fn emit_int(value: i128, ty: IntTy, key: u64) -> TokenStream {
    let size = ty.size();
    let mut plain = vec![0u8; size];
    let raw = (value as u128).to_le_bytes();
    plain[..size.min(16)].copy_from_slice(&raw[..size.min(16)]);
    let (ct, n) = encrypted_payload(&plain, key);
    let ty_name = ty.name();
    let final_expr = format!("unsafe {{ ::xorany::transmute_as::<{ty_name}, {n}>(buf) }}");
    let code = decrypt_scaffold(&ct, n, key, &final_expr);
    parse_ts(&code)
}

fn emit_int_ptr_width(value: i128, signed: bool, key: u64) -> TokenStream {
    let ty_name = if signed { "isize" } else { "usize" };
    let (ka, kb) = split_key(key);
    let fn_name = format!("__oxo_dec_{key:016x}");
    let state_machine = generate_state_machine_body(key);
    let code = format!(
        r#"{{
            const KEY_A: u64 = {ka}u64;
            const KEY_B: u64 = {kb}u64;
            const KEY: u64 = KEY_A ^ KEY_B;
            const V: {ty_name} = {value}i128 as {ty_name};
            const SIZE: usize = ::core::mem::size_of::<{ty_name}>();
            const CT: [u8; SIZE] = {{
                let raw: [u8; SIZE] = V.to_ne_bytes();
                let mut out = [0u8; SIZE];
                let mut i: usize = 0;
                while i < SIZE {{
                    out[i] = ::xorany::encrypt_byte(raw[i], i, KEY);
                    i += 1;
                }}
                out
            }};

            #[inline(never)]
            #[allow(clippy::all)]
            unsafe fn {fn_name}(buf: *mut u8, len: usize, key_a: u64, key_b: u64) {{
                {state_machine}
            }}

            let mut buf: [u8; SIZE] = CT;
            unsafe {{ {fn_name}(buf.as_mut_ptr(), SIZE, KEY_A, KEY_B); }}
            let v: {ty_name} = unsafe {{ ::xorany::transmute_as::<{ty_name}, SIZE>(buf) }};
            v
        }}"#
    );
    parse_ts(&code)
}

fn emit_float(value: f64, ty: FloatTy, key: u64) -> TokenStream {
    let (plain, ty_name): (Vec<u8>, &str) = match ty {
        FloatTy::F32 => ((value as f32).to_le_bytes().to_vec(), "f32"),
        FloatTy::F64 => (value.to_le_bytes().to_vec(), "f64"),
    };
    let (ct, n) = encrypted_payload(&plain, key);
    let final_expr = format!("unsafe {{ ::xorany::transmute_as::<{ty_name}, {n}>(buf) }}");
    let code = decrypt_scaffold(&ct, n, key, &final_expr);
    parse_ts(&code)
}

fn emit_const_block(input: TokenStream, key: u64) -> TokenStream {
    let expr = input.to_string();
    let (ka, kb) = split_key(key);
    let fn_name = format!("__oxo_dec_{key:016x}");
    let state_machine = generate_state_machine_body(key);
    let code = format!(
        r#"{{
            const KEY_A: u64 = {ka}u64;
            const KEY_B: u64 = {kb}u64;
            const KEY: u64 = KEY_A ^ KEY_B;
            const SIZE: usize = ::core::mem::size_of_val(&({expr}));
            const CT: [u8; SIZE] = {{
                let v = ({expr});
                let raw: [u8; SIZE] = unsafe {{ ::core::mem::transmute::<_, [u8; SIZE]>(v) }};
                let mut out = [0u8; SIZE];
                let mut i: usize = 0;
                while i < SIZE {{
                    out[i] = ::xorany::encrypt_byte(raw[i], i, KEY);
                    i += 1;
                }}
                out
            }};

            #[inline(never)]
            #[allow(clippy::all)]
            unsafe fn {fn_name}(buf: *mut u8, len: usize, key_a: u64, key_b: u64) {{
                {state_machine}
            }}

            let mut buf: [u8; SIZE] = CT;
            unsafe {{ {fn_name}(buf.as_mut_ptr(), SIZE, KEY_A, KEY_B); }}
            unsafe {{ ::xorany::transmute_as::<_, SIZE>(buf) }}
        }}"#
    );
    parse_ts(&code)
}

#[allow(dead_code)]
fn _keep_imports(_: Group, _: Punct, _: Spacing, _: Delimiter, _: Literal) {}
