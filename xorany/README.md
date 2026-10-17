# xorany

A compile-time string obfuscator for Rust, based on
[`oxorany`](https://github.com/llxiaoyuan/oxorany) by llxiaoyuan.

Wraps string, byte-string, integer, float, char and const-evaluable
expression literals. The plaintext does not appear in the compiled binary.
Each `xorany!()` call site compiles to its own differently-shaped decrypt
function, so pattern-matching one does not trivially crack the others.

## Install

```toml
[dependencies]
xorany = "0.1"
```

## Usage

```rust
use xorany::{xorany, xorany_wide};

let s = xorany!("hello world");           // &str
let b = xorany!(b"\x00\x01\x02");         // &[u8]
let n = xorany!(0xdeadbeefu32);           // u32
let neg = xorany!(-42i32);                // i32
let f = xorany!(3.14159);                 // f64
let c = xorany!('Z');                     // char
let w = xorany_wide!("utf-16 string");    // &[u16]

const SECRET: u64 = 0x1234_5678_9abc_def0;
let x: u64 = xorany!(SECRET);
```

## License

MIT. See `LICENSE` and `ATTRIBUTIONS.md`.
